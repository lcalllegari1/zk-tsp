from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from zk_tsp.recursive import prepare_recursive_workspace, sha256_file
from zk_tsp.workspace import PROJECT_ROOT

MANIFEST = PROJECT_ROOT / "provenance" / "import-manifest.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_noir_sha(source: str) -> str:
    without_comments = re.sub(r"//.*", "", source)
    tokens = "".join(without_comments.split())
    return hashlib.sha256(tokens.encode()).hexdigest()


class ImportEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_imported_file_and_token_hashes(self) -> None:
        for item in self.manifest["circuits"]:
            with self.subTest(mechanism=item["mechanism"]):
                destination = PROJECT_ROOT / item["destination_path"]
                source = destination / "src" / "main.nr"
                self.assertEqual(sha256(source), item["destination_main_sha256"])
                self.assertEqual(
                    sha256(destination / "Nargo.toml"),
                    item["destination_manifest_sha256"],
                )
                self.assertEqual(
                    normalized_noir_sha(source.read_text()),
                    item["normalized_source_sha256"],
                )

    def test_imported_component_file_hashes(self) -> None:
        for component in self.manifest["components"]:
            destination = PROJECT_ROOT / component["destination_path"]
            for relative, expected in component.get(
                "destination_module_sha256", {}
            ).items():
                with self.subTest(component=component["name"], path=relative):
                    self.assertEqual(sha256(destination / relative), expected)
            for relative, expected in component.get(
                "acceptance_test_sha256", {}
            ).items():
                with self.subTest(component=component["name"], path=relative):
                    self.assertEqual(sha256(PROJECT_ROOT / relative), expected)

    def test_n8_compilation_matches_immutable_source_fingerprints(self) -> None:
        for item in self.manifest["circuits"]:
            with self.subTest(mechanism=item["mechanism"]):
                with tempfile.TemporaryDirectory(prefix="zk-tsp-equivalence-") as tmp:
                    if item.get("build") == "recursive-key-chain":
                        workspace = Path(tmp) / "recursive"
                        prepare_recursive_workspace(
                            8,
                            2,
                            workspace,
                            seed=42,
                            cache_dir=Path(tmp) / "cache",
                        )
                        circuit = workspace / "outer"
                    else:
                        source = PROJECT_ROOT / item["destination_path"]
                        workspace = Path(tmp) / "circuit"
                        shutil.copytree(source, workspace)
                        subprocess.run(
                            ["nargo", "compile"],
                            cwd=workspace,
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                        circuit = workspace
                    artifact_path = circuit / "target" / f"{item['package']}.json"
                    artifact = json.loads(artifact_path.read_text())
                    expected = item["n8"]
                    bytecode_sha = hashlib.sha256(
                        (artifact["bytecode"] + "\n").encode()
                    ).hexdigest()
                    abi = json.dumps(
                        artifact["abi"]["parameters"], separators=(",", ":")
                    ) + "\n"
                    self.assertEqual(bytecode_sha, expected["bytecode_sha256"])
                    self.assertEqual(
                        hashlib.sha256(abi.encode()).hexdigest(), expected["abi_sha256"]
                    )
                    # Noir's container hash changes when source comments change;
                    # executable bytecode, ABI, and gate counts are the semantic
                    # equivalence checks. Preserve both container hashes in the
                    # provenance record instead of pretending they are equal.
                    self.assertEqual(
                        str(artifact["hash"]), expected["clean_artifact_hash"]
                    )

                    if item.get("build") == "recursive-key-chain":
                        self.assertEqual(
                            sha256_file(circuit / "target" / "vk" / "vk"),
                            expected["outer_verification_key_sha256"],
                        )
                        self.assertEqual(
                            sha256_file(
                                workspace
                                / "inner"
                                / "target"
                                / "recursive_vk"
                                / "vk"
                            ),
                            expected["inner_recursive_verification_key_sha256"],
                        )

                    gates_process = subprocess.run(
                        ["bb", "gates", "-b", str(artifact_path)],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    gates = json.loads(gates_process.stdout)["functions"][0]
                    self.assertEqual(gates["acir_opcodes"], expected["acir_opcodes"])
                    self.assertEqual(gates["circuit_size"], expected["circuit_size"])


if __name__ == "__main__":
    unittest.main()
