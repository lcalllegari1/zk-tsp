from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from tests.test_composite_correctness import execute, increment_field
from zk_tsp.backend import compile_circuit
from zk_tsp.cache import CachedInstance, InstanceCache
from zk_tsp.domain import cycle_cost
from zk_tsp.recursive import (
    RECURSIVE_PACKAGE,
    _compile_inner,
    _prove_inner_segment,
    _write_build_metadata,
    assemble_outer_witness,
    populate_recursive_workspace,
    prove_recursive_workspace,
    refresh_recursive_witnesses,
    sha256_file,
    write_segment_key_constants,
)
from zk_tsp.recursive_verify import (
    RecursiveVerificationError,
    verify_recursive_workspace,
)


class RecursiveCorrectnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="zk-tsp-recursive-tests-")
        cls.root = Path(cls.temporary.name)
        cls.cache = InstanceCache(cls.root / "cache")
        cls.cached = cls.cache.load_or_create(8, 42)
        cls.workspace = cls.root / "canonical"
        populate_recursive_workspace(cls.workspace, cls.cached, 2, 42)
        prove_recursive_workspace(cls.workspace)
        cls.valid_outer = (cls.workspace / "outer" / "Prover.toml").read_text()
        cls.trusted_metadata = cls.root / "trusted-build.json"
        shutil.copyfile(
            cls.workspace / "build-metadata.json", cls.trusted_metadata
        )
        cls.canonical_vk = cls.root / "canonical-vk"
        shutil.copyfile(
            cls.workspace / "outer" / "target" / "vk" / "vk",
            cls.canonical_vk,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        refresh_recursive_witnesses(self.workspace, self.cached, 2)
        (self.workspace / "outer" / "Prover.toml").write_text(self.valid_outer)

    def test_valid_proof_key_chain_and_public_surface(self) -> None:
        local = verify_recursive_workspace(self.workspace)
        explicit = verify_recursive_workspace(
            self.workspace, self.trusted_metadata
        )
        self.assertEqual(local.trust_mode, "workspace-local")
        self.assertEqual(explicit.trust_mode, "explicit")
        self.assertEqual((local.proofs, local.public_inputs), (1, 2))
        with self.assertRaises(FileExistsError):
            prove_recursive_workspace(self.workspace)

        artifact = json.loads(
            (
                self.workspace
                / "outer"
                / "target"
                / f"{RECURSIVE_PACKAGE}.json"
            ).read_text()
        )
        names = {parameter["name"] for parameter in artifact["abi"]["parameters"]}
        self.assertFalse(names & {"sub_vk", "key_hash"})
        self.assertEqual(
            [
                parameter["name"]
                for parameter in artifact["abi"]["parameters"]
                if parameter["visibility"] == "public"
            ],
            ["root", "threshold"],
        )

    def test_outer_constraints_reject_tampering(self) -> None:
        outer = self.workspace / "outer"
        valid = tomllib.loads(self.valid_outer)
        cases = []
        wrong_root = copy.deepcopy(valid)
        wrong_root["root"] = increment_field(wrong_root["root"])
        cases.append(wrong_root)
        wrong_start = copy.deepcopy(valid)
        wrong_start["starts"][0] = "99"
        cases.append(wrong_start)
        insufficient = copy.deepcopy(valid)
        insufficient["threshold"] = "1"
        cases.append(insufficient)
        wrong_boundary = copy.deepcopy(valid)
        wrong_boundary["boundary_costs"][0] = str(
            int(wrong_boundary["boundary_costs"][0]) + 1
        )
        cases.append(wrong_boundary)
        wrong_path = copy.deepcopy(valid)
        wrong_path["boundary_path_bits"][0] = not wrong_path[
            "boundary_path_bits"
        ][0]
        cases.append(wrong_path)
        for index, witness in enumerate(cases):
            with self.subTest(case=index):
                self.assertNotEqual(execute(outer, witness).returncode, 0)

    def test_tampered_inner_proof_makes_outer_proving_fail(self) -> None:
        outer = self.workspace / "outer"
        tampered = tomllib.loads(self.valid_outer)
        tampered["proofs"][0][0] = increment_field(tampered["proofs"][0][0])
        self.assertEqual(execute(outer, tampered).returncode, 0)
        with tempfile.TemporaryDirectory(prefix="zk-tsp-tampered-inner-") as tmp:
            result = subprocess.run(
                [
                    "bb",
                    "prove",
                    "-b",
                    f"target/{RECURSIVE_PACKAGE}.json",
                    "-w",
                    f"target/{RECURSIVE_PACKAGE}.gz",
                    "-k",
                    "target/vk/vk",
                    "-o",
                    tmp,
                ],
                cwd=outer,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_overlapping_segments_fail_global_product(self) -> None:
        duplicate_cycle = [0, 1, 2, 3, 0, 5, 6, 7]
        cost = cycle_cost(self.cached.instance["matrix"], duplicate_cycle)
        duplicate = CachedInstance(
            self.cached.directory,
            self.cached.instance,
            duplicate_cycle,
            cost,
            1 << 63,
        )
        refresh_recursive_witnesses(self.workspace, duplicate, 2)
        with tempfile.TemporaryDirectory(prefix="zk-tsp-recursive-overlap-") as tmp:
            staging = Path(tmp)
            segments = [
                _prove_inner_segment(self.workspace, staging, index)[0]
                for index in range(2)
            ]
            witness = assemble_outer_witness(
                segments,
                self.workspace / "witnesses" / "glue" / "Prover.toml",
            )
            (self.workspace / "outer" / "Prover.toml").write_text(witness)
            result = subprocess.run(
                ["nargo", "execute"],
                cwd=self.workspace / "outer",
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("grand-product", result.stderr)

    def test_alternate_inner_is_bound_to_a_different_outer_key(self) -> None:
        alternate = self.root / "alternate"
        if alternate.exists():
            shutil.rmtree(alternate)
        shutil.copytree(self.workspace, alternate)
        shutil.rmtree(alternate / "proofs")

        inner_source = alternate / "inner" / "src" / "main.nr"
        source = inner_source.read_text()
        marker = '    assert(cycle_segment[0] != cycle_segment[1], "alternate relation");\n'
        inner_source.write_text(source.replace("    for i in 0..M {", marker + "    for i in 0..M {", 1))
        _, vk_fields, key_hash = _compile_inner(alternate / "inner")
        write_segment_key_constants(
            alternate / "outer" / "src" / "expected_segment_vk.nr",
            n=8,
            m=4,
            depth=6,
            vk_fields=vk_fields,
            key_hash=key_hash,
        )
        compile_circuit(alternate / "outer", RECURSIVE_PACKAGE)
        build_path = _write_build_metadata(
            alternate,
            n=8,
            k=2,
            m=4,
            depth=6,
            vk_fields=vk_fields,
            key_hash=key_hash,
        )
        metadata_path = alternate / "metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["build_metadata_sha256"] = sha256_file(build_path)
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        prove_recursive_workspace(alternate)
        verify_recursive_workspace(alternate)

        alternate_vk = alternate / "outer" / "target" / "vk" / "vk"
        alternate_proof = alternate / "proofs" / "outer"
        self.assertFalse(
            self._bb_verify(self.canonical_vk, alternate_proof)
        )
        self.assertFalse(
            self._bb_verify(
                alternate_vk, self.workspace / "proofs" / "outer"
            )
        )
        with self.assertRaises(RecursiveVerificationError):
            verify_recursive_workspace(alternate, self.trusted_metadata)

    def test_valid_k4_geometry_executes(self) -> None:
        cached = self.cache.load_or_create(12, 42)
        workspace = self.root / "k4"
        populate_recursive_workspace(workspace, cached, 4, 42)
        with tempfile.TemporaryDirectory(prefix="zk-tsp-recursive-k4-") as tmp:
            staging = Path(tmp)
            segments = [
                _prove_inner_segment(workspace, staging, index)[0]
                for index in range(4)
            ]
            witness = assemble_outer_witness(
                segments, workspace / "witnesses" / "glue" / "Prover.toml"
            )
            (workspace / "outer" / "Prover.toml").write_text(witness)
            result = subprocess.run(
                ["nargo", "execute"],
                cwd=workspace / "outer",
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verifier_rejects_tampered_artifacts_and_proof_shapes(self) -> None:
        proof = self.workspace / "proofs" / "outer" / "proof"
        public_inputs = self.workspace / "proofs" / "outer" / "public_inputs"
        outer_vk = self.workspace / "outer" / "target" / "vk" / "vk"
        for path, mutate in (
            (proof, lambda data: data[:-32]),
            (public_inputs, lambda data: data + bytes(32)),
            (outer_vk, self._flip_first_byte),
        ):
            original = path.read_bytes()
            try:
                path.write_bytes(mutate(original))
                with self.assertRaises(RecursiveVerificationError):
                    verify_recursive_workspace(self.workspace)
            finally:
                path.write_bytes(original)

        altered_metadata = self.root / "altered-build.json"
        build = json.loads(self.trusted_metadata.read_text())
        build["outer"]["verification_key_sha256"] = "00" * 32
        altered_metadata.write_text(json.dumps(build, indent=2, sort_keys=True) + "\n")
        with self.assertRaises(RecursiveVerificationError):
            verify_recursive_workspace(self.workspace, altered_metadata)

        build_path = self.workspace / "build-metadata.json"
        workspace_metadata_path = self.workspace / "metadata.json"
        original_build = build_path.read_bytes()
        original_workspace_metadata = workspace_metadata_path.read_bytes()
        try:
            malformed = json.loads(original_build)
            malformed["segment"]["verification_key_fields"][0] = "not-a-field"
            build_path.write_text(json.dumps(malformed, indent=2, sort_keys=True) + "\n")
            workspace_metadata = json.loads(original_workspace_metadata)
            workspace_metadata["build_metadata_sha256"] = sha256_file(build_path)
            workspace_metadata_path.write_text(
                json.dumps(workspace_metadata, indent=2, sort_keys=True) + "\n"
            )
            with self.assertRaises(RecursiveVerificationError):
                verify_recursive_workspace(self.workspace)
        finally:
            build_path.write_bytes(original_build)
            workspace_metadata_path.write_bytes(original_workspace_metadata)

        outer_artifact = (
            self.workspace / "outer" / "target" / f"{RECURSIVE_PACKAGE}.json"
        )
        missing_artifact = outer_artifact.with_suffix(".missing")
        outer_artifact.replace(missing_artifact)
        try:
            with self.assertRaises(RecursiveVerificationError):
                verify_recursive_workspace(self.workspace)
        finally:
            missing_artifact.replace(outer_artifact)

    @staticmethod
    def _bb_verify(vk: Path, proof_directory: Path) -> bool:
        return (
            subprocess.run(
                [
                    "bb",
                    "verify",
                    "-k",
                    str(vk),
                    "-p",
                    str(proof_directory / "proof"),
                    "-i",
                    str(proof_directory / "public_inputs"),
                ],
                capture_output=True,
                text=True,
            ).returncode
            == 0
        )

    @staticmethod
    def _flip_first_byte(data: bytes) -> bytes:
        return bytes([data[0] ^ 1]) + data[1:]


if __name__ == "__main__":
    unittest.main()
