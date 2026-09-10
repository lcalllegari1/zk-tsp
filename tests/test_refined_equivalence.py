from __future__ import annotations

import hashlib
import json
import tempfile
import tomllib
import unittest
from copy import deepcopy
from pathlib import Path

from zk_tsp.cache import InstanceCache
from zk_tsp.merkle import write_composite_witnesses, write_merkle_witness
from zk_tsp.workspace import PROJECT_ROOT


class RefinedEquivalenceTests(unittest.TestCase):
    def test_builder_files_and_semantic_witnesses_match_frozen_baselines(self) -> None:
        manifest = json.loads(
            (PROJECT_ROOT / "provenance" / "import-manifest.json").read_text()
        )
        component = next(
            item for item in manifest["components"] if item["name"] == "merkle_builder"
        )
        crate = PROJECT_ROOT / component["destination_path"]
        for relative, field in (
            ("Cargo.toml", "destination_manifest_sha256"),
            ("Cargo.lock", "destination_lock_sha256"),
            ("src/lib.rs", "destination_lib_sha256"),
            ("src/main.rs", "destination_main_sha256"),
        ):
            digest = hashlib.sha256((crate / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, component[field])
        for relative, expected in component["destination_module_sha256"].items():
            digest = hashlib.sha256((crate / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, expected)

        with tempfile.TemporaryDirectory(prefix="zk-tsp-builder-equivalence-") as tmp:
            cache = InstanceCache(Path(tmp) / "cache")
            for n in (1, 3, 5, 8):
                with self.subTest(n=n):
                    cached = cache.load_or_create(n, 42)
                    output = Path(tmp) / f"n{n}.toml"
                    write_merkle_witness(
                        cached.instance,
                        cached.cycle,
                        cached.threshold,
                        output,
                        tree_cache=cached.tree_cache,
                    )
                    parsed = tomllib.loads(output.read_text())
                    canonical = json.dumps(
                        parsed, sort_keys=True, separators=(",", ":")
                    ).encode()
                    digest = hashlib.sha256(canonical).hexdigest()
                    self.assertEqual(
                        digest, component["semantic_witness_sha256"][f"n{n}_seed42"]
                    )

            cases = (
                ("plain-sort", 8, 2),
                ("plain-product", 8, 2),
                ("committed-sort", 8, 2),
                ("committed-product", 8, 2),
                ("plain-sort", 16, 4),
                ("plain-product", 16, 4),
                ("committed-sort", 16, 4),
                ("committed-product", 16, 4),
            )
            expected = component["semantic_composite_witness_sha256"]
            for variant, n, k in cases:
                with self.subTest(variant=variant, n=n, k=k):
                    cached = cache.load_or_create(n, 42)
                    output = Path(tmp) / f"{variant}-n{n}-k{k}-first"
                    write_composite_witnesses(
                        cached.instance,
                        cached.cycle,
                        cached.threshold,
                        variant,
                        k,
                        output,
                        tree_cache=cached.tree_cache,
                    )
                    witnesses = self._read_witnesses(output)
                    if variant.startswith("committed-"):
                        second_output = Path(tmp) / f"{variant}-n{n}-k{k}-second"
                        write_composite_witnesses(
                            cached.instance,
                            cached.cycle,
                            cached.threshold,
                            variant,
                            k,
                            second_output,
                            tree_cache=cached.tree_cache,
                        )
                        second = self._read_witnesses(second_output)
                        self._assert_committed_linkage(witnesses, k)
                        self._assert_committed_linkage(second, k)
                        self.assertNotEqual(
                            witnesses["glue/Prover.toml"]["r_is"],
                            second["glue/Prover.toml"]["r_is"],
                        )
                        self.assertEqual(
                            self._normalize_committed(witnesses),
                            self._normalize_committed(second),
                        )
                        witnesses = self._normalize_committed(witnesses)
                    canonical = json.dumps(
                        witnesses, sort_keys=True, separators=(",", ":")
                    ).encode()
                    digest = hashlib.sha256(canonical).hexdigest()
                    key = f"{variant}_n{n}_k{k}_seed42"
                    self.assertEqual(digest, expected[key])

    @staticmethod
    def _read_witnesses(output: Path) -> dict[str, dict]:
        return {
            path.relative_to(output).as_posix(): tomllib.loads(path.read_text())
            for path in sorted(output.glob("*/Prover.toml"))
        }

    def _assert_committed_linkage(
        self, witnesses: dict[str, dict], k: int
    ) -> None:
        glue = witnesses["glue/Prover.toml"]
        segment_blindings = [
            witnesses[f"sub_{index}/Prover.toml"]["r"] for index in range(k)
        ]
        segment_commitments = [
            witnesses[f"sub_{index}/Prover.toml"]["C_i"] for index in range(k)
        ]
        self.assertEqual(glue["r_is"], segment_blindings)
        self.assertEqual(glue["C_is"], segment_commitments)
        for blinding in segment_blindings:
            self.assertLess(int(blinding, 16), 2**128)

    @staticmethod
    def _normalize_committed(
        witnesses: dict[str, dict]
    ) -> dict[str, dict]:
        normalized = deepcopy(witnesses)
        for relative, witness in normalized.items():
            if relative == "glue/Prover.toml":
                witness.pop("r_is")
                witness.pop("C_is")
            else:
                witness.pop("r")
                witness.pop("C_i")
        return normalized


if __name__ == "__main__":
    unittest.main()
