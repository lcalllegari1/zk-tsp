from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from zk_tsp.cache import CACHE_SCHEMA, InstanceCache
from zk_tsp.cli import main
from zk_tsp.composite import (
    COMPOSITE_VARIANTS,
    prepare_composite_workspace,
    validate_geometry,
)
from zk_tsp.domain import (
    cycle_cost,
    generate_instance,
    inverse_permutation,
    make_study_witness,
    merkle_depth,
    solve,
    threshold_for,
)
from zk_tsp.workspace import (
    COMMITTED_CIRCUITS,
    STUDY_CIRCUITS,
    prepare_committed_workspace,
    prepare_workspace,
)


class DomainTests(unittest.TestCase):
    def test_instance_matches_the_thesis_generator(self) -> None:
        instance = generate_instance(5, seed=42)
        encoded = json.dumps(instance, sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            hashlib.sha256(encoded.encode()).hexdigest(),
            "d9f4baa551bed36c5543675ad5758e9cc95ca8223f42f6933c2b3455fbdcf426",
        )
        self.assertEqual(
            instance["matrix"],
            [
                [0, 501713, 824215, 327553, 331980],
                [501713, 0, 726428, 725066, 170589],
                [824215, 726428, 0, 716902, 709155],
                [327553, 725066, 716902, 0, 565579],
                [331980, 170589, 709155, 565579, 0],
            ],
        )

    def test_solver_cost_threshold_and_inverse(self) -> None:
        instance = generate_instance(5, seed=42)
        cycle = solve(instance["matrix"])
        self.assertEqual(cycle, [0, 3, 2, 1, 4])
        self.assertEqual(cycle_cost(instance["matrix"], cycle), 2_273_452)
        self.assertEqual(threshold_for(2_273_452), 2_500_798)
        self.assertEqual(inverse_permutation(cycle), [0, 3, 2, 1, 4])

    def test_invalid_domain_inputs_fail(self) -> None:
        with self.assertRaises(ValueError):
            generate_instance(0)
        with self.assertRaises(ValueError):
            inverse_permutation([0, 0, 2])
        with self.assertRaises(ValueError):
            threshold_for(10, 0)

    def test_inverse_witness_is_the_only_extra_private_array(self) -> None:
        instance = generate_instance(3)
        cycle = solve(instance["matrix"])
        for mechanism in STUDY_CIRCUITS:
            witness = make_study_witness(instance, cycle, mechanism)
            self.assertEqual("inv_perm" in witness, mechanism == "inverse")

    def test_merkle_depth_covers_square_matrix_and_padding(self) -> None:
        self.assertEqual([merkle_depth(n) for n in (1, 2, 3, 5, 8)], [0, 2, 4, 5, 6])


class CacheTests(unittest.TestCase):
    def test_cache_is_reused_and_tampering_is_rebuilt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = InstanceCache(Path(tmp) / "cache")
            first = cache.load_or_create(5, 42)
            metadata_path = first.directory / "meta.json"
            metadata = json.loads(metadata_path.read_text())
            self.assertEqual(metadata["schema"], CACHE_SCHEMA)

            second = cache.load_or_create(5, 42)
            self.assertEqual(second.instance, first.instance)
            self.assertEqual(second.cycle, first.cycle)

            (first.directory / "cycle.json").write_text("[0, 0, 0, 0, 0]\n")
            repaired = cache.load_or_create(5, 42)
            self.assertEqual(repaired.cycle, first.cycle)
            self.assertEqual(sorted(repaired.cycle), list(range(5)))


class WorkspaceAndCliTests(unittest.TestCase):
    def test_prepare_is_transactional_and_does_not_patch_canonical_source(self) -> None:
        canonical = {
            mechanism: (circuit.path / "src" / "main.nr").read_bytes()
            for mechanism, circuit in STUDY_CIRCUITS.items()
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "prepared"
            prepare_workspace("sort", 3, output, seed=42)
            self.assertIn("global N: u32 = 3;", (output / "src" / "main.nr").read_text())
            self.assertTrue((output / "Prover.toml").is_file())
            self.assertEqual(json.loads((output / "metadata.json").read_text())["nodes"], 3)
        for mechanism, circuit in STUDY_CIRCUITS.items():
            self.assertEqual(
                (circuit.path / "src" / "main.nr").read_bytes(), canonical[mechanism]
            )

    def test_prepare_refuses_nonempty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "prepared"
            output.mkdir()
            (output / "user-file").write_text("keep")
            with self.assertRaises(FileExistsError):
                prepare_workspace("pairwise", 3, output)
            self.assertEqual((output / "user-file").read_text(), "keep")

    def test_committed_prepare_is_transactional_and_uses_shared_cache(self) -> None:
        canonical = {
            mechanism: (circuit.path / "src" / "main.nr").read_bytes()
            for mechanism, circuit in COMMITTED_CIRCUITS.items()
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "prepared"
            cache = root / "cache"
            prepare_committed_workspace("sort", 3, output, seed=42, cache_dir=cache)
            configured = (output / "src" / "main.nr").read_text()
            self.assertIn("global N: u32 = 3;", configured)
            self.assertIn("global DEPTH: u32 = 4;", configured)
            self.assertTrue((output / "Prover.toml").is_file())
            self.assertTrue((cache / "n3_seed42" / "tree.bin").is_file())
            metadata = json.loads((output / "metadata.json").read_text())
            self.assertEqual(metadata["variant"], "flat_merkle_sort")
        for mechanism, circuit in COMMITTED_CIRCUITS.items():
            self.assertEqual(
                (circuit.path / "src" / "main.nr").read_bytes(), canonical[mechanism]
            )

    def test_cli_reports_invalid_sizes_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "invalid"
            self.assertEqual(
                main(
                    [
                        "prepare",
                        "study",
                        "--mechanism",
                        "pairwise",
                        "--nodes",
                        "0",
                        "--output",
                        str(output),
                    ]
                ),
                1,
            )
            self.assertFalse(output.exists())

            committed_output = root / "invalid-committed"
            cache = root / "cache"
            self.assertEqual(
                main(
                    [
                        "prepare",
                        "monolithic",
                        "--mechanism",
                        "sort",
                        "--nodes",
                        "1",
                        "--cache-dir",
                        str(cache),
                        "--output",
                        str(committed_output),
                    ]
                ),
                1,
            )
            self.assertFalse(committed_output.exists())
            self.assertFalse(cache.exists())

            for n, k in ((8, 1), (8, 3), (4, 2)):
                with self.subTest(n=n, k=k):
                    composite_output = root / f"invalid-composite-{n}-{k}"
                    composite_cache = root / f"cache-{n}-{k}"
                    self.assertEqual(
                        main(
                            [
                                "prepare",
                                "composite",
                                "--variant",
                                "plain-sort",
                                "--nodes",
                                str(n),
                                "--segments",
                                str(k),
                                "--cache-dir",
                                str(composite_cache),
                                "--output",
                                str(composite_output),
                            ]
                        ),
                        1,
                    )
                    self.assertFalse(composite_output.exists())
                    self.assertFalse(composite_cache.exists())

                    recursive_output = root / f"invalid-recursive-{n}-{k}"
                    recursive_cache = root / f"recursive-cache-{n}-{k}"
                    self.assertEqual(
                        main(
                            [
                                "prepare",
                                "recursive",
                                "--nodes",
                                str(n),
                                "--segments",
                                str(k),
                                "--cache-dir",
                                str(recursive_cache),
                                "--output",
                                str(recursive_output),
                            ]
                        ),
                        1,
                    )
                    self.assertFalse(recursive_output.exists())
                    self.assertFalse(recursive_cache.exists())

    def test_composite_geometry_and_transactional_prepare(self) -> None:
        self.assertEqual(validate_geometry(8, 2), 4)
        self.assertEqual(validate_geometry(16, 4), 4)
        for n, k in ((8, 1), (8, 3), (4, 2)):
            with self.subTest(n=n, k=k), self.assertRaises(ValueError):
                validate_geometry(n, k)

        canonical = {
            path: path.read_bytes()
            for spec in COMPOSITE_VARIANTS.values()
            for path in (
                spec.segment_path / "src" / "main.nr",
                spec.glue_path / "src" / "main.nr",
            )
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "cache"
            for variant in COMPOSITE_VARIANTS:
                output = root / variant
                prepare_composite_workspace(
                    variant, 8, 2, output, seed=42, cache_dir=cache
                )
                metadata = json.loads((output / "metadata.json").read_text())
                self.assertEqual(metadata["variant"], variant)
                self.assertEqual(metadata["segment_length"], 4)
                self.assertEqual(
                    metadata["blinding"],
                    "os-random-128-per-segment"
                    if variant.startswith("committed-")
                    else "none",
                )
                for circuit in ("sub_0", "sub_1", "glue"):
                    self.assertTrue((output / circuit / "Nargo.toml").is_file())
                    self.assertTrue((output / circuit / "Prover.toml").is_file())

            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "user-file").write_text("keep")
            with self.assertRaises(FileExistsError):
                prepare_composite_workspace(
                    "plain-sort", 8, 2, occupied, cache_dir=cache
                )
            self.assertEqual((occupied / "user-file").read_text(), "keep")

        for path, content in canonical.items():
            self.assertEqual(path.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
