from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from zk_tsp.composite_benchmark import COMPOSITE_FIELDNAMES, benchmark_composite
from zk_tsp.workspace import PROJECT_ROOT


class CompositeBenchmarkSmokeTests(unittest.TestCase):
    def test_all_composite_variants_emit_proof_rows_in_the_historical_schema(self) -> None:
        manifest = json.loads(
            (PROJECT_ROOT / "provenance" / "import-manifest.json").read_text()
        )
        expected = {
            item["mechanism"]: item["n8"]
            for item in manifest["circuits"]
            if item["mechanism"].endswith(("-segment", "-glue"))
        }
        tag_to_mechanism = {
            "hier_a_iso": ("plain-sort-segment", "plain-sort-glue"),
            "hier_fs_iso": ("plain-product-segment", "plain-product-glue"),
            "hier_c_iso": ("committed-sort-segment", "committed-sort-glue"),
            "hier_cfs_iso": (
                "committed-product-segment",
                "committed-product-glue",
            ),
        }

        with tempfile.TemporaryDirectory(prefix="zk-tsp-composite-smoke-") as tmp:
            root = Path(tmp)
            output = root / "composite.csv"
            benchmark_composite(
                [
                    "plain-sort",
                    "plain-product",
                    "committed-sort",
                    "committed-product",
                ],
                [8],
                [2],
                1,
                output,
                seed=42,
                cache_dir=root / "cache",
            )
            with output.open(newline="") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, COMPOSITE_FIELDNAMES)

            self.assertEqual(len(rows), 12)
            self.assertEqual({row["variant"] for row in rows}, set(tag_to_mechanism))
            for tag, mechanisms in tag_to_mechanism.items():
                proof_set = [row for row in rows if row["variant"] == tag]
                self.assertEqual(
                    {row["circuit"] for row in proof_set},
                    {"sub_0", "sub_1", "glue"},
                )
                self.assertEqual(
                    len({row["verify_hier_s"] for row in proof_set}), 1
                )
                segment_expected = expected[mechanisms[0]]
                glue_expected = expected[mechanisms[1]]
                for row in proof_set:
                    circuit_expected = (
                        glue_expected if row["circuit"] == "glue" else segment_expected
                    )
                    self.assertEqual(
                        int(row["circuit_size"]), circuit_expected["circuit_size"]
                    )
                    self.assertEqual(
                        int(row["acir_opcodes"]), circuit_expected["acir_opcodes"]
                    )
                    self.assertEqual(int(row["n"]), 8)
                    self.assertEqual(int(row["k"]), 2)
                    self.assertEqual(int(row["m"]), 4)
                    self.assertEqual(int(row["run"]), 1)
                    self.assertEqual(int(row["proof_bytes"]), 14_656)
                    self.assertEqual(int(row["xchecks_ok"]), 1)
                    for metric in (
                        "compile_s",
                        "witness_s",
                        "prove_s",
                        "verify_s",
                        "peak_mb",
                        "verify_hier_s",
                    ):
                        self.assertGreater(float(row[metric]), 0)

            with self.assertRaises(FileExistsError):
                benchmark_composite(
                    ["plain-sort"],
                    [8],
                    [2],
                    1,
                    output,
                    cache_dir=root / "cache",
                )

    def test_invalid_grid_is_rejected_before_output_or_cache_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "invalid.csv"
            cache = root / "cache"
            with self.assertRaises(ValueError):
                benchmark_composite(
                    ["plain-sort"], [8], [3], 1, output, cache_dir=cache
                )
            self.assertFalse(output.exists())
            self.assertFalse(cache.exists())


if __name__ == "__main__":
    unittest.main()
