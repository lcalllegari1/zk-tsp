from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from zk_tsp.recursive_benchmark import RECURSIVE_FIELDNAMES, benchmark_recursive


class RecursiveBenchmarkSmokeTests(unittest.TestCase):
    def test_recursive_product_emits_real_proof_rows_and_build_metadata(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zk-tsp-recursive-smoke-") as tmp:
            root = Path(tmp)
            output = root / "recursive.csv"
            benchmark_recursive(
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
                self.assertEqual(reader.fieldnames, RECURSIVE_FIELDNAMES)

            self.assertEqual(len(rows), 3)
            self.assertEqual({row["exp"] for row in rows}, {"2"})
            self.assertEqual({row["circuit"] for row in rows}, {"sub_0", "sub_1", "composite_recursive"})
            inner = [row for row in rows if row["role"] == "inner_segment"]
            outer = next(row for row in rows if row["role"] == "outer_recursive")
            self.assertEqual(len(inner), 2)
            for row in inner:
                self.assertEqual((int(row["gates"]), int(row["acir"])), (4776, 230))
                self.assertEqual(row["verify_s"], "")
                self.assertEqual(row["proof_bytes"], "")
            self.assertEqual((int(outer["gates"]), int(outer["acir"])), (1_472_361, 285))
            self.assertEqual(int(outer["proof_bytes"]), 14_656)
            for row in rows:
                self.assertEqual((int(row["n"]), int(row["k"]), int(row["m"])), (8, 2, 4))
                self.assertEqual((int(row["depth"]), int(row["run"])), (6, 1))
                for field in ("compile_s", "witness_s", "prove_s", "peak_mb"):
                    self.assertGreater(float(row[field]), 0)
            self.assertGreater(float(outer["verify_s"]), 0)

            build_path = root / "recursive_builds" / "n8_k2_depth6.json"
            build = json.loads(build_path.read_text())
            self.assertEqual(build["schema"], "zk-tsp.recursive-build.v1")
            self.assertEqual(
                build["outer"]["verification_key_sha256"],
                "816db1fdded37d1cf3cb3e3f6b5b94067f7f16c17f96f03f631f138b973a6692",
            )

            with self.assertRaises(FileExistsError):
                benchmark_recursive([8], [2], 1, output, cache_dir=root / "cache")

    def test_invalid_grid_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "invalid.csv"
            cache = root / "cache"
            with self.assertRaises(ValueError):
                benchmark_recursive([8], [4], 1, output, cache_dir=cache)
            self.assertFalse(output.exists())
            self.assertFalse((root / "invalid_builds").exists())
            self.assertFalse(cache.exists())


if __name__ == "__main__":
    unittest.main()
