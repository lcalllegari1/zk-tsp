from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from zk_tsp.benchmark import FIELDNAMES, benchmark_monolithic
from zk_tsp.workspace import COMMITTED_CIRCUITS, PROJECT_ROOT


class RefinedBenchmarkSmokeTests(unittest.TestCase):
    def test_both_committed_mechanisms_prove_verify_and_emit_compatible_csv(self) -> None:
        manifest = json.loads(
            (PROJECT_ROOT / "provenance" / "import-manifest.json").read_text()
        )
        expected = {
            item["mechanism"].removeprefix("committed-"): item["n8"]
            for item in manifest["circuits"]
            if item["mechanism"].startswith("committed-")
        }
        mechanism_by_variant = {
            circuit.variant: mechanism
            for mechanism, circuit in COMMITTED_CIRCUITS.items()
        }

        with tempfile.TemporaryDirectory(prefix="zk-tsp-refined-smoke-") as tmp:
            root = Path(tmp)
            output = root / "monolithic.csv"
            benchmark_monolithic(
                COMMITTED_CIRCUITS,
                [8],
                1,
                output,
                seed=42,
                cache_dir=root / "cache",
            )
            with output.open(newline="") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, FIELDNAMES)
            self.assertEqual(len(rows), 2)
            self.assertEqual(set(mechanism_by_variant), {row["variant"] for row in rows})
            for row in rows:
                mechanism = mechanism_by_variant[row["variant"]]
                self.assertEqual(
                    int(row["circuit_size"]), expected[mechanism]["circuit_size"]
                )
                self.assertEqual(
                    int(row["acir_opcodes"]), expected[mechanism]["acir_opcodes"]
                )
                self.assertEqual(int(row["proof_bytes"]), 14_656)
                for metric in (
                    "compile_s",
                    "witness_s",
                    "prove_s",
                    "verify_s",
                    "peak_mb",
                ):
                    self.assertGreater(float(row[metric]), 0)

            with self.assertRaises(FileExistsError):
                benchmark_monolithic(
                    ["sort"],
                    [8],
                    1,
                    output,
                    seed=42,
                    cache_dir=root / "cache",
                )


if __name__ == "__main__":
    unittest.main()
