from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from zk_tsp.benchmark import FIELDNAMES, benchmark_study
from zk_tsp.workspace import PROJECT_ROOT, STUDY_CIRCUITS


class BenchmarkSmokeTests(unittest.TestCase):
    def test_all_mechanisms_prove_verify_and_emit_compatible_csv(self) -> None:
        manifest = json.loads(
            (PROJECT_ROOT / "provenance" / "import-manifest.json").read_text()
        )
        expected = {item["mechanism"]: item["n8"] for item in manifest["circuits"]}
        mechanism_by_variant = {
            circuit.variant: mechanism for mechanism, circuit in STUDY_CIRCUITS.items()
        }

        with tempfile.TemporaryDirectory(prefix="zk-tsp-smoke-") as tmp:
            output = Path(tmp) / "study.csv"
            benchmark_study(STUDY_CIRCUITS, [8], 1, output, seed=42)
            with output.open(newline="") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, FIELDNAMES)
            self.assertEqual(len(rows), 4)
            self.assertEqual(set(mechanism_by_variant), {row["variant"] for row in rows})
            for row in rows:
                mechanism = mechanism_by_variant[row["variant"]]
                self.assertEqual(int(row["circuit_size"]), expected[mechanism]["circuit_size"])
                self.assertEqual(int(row["acir_opcodes"]), expected[mechanism]["acir_opcodes"])
                self.assertEqual(int(row["proof_bytes"]), 14_656)
                for metric in ("compile_s", "witness_s", "prove_s", "verify_s", "peak_mb"):
                    self.assertGreater(float(row[metric]), 0)

            with self.assertRaises(FileExistsError):
                benchmark_study(["pairwise"], [8], 1, output, seed=42)


if __name__ == "__main__":
    unittest.main()
