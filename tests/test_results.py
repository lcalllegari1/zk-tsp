from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from unittest.mock import patch

from zk_tsp.cli import main
from zk_tsp.results import (
    ARCHITECTURE_FIELDS,
    COMPONENT_FIELDS,
    EXTERNAL_FIELDS,
    PROOF_BYTES,
    RECURSIVE_FIELDS,
    SUMMARY_FIELDS,
    ArchitectureRow,
    ComponentRow,
    ResultsValidationError,
    aggregate_architectures,
    load_results_components,
    materialize_recursive_bytes,
    parse_external_dataset,
    reproduce_results,
    summarize_architectures,
    validate_results,
)
from zk_tsp.workspace import PROJECT_ROOT


class ResultsCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.components = load_results_components()
        cls.architectures = aggregate_architectures(cls.components)
        cls.summaries = summarize_architectures(cls.architectures)

    def test_manifest_schemas_hashes_and_recursive_derivation(self) -> None:
        report = validate_results()
        self.assertEqual(
            (
                report.tracked_datasets,
                report.thesis_inputs,
                report.component_rows,
                report.architecture_runs,
                report.summary_rows,
                report.recursive_rows_changed,
            ),
            (12, 9, 3704, 1156, 3720, 78),
        )
        manifest = json.loads(
            (PROJECT_ROOT / "provenance/results-manifest.json").read_text()
        )
        catalogued = {record["path"] for record in manifest["datasets"]}
        present = {
            path.relative_to(PROJECT_ROOT).as_posix()
            for path in (PROJECT_ROOT / "results").rglob("*.csv")
        }
        self.assertEqual(present, catalogued)
        pairs = (
            (
                PROJECT_ROOT / "results/frozen/recursive_gp_pre_repair.csv",
                PROJECT_ROOT / "results/derived/recursive_gp.csv",
                42,
            ),
            (
                PROJECT_ROOT / "results/frozen/recursive_gp_large_pre_repair.csv",
                PROJECT_ROOT / "results/derived/recursive_gp_large.csv",
                36,
            ),
        )
        for source, derived, expected_changes in pairs:
            with self.subTest(derived=derived.name):
                generated = materialize_recursive_bytes(source.read_bytes())
                self.assertEqual(generated, derived.read_bytes())
                with source.open(newline="") as left, derived.open(newline="") as right:
                    historical = list(csv.DictReader(left))
                    repaired = list(csv.DictReader(right))
                changed = 0
                for before, after in zip(historical, repaired, strict=True):
                    differences = {
                        field for field in RECURSIVE_FIELDS if before[field] != after[field]
                    }
                    if before["role"] == "outer_recursive":
                        self.assertEqual(differences, {"gates", "acir"})
                        self.assertEqual(int(after["gates"]) - int(before["gates"]), 113)
                        self.assertEqual(int(after["acir"]) - int(before["acir"]), 113)
                        changed += 1
                    else:
                        self.assertEqual(differences, set())
                self.assertEqual(changed, expected_changes)

    def test_reproduction_is_transactional_and_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zk-tsp-results-reproduce-") as tmp:
            root = Path(tmp)
            first = reproduce_results(root / "first")
            second = reproduce_results(root / "second")
            expected_files = {
                "architectures.csv",
                "components.csv",
                "derived/recursive_gp.csv",
                "derived/recursive_gp_large.csv",
                "summaries.csv",
            }
            self.assertEqual(
                {
                    path.relative_to(first).as_posix()
                    for path in first.rglob("*")
                    if path.is_file()
                },
                expected_files,
            )
            for relative in expected_files:
                self.assertEqual(
                    (first / relative).read_bytes(), (second / relative).read_bytes()
                )

            for name, fields, expected_rows in (
                ("components.csv", COMPONENT_FIELDS, 3704),
                ("architectures.csv", ARCHITECTURE_FIELDS, 1156),
                ("summaries.csv", SUMMARY_FIELDS, 3720),
            ):
                with (first / name).open(newline="") as stream:
                    reader = csv.DictReader(stream)
                    self.assertEqual(reader.fieldnames, fields)
                    self.assertEqual(len(list(reader)), expected_rows)

            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("user data\n")
            with self.assertRaises(FileExistsError):
                reproduce_results(occupied)
            self.assertEqual((occupied / "keep.txt").read_text(), "user data\n")

            failed = root / "failed"
            with patch("zk_tsp.results._write_csv", side_effect=RuntimeError("stop")):
                with self.assertRaises(RuntimeError):
                    reproduce_results(failed)
            self.assertFalse(failed.exists())
            self.assertEqual(list(root.glob(".failed-*")), [])

    def test_results_cli_exposes_validation_and_reproduction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zk-tsp-results-cli-") as tmp:
            output = Path(tmp) / "output"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(["results", "validate"]), 0)
                self.assertEqual(
                    main(
                        [
                            "results",
                            "reproduce",
                            "--output",
                            str(output),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    main(
                        [
                            "results",
                            "reproduce",
                            "--output",
                            str(output),
                        ]
                    ),
                    1,
                )
            report = json.loads(stdout.getvalue().split("}\n", 1)[0] + "}")
            self.assertEqual(report["recursive_rows_changed"], 78)
            self.assertTrue((output / "architectures.csv").is_file())
            self.assertIn("not empty", stderr.getvalue())

    def test_thesis_gate_memory_and_schedule_checkpoints(self) -> None:
        architecture = {
            (row.construction, row.n, row.k, row.run): row
            for row in self.architectures
        }
        expected_gates = {
            ("plain-sort", 2): 6_310_775,
            ("plain-sort", 4): 6_316_472,
            ("plain-sort", 8): 6_327_854,
            ("committed-sort", 2): 6_685_288,
            ("committed-sort", 4): 6_691_246,
            ("committed-sort", 8): 6_703_170,
            ("plain-product", 2): 6_425_774,
            ("plain-product", 4): 6_431_643,
            ("plain-product", 8): 6_443_373,
            ("committed-product", 2): 6_427_333,
            ("committed-product", 4): 6_434_762,
            ("committed-product", 8): 6_449_628,
            ("recursive-product", 2): 7_894_150,
            ("recursive-product", 4): 9_433_476,
            ("recursive-product", 8): 12_512_121,
        }
        for (construction, k), expected in expected_gates.items():
            self.assertEqual(architecture[(construction, 3000, k, 1)].aggregate_gates, expected)

        summary = {
            (row["construction"], row["n"], row["k"], row["metric"]): row["center"]
            for row in self.summaries
        }
        expected_times = {
            ("monolithic-sort", None): (Decimal("147.8"), Decimal("147.8")),
            ("plain-sort", 2): (Decimal("169.7"), Decimal("64.6")),
            ("plain-sort", 4): (Decimal("163.9"), Decimal("38.3")),
            ("plain-sort", 8): (Decimal("166.3"), Decimal("37.5")),
            ("committed-sort", 2): (Decimal("192.5"), Decimal("75.6")),
            ("committed-sort", 4): (Decimal("201.8"), Decimal("41.5")),
            ("committed-sort", 8): (Decimal("209.6"), Decimal("41.5")),
            ("plain-product", 2): (Decimal("149.0"), Decimal("75.3")),
            ("plain-product", 4): (Decimal("160.4"), Decimal("40.0")),
            ("plain-product", 8): (Decimal("168.3"), Decimal("21.0")),
            ("committed-product", 2): (Decimal("149.8"), Decimal("75.5")),
            ("committed-product", 4): (Decimal("160.6"), Decimal("40.0")),
            ("committed-product", 8): (Decimal("168.4"), Decimal("21.0")),
            ("recursive-product", 2): (Decimal("171.5"), Decimal("96.5")),
            ("recursive-product", 4): (Decimal("197.2"), Decimal("81.0")),
            ("recursive-product", 8): (Decimal("246.2"), Decimal("101.4")),
        }
        tenth = Decimal("0.1")
        for (construction, k), (sequential, distributed) in expected_times.items():
            actual_sequential = summary[
                (construction, 4000, k, "sequential_online_s")
            ].quantize(tenth, rounding=ROUND_HALF_UP)
            actual_distributed = summary[
                (construction, 4000, k, "distributed_online_s")
            ].quantize(tenth, rounding=ROUND_HALF_UP)
            self.assertEqual((actual_sequential, actual_distributed), (sequential, distributed))

        component_peaks: dict[tuple[str, int, str, int], list[Decimal]] = defaultdict(list)
        for row in self.components:
            if row.n == 4000:
                component_peaks[(row.construction, row.k or 0, row.role, row.run)].append(
                    row.peak_mb
                )
        for construction, k, segment_role, recombiner_role, expected in (
            ("plain-sort", 4, "segment", "glue", (Decimal("2.735"), Decimal("8.775"))),
            ("recursive-product", 4, "inner", "outer", (Decimal("3.203"), Decimal("4.029"))),
        ):
            segments = []
            recombiners = []
            for run in (1, 2, 3):
                segment = component_peaks.get((construction, k, segment_role, run))
                recombiner = component_peaks.get((construction, k, recombiner_role, run))
                if segment and recombiner:
                    segments.append(max(segment))
                    recombiners.append(max(recombiner))
            segment_median = _median(segments) / Decimal(1024)
            recombiner_median = _median(recombiners) / Decimal(1024)
            thousandth = Decimal("0.001")
            self.assertEqual(
                (
                    segment_median.quantize(thousandth, rounding=ROUND_HALF_UP),
                    recombiner_median.quantize(thousandth, rounding=ROUND_HALF_UP),
                ),
                expected,
            )


class ResultsAggregationTests(unittest.TestCase):
    def test_schedule_formulas_are_applied_after_complete_run_composition(self) -> None:
        mono = [_component("monolithic-sort", None, "monolithic", None, 7, 1, 2, 3, True)]
        external = [
            _component("plain-product", 2, "segment", 0, 10, 1, 2, 3, True),
            _component("plain-product", 2, "segment", 1, 10, 2, 3, 5, True),
            _component("plain-product", 2, "glue", None, 4, 1, 3, 4, True),
        ]
        recursive = [
            _component("recursive-product", 2, "inner", 0, 10, 1, 2, 3, False),
            _component("recursive-product", 2, "inner", 1, 10, 2, 3, 5, False),
            _component("recursive-product", 2, "outer", None, 40, 1, 3, 4, True),
        ]
        rows = {
            row.construction: row
            for row in aggregate_architectures([*mono, *external, *recursive])
        }
        self.assertEqual(rows["monolithic-sort"].distributed_online_s, Decimal(3))
        self.assertEqual(rows["plain-product"].sequential_online_s, Decimal(12))
        self.assertEqual(rows["plain-product"].distributed_online_s, Decimal(5))
        self.assertEqual(rows["plain-product"].proof_count, 3)
        self.assertEqual(rows["plain-product"].proof_bytes, 3 * PROOF_BYTES)
        self.assertEqual(rows["recursive-product"].sequential_online_s, Decimal(12))
        self.assertEqual(rows["recursive-product"].distributed_online_s, Decimal(9))
        self.assertEqual(rows["recursive-product"].proof_count, 1)
        self.assertEqual(rows["recursive-product"].proof_bytes, PROOF_BYTES)
        self.assertEqual(rows["recursive-product"].backend_verify_s, Decimal(1))

        second = ArchitectureRow(
            **{
                **rows["recursive-product"].__dict__,
                "run": 2,
                "sequential_online_s": Decimal(15),
                "distributed_online_s": Decimal(10),
                "peak_mb": Decimal(7),
            }
        )
        summary = {
            row["metric"]: row
            for row in summarize_architectures([rows["recursive-product"], second])
        }
        self.assertEqual(summary["sequential_online_s"]["center"], Decimal(12))
        self.assertEqual(summary["sequential_online_s"]["max"], Decimal(15))
        self.assertEqual(summary["peak_mb"]["center"], Decimal(6))

    def test_external_parser_rejects_malformed_or_incomplete_sets(self) -> None:
        valid = [_external_row("sub_0"), _external_row("sub_1"), _external_row("glue")]
        cases = {
            "missing glue": valid[:2],
            "duplicate row": [valid[0], valid[0], valid[1], valid[2]],
            "different shape": [valid[0], {**valid[1], "circuit_size": "11"}, valid[2]],
            "bad geometry": [{**row, "m": "3"} for row in valid],
            "failed checks": [valid[0], valid[1], {**valid[2], "xchecks_ok": "0"}],
            "malformed number": [valid[0], {**valid[1], "prove_s": "nan"}, valid[2]],
            "wrong proof size": [valid[0], valid[1], {**valid[2], "proof_bytes": "32"}],
            "missing segment": [valid[0], valid[2]],
        }
        with tempfile.TemporaryDirectory(prefix="zk-tsp-results-invalid-") as tmp:
            for label, rows in cases.items():
                with self.subTest(case=label):
                    path = Path(tmp) / f"{label.replace(' ', '-')}.csv"
                    _write_fixture(path, EXTERNAL_FIELDS, rows)
                    with self.assertRaises(ResultsValidationError):
                        parse_external_dataset(path, "plain-product")


def _component(
    construction: str,
    k: int | None,
    role: str,
    index: int | None,
    gates: int,
    witness: int,
    prove: int,
    peak: int,
    delivered: bool,
) -> ComponentRow:
    return ComponentRow(
        construction=construction,
        n=8,
        k=k,
        run=1,
        role=role,
        component_index=index,
        gates=gates,
        acir=gates,
        compile_s=Decimal(1),
        witness_s=Decimal(witness),
        prove_s=Decimal(prove),
        verify_s=Decimal(1) if delivered else None,
        reconciliation_s=None,
        proof_bytes=PROOF_BYTES if delivered else None,
        peak_mb=Decimal(peak),
        delivered=delivered,
    )


def _external_row(circuit: str) -> dict[str, str]:
    return {
        "variant": "hier_fs_iso",
        "n": "8",
        "k": "2",
        "m": "4",
        "run": "1",
        "circuit": circuit,
        "circuit_size": "10" if circuit.startswith("sub_") else "20",
        "acir_opcodes": "5" if circuit.startswith("sub_") else "8",
        "compile_s": "1",
        "witness_s": "1",
        "prove_s": "1",
        "verify_s": "1",
        "proof_bytes": str(PROOF_BYTES),
        "peak_mb": "1",
        "verify_hier_s": "0.1",
        "xchecks_ok": "1",
    }


def _write_fixture(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _median(values: list[Decimal]) -> Decimal:
    values = sorted(values)
    middle = len(values) // 2
    if len(values) % 2:
        return values[middle]
    return (values[middle - 1] + values[middle]) / 2


if __name__ == "__main__":
    unittest.main()
