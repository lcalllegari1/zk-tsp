from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable

from .domain import merkle_depth
from .workspace import PROJECT_ROOT

RESULTS_MANIFEST = PROJECT_ROOT / "provenance" / "results-manifest.json"
RESULTS_SCHEMA = "zk-tsp.results-manifest.v1"
PROOF_BYTES = 14_656
RECURSIVE_GATE_DELTA = 113

MONOLITHIC_FIELDS = [
    "variant",
    "n",
    "run",
    "circuit_size",
    "acir_opcodes",
    "compile_s",
    "witness_s",
    "prove_s",
    "verify_s",
    "proof_bytes",
    "peak_mb",
]
EXTERNAL_FIELDS = [
    "variant",
    "n",
    "k",
    "m",
    "run",
    "circuit",
    "circuit_size",
    "acir_opcodes",
    "compile_s",
    "witness_s",
    "prove_s",
    "verify_s",
    "proof_bytes",
    "peak_mb",
    "verify_hier_s",
    "xchecks_ok",
]
RECURSIVE_FIELDS = [
    "exp",
    "n",
    "k",
    "m",
    "depth",
    "run",
    "role",
    "circuit",
    "gates",
    "acir",
    "compile_s",
    "witness_s",
    "prove_s",
    "verify_s",
    "proof_bytes",
    "peak_mb",
]
CALIBRATION_FIELDS = [
    "n",
    "k",
    "depth",
    "old_outer_gates",
    "new_outer_gates",
    "gate_delta",
    "old_outer_acir",
    "new_outer_acir",
    "acir_delta",
    "proof_bytes",
    "calibration_prove_s",
    "calibration_verify_s",
    "calibration_peak_mb",
]
SCHEMAS = {
    "monolithic": MONOLITHIC_FIELDS,
    "external": EXTERNAL_FIELDS,
    "recursive": RECURSIVE_FIELDS,
    "calibration": CALIBRATION_FIELDS,
}

MONOLITHIC_VARIANTS = {
    "mechanism-study": {
        "flat_full_pairwise": "study-pairwise",
        "flat_full_presence": "study-presence",
        "flat_full_invperm": "study-inverse",
        "flat_full_sort": "study-sort",
    },
    "monolithic": {
        "flat_full_pairwise": "public-pairwise",
        "flat_full_sort": "public-sort",
        "flat_merkle_sort": "monolithic-sort",
        "flat_merkle_grand_product": "monolithic-product",
    },
    "monolithic-large": {
        "flat_merkle_sort": "monolithic-sort",
        "flat_merkle_grand_product": "monolithic-product",
    },
}
EXTERNAL_VARIANTS = {
    "plain-sort": "hier_a_iso",
    "plain-product": "hier_fs_iso",
    "committed-sort": "hier_c_iso",
    "committed-product": "hier_cfs_iso",
}
EXTERNAL_CONSTRUCTIONS = frozenset(EXTERNAL_VARIANTS)
RECURSIVE_CONSTRUCTIONS = frozenset({"recursive-product"})
EXTERNAL_NODES = (48, 96, 128, 256, 512, 768, 1000, 1504, 2000, 2504, 3000, 4000, 5000)
RECURSIVE_SMALL_NODES = (48, 96, 128, 256, 512, 768, 1000)
RECURSIVE_LARGE_NODES = (1504, 2000, 2504, 3000, 4000, 5000)
COMPOSITE_SEGMENTS = (2, 4, 8)

COMPONENT_FIELDS = [
    "construction",
    "n",
    "k",
    "run",
    "role",
    "component_index",
    "gates",
    "acir",
    "compile_s",
    "witness_s",
    "prove_s",
    "verify_s",
    "reconciliation_s",
    "proof_bytes",
    "peak_mb",
    "delivered",
]
ARCHITECTURE_FIELDS = [
    "construction",
    "n",
    "k",
    "run",
    "aggregate_gates",
    "aggregate_acir",
    "sequential_witness_s",
    "sequential_prove_s",
    "sequential_online_s",
    "distributed_online_s",
    "peak_mb",
    "backend_verify_s",
    "proof_count",
    "proof_bytes",
]
SUMMARY_FIELDS = [
    "construction",
    "n",
    "k",
    "metric",
    "statistic",
    "observations",
    "center",
    "min",
    "max",
]


class ResultsValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ComponentRow:
    construction: str
    n: int
    k: int | None
    run: int
    role: str
    component_index: int | None
    gates: int
    acir: int
    compile_s: Decimal
    witness_s: Decimal
    prove_s: Decimal
    verify_s: Decimal | None
    reconciliation_s: Decimal | None
    proof_bytes: int | None
    peak_mb: Decimal
    delivered: bool

    @property
    def online_s(self) -> Decimal:
        return self.witness_s + self.prove_s


@dataclass(frozen=True)
class ArchitectureRow:
    construction: str
    n: int
    k: int | None
    run: int
    aggregate_gates: int
    aggregate_acir: int
    sequential_witness_s: Decimal
    sequential_prove_s: Decimal
    sequential_online_s: Decimal
    distributed_online_s: Decimal
    peak_mb: Decimal
    backend_verify_s: Decimal
    proof_count: int
    proof_bytes: int


@dataclass(frozen=True)
class ResultsValidationReport:
    tracked_datasets: int
    thesis_inputs: int
    component_rows: int
    architecture_runs: int
    summary_rows: int
    recursive_rows_changed: int


def validate_results() -> ResultsValidationReport:
    records = _validate_manifest_files()
    _validate_calibration(_path_for(records, "recursive-key-embedding-calibration"))
    changed = _validate_derived_views(records)
    components = _load_thesis_components(records)
    architectures = aggregate_architectures(components)
    summaries = summarize_architectures(architectures)
    return ResultsValidationReport(
        tracked_datasets=len(records),
        thesis_inputs=9,
        component_rows=len(components),
        architecture_runs=len(architectures),
        summary_rows=len(summaries),
        recursive_rows_changed=changed,
    )


def load_results_components() -> list[ComponentRow]:
    records = _validate_manifest_files()
    _validate_calibration(_path_for(records, "recursive-key-embedding-calibration"))
    _validate_derived_views(records)
    return _load_thesis_components(records)


def reproduce_results(output: Path) -> Path:
    records = _validate_manifest_files()
    _validate_calibration(_path_for(records, "recursive-key-embedding-calibration"))
    _validate_derived_views(records)

    output = output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"output destination is not empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        derived = staging / "derived"
        derived.mkdir()
        small = derived / "recursive_gp.csv"
        large = derived / "recursive_gp_large.csv"
        small.write_bytes(
            materialize_recursive_bytes(
                _path_for(records, "recursive-product-pre-repair").read_bytes()
            )
        )
        large.write_bytes(
            materialize_recursive_bytes(
                _path_for(records, "recursive-product-large-pre-repair").read_bytes()
            )
        )
        components = _load_thesis_components(
            records,
            recursive_paths={
                "recursive-product": small,
                "recursive-product-large": large,
            },
        )
        architectures = aggregate_architectures(components)
        summaries = summarize_architectures(architectures)
        _write_csv(staging / "components.csv", COMPONENT_FIELDS, components)
        _write_csv(staging / "architectures.csv", ARCHITECTURE_FIELDS, architectures)
        _write_csv(staging / "summaries.csv", SUMMARY_FIELDS, summaries)
        if output.exists():
            output.rmdir()
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output


def materialize_recursive_bytes(source: bytes) -> bytes:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ResultsValidationError("recursive dataset is not UTF-8") from exc
    reader = csv.reader(io.StringIO(text, newline=""))
    rows = list(reader)
    if not rows or rows[0] != RECURSIVE_FIELDS:
        raise ResultsValidationError("recursive dataset has an unexpected header")
    role_index = RECURSIVE_FIELDS.index("role")
    gates_index = RECURSIVE_FIELDS.index("gates")
    acir_index = RECURSIVE_FIELDS.index("acir")
    for line, row in enumerate(rows[1:], start=2):
        if len(row) != len(RECURSIVE_FIELDS):
            raise ResultsValidationError(
                f"recursive dataset row {line} has {len(row)} fields"
            )
        if row[role_index] == "outer_recursive":
            row[gates_index] = str(
                _strict_int(row[gates_index], "gates", line)
                + RECURSIVE_GATE_DELTA
            )
            row[acir_index] = str(
                _strict_int(row[acir_index], "acir", line)
                + RECURSIVE_GATE_DELTA
            )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerows(rows)
    return output.getvalue().encode()


def aggregate_architectures(
    components: Iterable[ComponentRow],
) -> list[ArchitectureRow]:
    grouped: dict[tuple[str, int, int | None, int], list[ComponentRow]] = defaultdict(list)
    for component in components:
        grouped[
            (component.construction, component.n, component.k, component.run)
        ].append(component)
    output = []
    for (construction, n, k, run), tasks in sorted(
        grouped.items(), key=lambda item: _group_sort_key(item[0])
    ):
        _validate_architecture_group(construction, n, k, run, tasks)
        witness = sum((task.witness_s for task in tasks), Decimal(0))
        prove = sum((task.prove_s for task in tasks), Decimal(0))
        online = witness + prove
        if construction in EXTERNAL_CONSTRUCTIONS:
            distributed = max(task.online_s for task in tasks)
        elif construction in RECURSIVE_CONSTRUCTIONS:
            inners = [task for task in tasks if task.role == "inner"]
            outer = next(task for task in tasks if task.role == "outer")
            distributed = max(task.online_s for task in inners) + outer.online_s
        else:
            distributed = tasks[0].online_s
        delivered = [task for task in tasks if task.delivered]
        verify = sum(
            (task.verify_s or Decimal(0) for task in delivered), Decimal(0)
        )
        output.append(
            ArchitectureRow(
                construction=construction,
                n=n,
                k=k,
                run=run,
                aggregate_gates=sum(task.gates for task in tasks),
                aggregate_acir=sum(task.acir for task in tasks),
                sequential_witness_s=witness,
                sequential_prove_s=prove,
                sequential_online_s=online,
                distributed_online_s=distributed,
                peak_mb=max(task.peak_mb for task in tasks),
                backend_verify_s=verify,
                proof_count=len(delivered),
                proof_bytes=sum(task.proof_bytes or 0 for task in delivered),
            )
        )
    return output


def summarize_architectures(
    rows: Iterable[ArchitectureRow],
) -> list[dict[str, object]]:
    grouped: dict[tuple[str, int, int | None], list[ArchitectureRow]] = defaultdict(list)
    for row in rows:
        grouped[(row.construction, row.n, row.k)].append(row)
    deterministic = (
        "aggregate_gates",
        "aggregate_acir",
        "proof_count",
        "proof_bytes",
    )
    timings = (
        "sequential_witness_s",
        "sequential_prove_s",
        "sequential_online_s",
        "distributed_online_s",
        "backend_verify_s",
    )
    output: list[dict[str, object]] = []
    for (construction, n, k), group in sorted(
        grouped.items(), key=lambda item: _group_sort_key((*item[0], 0))
    ):
        for metric in deterministic:
            values = [Decimal(getattr(row, metric)) for row in group]
            if len(set(values)) != 1:
                raise ResultsValidationError(
                    f"{construction} n={n} k={k}: {metric} differs across runs"
                )
            output.append(
                _summary_row(construction, n, k, metric, "exact", values[0], values)
            )
        for metric in timings:
            values = [getattr(row, metric) for row in group]
            output.append(
                _summary_row(construction, n, k, metric, "minimum", min(values), values)
            )
        memory = [row.peak_mb for row in group]
        output.append(
            _summary_row(
                construction,
                n,
                k,
                "peak_mb",
                "median",
                _median(memory),
                memory,
            )
        )
    return output


def parse_monolithic_dataset(path: Path, dataset_id: str) -> list[ComponentRow]:
    variants = MONOLITHIC_VARIANTS.get(dataset_id)
    if variants is None:
        raise ResultsValidationError(f"unknown monolithic dataset: {dataset_id}")
    rows = _read_rows(path, MONOLITHIC_FIELDS)
    output = []
    seen = set()
    for line, row in enumerate(rows, start=2):
        variant = row["variant"]
        if variant not in variants:
            raise ResultsValidationError(f"{path.name}:{line}: unexpected variant {variant}")
        task = ComponentRow(
            construction=variants[variant],
            n=_positive_int(row["n"], "n", line),
            k=None,
            run=_positive_int(row["run"], "run", line),
            role="monolithic",
            component_index=None,
            gates=_positive_int(row["circuit_size"], "circuit_size", line),
            acir=_positive_int(row["acir_opcodes"], "acir_opcodes", line),
            compile_s=_positive_decimal(row["compile_s"], "compile_s", line),
            witness_s=_positive_decimal(row["witness_s"], "witness_s", line),
            prove_s=_positive_decimal(row["prove_s"], "prove_s", line),
            verify_s=_positive_decimal(row["verify_s"], "verify_s", line),
            reconciliation_s=None,
            proof_bytes=_proof_bytes(row["proof_bytes"], line),
            peak_mb=_positive_decimal(row["peak_mb"], "peak_mb", line),
            delivered=True,
        )
        key = (task.construction, task.n, task.run)
        if key in seen:
            raise ResultsValidationError(f"{path.name}:{line}: duplicate monolithic row")
        seen.add(key)
        output.append(task)
    return output


def parse_external_dataset(path: Path, construction: str) -> list[ComponentRow]:
    expected_variant = EXTERNAL_VARIANTS.get(construction)
    if expected_variant is None:
        raise ResultsValidationError(f"unknown external construction: {construction}")
    rows = _read_rows(path, EXTERNAL_FIELDS)
    parsed: list[tuple[ComponentRow, Decimal, int]] = []
    segment_pattern = re.compile(r"sub_(\d+)")
    for line, row in enumerate(rows, start=2):
        if row["variant"] != expected_variant:
            raise ResultsValidationError(f"{path.name}:{line}: unexpected variant")
        n = _positive_int(row["n"], "n", line)
        k = _positive_int(row["k"], "k", line)
        m = _positive_int(row["m"], "m", line)
        _validate_geometry(n, k, m, line)
        circuit = row["circuit"]
        match = segment_pattern.fullmatch(circuit)
        if match:
            role = "segment"
            index = int(match.group(1))
        elif circuit == "glue":
            role = "glue"
            index = None
        else:
            raise ResultsValidationError(f"{path.name}:{line}: invalid circuit role")
        task = ComponentRow(
            construction=construction,
            n=n,
            k=k,
            run=_positive_int(row["run"], "run", line),
            role=role,
            component_index=index,
            gates=_positive_int(row["circuit_size"], "circuit_size", line),
            acir=_positive_int(row["acir_opcodes"], "acir_opcodes", line),
            compile_s=_positive_decimal(row["compile_s"], "compile_s", line),
            witness_s=_positive_decimal(row["witness_s"], "witness_s", line),
            prove_s=_positive_decimal(row["prove_s"], "prove_s", line),
            verify_s=_positive_decimal(row["verify_s"], "verify_s", line),
            reconciliation_s=None,
            proof_bytes=_proof_bytes(row["proof_bytes"], line),
            peak_mb=_positive_decimal(row["peak_mb"], "peak_mb", line),
            delivered=True,
        )
        parsed.append(
            (
                task,
                _positive_decimal(row["verify_hier_s"], "verify_hier_s", line),
                _strict_int(row["xchecks_ok"], "xchecks_ok", line),
            )
        )
    grouped: dict[tuple[int, int, int], list[tuple[ComponentRow, Decimal, int]]] = defaultdict(list)
    for item in parsed:
        task = item[0]
        grouped[(task.n, task.k or 0, task.run)].append(item)
    output = []
    for (n, k, run), group in grouped.items():
        tasks = [item[0] for item in group]
        segments = [task for task in tasks if task.role == "segment"]
        glues = [task for task in tasks if task.role == "glue"]
        indexes = [task.component_index for task in segments]
        if sorted(indexes) != list(range(k)) or len(glues) != 1:
            raise ResultsValidationError(
                f"{construction} n={n} k={k} run={run}: incomplete proof set"
            )
        if len({(task.gates, task.acir) for task in segments}) != 1:
            raise ResultsValidationError(
                f"{construction} n={n} k={k} run={run}: segment shapes differ"
            )
        reconciliation = {item[1] for item in group}
        if len(reconciliation) != 1 or any(item[2] != 1 for item in group):
            raise ResultsValidationError(
                f"{construction} n={n} k={k} run={run}: reconciliation failed"
            )
        value = reconciliation.pop()
        output.extend(segments)
        output.append(replace(glues[0], reconciliation_s=value))
    _validate_deterministic_components(output)
    return output


def parse_recursive_dataset(path: Path) -> list[ComponentRow]:
    rows = _read_rows(path, RECURSIVE_FIELDS)
    output = []
    segment_pattern = re.compile(r"sub_(\d+)")
    for line, row in enumerate(rows, start=2):
        if _strict_int(row["exp"], "exp", line) != 2:
            raise ResultsValidationError(f"{path.name}:{line}: only exp=2 is in scope")
        n = _positive_int(row["n"], "n", line)
        k = _positive_int(row["k"], "k", line)
        m = _positive_int(row["m"], "m", line)
        _validate_geometry(n, k, m, line)
        if _positive_int(row["depth"], "depth", line) != merkle_depth(n):
            raise ResultsValidationError(f"{path.name}:{line}: invalid Merkle depth")
        role = row["role"]
        if role == "inner_segment":
            match = segment_pattern.fullmatch(row["circuit"])
            if match is None or row["verify_s"] or row["proof_bytes"]:
                raise ResultsValidationError(f"{path.name}:{line}: invalid inner row")
            normalized_role = "inner"
            index = int(match.group(1))
            verify = None
            proof_bytes = None
            delivered = False
        elif role == "outer_recursive":
            if row["circuit"] not in {"recursion", "composite_recursive"}:
                raise ResultsValidationError(f"{path.name}:{line}: invalid outer circuit")
            normalized_role = "outer"
            index = None
            verify = _positive_decimal(row["verify_s"], "verify_s", line)
            proof_bytes = _proof_bytes(row["proof_bytes"], line)
            delivered = True
        else:
            raise ResultsValidationError(f"{path.name}:{line}: invalid recursive role")
        output.append(
            ComponentRow(
                construction="recursive-product",
                n=n,
                k=k,
                run=_positive_int(row["run"], "run", line),
                role=normalized_role,
                component_index=index,
                gates=_positive_int(row["gates"], "gates", line),
                acir=_positive_int(row["acir"], "acir", line),
                compile_s=_positive_decimal(row["compile_s"], "compile_s", line),
                witness_s=_positive_decimal(row["witness_s"], "witness_s", line),
                prove_s=_positive_decimal(row["prove_s"], "prove_s", line),
                verify_s=verify,
                reconciliation_s=None,
                proof_bytes=proof_bytes,
                peak_mb=_positive_decimal(row["peak_mb"], "peak_mb", line),
                delivered=delivered,
            )
        )
    grouped: dict[tuple[int, int, int], list[ComponentRow]] = defaultdict(list)
    for task in output:
        grouped[(task.n, task.k or 0, task.run)].append(task)
    for (n, k, run), tasks in grouped.items():
        inners = [task for task in tasks if task.role == "inner"]
        outers = [task for task in tasks if task.role == "outer"]
        if (
            sorted(task.component_index for task in inners) != list(range(k))
            or len(outers) != 1
        ):
            raise ResultsValidationError(
                f"recursive-product n={n} k={k} run={run}: incomplete proof set"
            )
        if len({(task.gates, task.acir) for task in inners}) != 1:
            raise ResultsValidationError(
                f"recursive-product n={n} k={k} run={run}: inner shapes differ"
            )
    _validate_deterministic_components(output)
    return output


def _validate_manifest_files() -> dict[str, dict[str, Any]]:
    try:
        manifest = json.loads(RESULTS_MANIFEST.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ResultsValidationError("cannot read results manifest") from exc
    if manifest.get("schema") != RESULTS_SCHEMA:
        raise ResultsValidationError("unsupported results manifest schema")
    datasets = manifest.get("datasets")
    if not isinstance(datasets, list):
        raise ResultsValidationError("results manifest has no dataset list")
    records = {}
    for record in datasets:
        try:
            dataset_id = record["id"]
            relative = Path(record["path"])
            expected_hash = record["sha256"]
            expected_rows = int(record["rows"])
            expected_fields = SCHEMAS[record["schema_name"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise ResultsValidationError("malformed results manifest record") from exc
        if dataset_id in records or relative.is_absolute() or ".." in relative.parts:
            raise ResultsValidationError("unsafe or duplicate results manifest record")
        path = PROJECT_ROOT / relative
        try:
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            rows = _read_rows(path, expected_fields)
        except OSError as exc:
            raise ResultsValidationError(f"cannot read tracked dataset {relative}") from exc
        if actual_hash != expected_hash:
            raise ResultsValidationError(f"tracked dataset hash mismatch: {relative}")
        if len(rows) != expected_rows:
            raise ResultsValidationError(f"tracked dataset row-count mismatch: {relative}")
        records[dataset_id] = record
    if len(records) != 12:
        raise ResultsValidationError("results manifest must contain exactly 12 records")
    return records


def _validate_calibration(path: Path) -> None:
    rows = _read_rows(path, CALIBRATION_FIELDS)
    if len(rows) != 3:
        raise ResultsValidationError("recursive calibration must contain three rows")
    for line, row in enumerate(rows, start=2):
        old_gates = _positive_int(row["old_outer_gates"], "old_outer_gates", line)
        new_gates = _positive_int(row["new_outer_gates"], "new_outer_gates", line)
        old_acir = _positive_int(row["old_outer_acir"], "old_outer_acir", line)
        new_acir = _positive_int(row["new_outer_acir"], "new_outer_acir", line)
        if (
            new_gates - old_gates != RECURSIVE_GATE_DELTA
            or new_acir - old_acir != RECURSIVE_GATE_DELTA
            or _strict_int(row["gate_delta"], "gate_delta", line)
            != RECURSIVE_GATE_DELTA
            or _strict_int(row["acir_delta"], "acir_delta", line)
            != RECURSIVE_GATE_DELTA
        ):
            raise ResultsValidationError("recursive calibration does not support +113")
        if row["proof_bytes"] and _proof_bytes(row["proof_bytes"], line) != PROOF_BYTES:
            raise ResultsValidationError("recursive calibration has an invalid proof size")


def _validate_derived_views(records: dict[str, dict[str, Any]]) -> int:
    pairs = (
        ("recursive-product-pre-repair", "recursive-product", 42),
        ("recursive-product-large-pre-repair", "recursive-product-large", 36),
    )
    changed = 0
    for source_id, derived_id, expected_changes in pairs:
        source = _path_for(records, source_id)
        derived = _path_for(records, derived_id)
        generated = materialize_recursive_bytes(source.read_bytes())
        if generated != derived.read_bytes():
            raise ResultsValidationError(f"derived recursive view differs: {derived.name}")
        rows = _read_rows(derived, RECURSIVE_FIELDS)
        changes = sum(row["role"] == "outer_recursive" for row in rows)
        if changes != expected_changes:
            raise ResultsValidationError(
                f"{derived.name} changes {changes} rows; expected {expected_changes}"
            )
        changed += changes
    return changed


def _load_thesis_components(
    records: dict[str, dict[str, Any]],
    *,
    recursive_paths: dict[str, Path] | None = None,
) -> list[ComponentRow]:
    output = []
    for dataset_id in ("mechanism-study", "monolithic", "monolithic-large"):
        output.extend(parse_monolithic_dataset(_path_for(records, dataset_id), dataset_id))
    for construction in EXTERNAL_VARIANTS:
        tasks = parse_external_dataset(_path_for(records, construction), construction)
        _validate_grid(tasks, construction, EXTERNAL_NODES, runs=(1, 2, 3))
        output.extend(tasks)
    recursive_paths = recursive_paths or {}
    for dataset_id in ("recursive-product", "recursive-product-large"):
        tasks = parse_recursive_dataset(
            recursive_paths.get(dataset_id, _path_for(records, dataset_id))
        )
        nodes = (
            RECURSIVE_LARGE_NODES
            if dataset_id.endswith("large")
            else RECURSIVE_SMALL_NODES
        )
        _validate_grid(tasks, "recursive-product", nodes, runs=(1, 2))
        output.extend(tasks)
    _validate_deterministic_components(output)
    return sorted(output, key=_component_sort_key)


def _validate_deterministic_components(rows: Iterable[ComponentRow]) -> None:
    seen: dict[
        tuple[str, int, int | None, str, int | None], set[tuple[int, int]]
    ] = defaultdict(set)
    unique = set()
    for row in rows:
        instance_key = (
            row.construction,
            row.n,
            row.k,
            row.run,
            row.role,
            row.component_index,
        )
        if instance_key in unique:
            raise ResultsValidationError(f"duplicate component row: {instance_key}")
        unique.add(instance_key)
        shape_key = (row.construction, row.n, row.k, row.role, row.component_index)
        seen[shape_key].add((row.gates, row.acir))
    for key, shapes in seen.items():
        if len(shapes) != 1:
            raise ResultsValidationError(f"component shape differs across runs: {key}")


def _validate_architecture_group(
    construction: str,
    n: int,
    k: int | None,
    run: int,
    tasks: list[ComponentRow],
) -> None:
    if construction in EXTERNAL_CONSTRUCTIONS:
        segments = [task for task in tasks if task.role == "segment"]
        glues = [task for task in tasks if task.role == "glue"]
        valid = (
            k is not None
            and sorted(task.component_index for task in segments) == list(range(k))
            and len(glues) == 1
            and len(tasks) == k + 1
        )
    elif construction in RECURSIVE_CONSTRUCTIONS:
        inners = [task for task in tasks if task.role == "inner"]
        outers = [task for task in tasks if task.role == "outer"]
        valid = (
            k is not None
            and sorted(task.component_index for task in inners) == list(range(k))
            and len(outers) == 1
            and len(tasks) == k + 1
        )
    else:
        valid = k is None and len(tasks) == 1 and tasks[0].role == "monolithic"
    if not valid:
        raise ResultsValidationError(
            f"{construction} n={n} k={k} run={run}: incomplete architecture run"
        )


def _validate_grid(
    rows: Iterable[ComponentRow],
    construction: str,
    nodes: tuple[int, ...],
    *,
    runs: tuple[int, ...],
) -> None:
    actual = {(row.n, row.k, row.run) for row in rows}
    expected = {
        (n, k, run)
        for n in nodes
        for k in COMPOSITE_SEGMENTS
        for run in runs
    }
    if actual != expected:
        raise ResultsValidationError(f"{construction} has an incomplete benchmark grid")


def _read_rows(path: Path, expected_fields: list[str]) -> list[dict[str, str]]:
    try:
        with path.open(newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != expected_fields:
                raise ResultsValidationError(f"{path.name} has an unexpected header")
            rows = list(reader)
    except (OSError, csv.Error) as exc:
        raise ResultsValidationError(f"cannot parse {path}") from exc
    if not rows:
        raise ResultsValidationError(f"{path.name} is empty")
    if any(None in row or None in row.values() for row in rows):
        raise ResultsValidationError(f"{path.name} contains a malformed row")
    return rows


def _path_for(records: dict[str, dict[str, Any]], dataset_id: str) -> Path:
    try:
        return PROJECT_ROOT / records[dataset_id]["path"]
    except KeyError as exc:
        raise ResultsValidationError(f"missing results dataset: {dataset_id}") from exc


def _validate_geometry(n: int, k: int, m: int, line: int) -> None:
    if k < 2 or n % k or n // k != m or m <= 2:
        raise ResultsValidationError(f"row {line}: invalid composite geometry")


def _strict_int(value: str, field: str, line: int) -> int:
    if re.fullmatch(r"-?\d+", value) is None:
        raise ResultsValidationError(f"row {line}: {field} is not an integer")
    return int(value)


def _positive_int(value: str, field: str, line: int) -> int:
    parsed = _strict_int(value, field, line)
    if parsed <= 0:
        raise ResultsValidationError(f"row {line}: {field} must be positive")
    return parsed


def _positive_decimal(value: str, field: str, line: int) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ResultsValidationError(f"row {line}: {field} is not numeric") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ResultsValidationError(f"row {line}: {field} must be finite and positive")
    return parsed


def _proof_bytes(value: str, line: int) -> int:
    parsed = _positive_int(value, "proof_bytes", line)
    if parsed != PROOF_BYTES:
        raise ResultsValidationError(
            f"row {line}: proof_bytes is {parsed}; expected {PROOF_BYTES}"
        )
    return parsed


def _median(values: list[Decimal]) -> Decimal:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / Decimal(2)


def _summary_row(
    construction: str,
    n: int,
    k: int | None,
    metric: str,
    statistic: str,
    center: Decimal,
    values: list[Decimal],
) -> dict[str, object]:
    return {
        "construction": construction,
        "n": n,
        "k": k,
        "metric": metric,
        "statistic": statistic,
        "observations": len(values),
        "center": center,
        "min": min(values),
        "max": max(values),
    }


def _write_csv(path: Path, fields: list[str], rows: Iterable[object]) -> None:
    with path.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            values = row if isinstance(row, dict) else asdict(row)
            writer.writerow({field: _csv_value(values[field]) for field in fields})


def _csv_value(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, Decimal):
        return _decimal_text(value)
    return value


def _decimal_text(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _component_sort_key(row: ComponentRow) -> tuple[object, ...]:
    role_order = {"monolithic": 0, "segment": 0, "inner": 0, "glue": 1, "outer": 1}
    return (
        row.construction,
        row.n,
        row.k or 0,
        row.run,
        role_order[row.role],
        row.component_index if row.component_index is not None else -1,
    )


def _group_sort_key(key: tuple[str, int, int | None, int]) -> tuple[object, ...]:
    construction, n, k, run = key
    return construction, n, k or 0, run
