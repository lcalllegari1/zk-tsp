from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from .cache import CachedInstance, InstanceCache
from .domain import (
    DEFAULT_SEED,
    cycle_cost,
    generate_instance,
    make_study_witness,
    merkle_depth,
    solve,
    threshold_for,
)
from .merkle import write_merkle_witness

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STUDY_ROOT = PROJECT_ROOT / "circuits" / "monolithic" / "study"
COMMITTED_ROOT = PROJECT_ROOT / "circuits" / "monolithic" / "committed"
DEFAULT_CACHE_ROOT = PROJECT_ROOT / "data" / "cache"


@dataclass(frozen=True)
class StudyCircuit:
    mechanism: str
    directory: str
    package: str
    variant: str

    @property
    def path(self) -> Path:
        return STUDY_ROOT / self.directory


@dataclass(frozen=True)
class CommittedCircuit:
    mechanism: str
    directory: str
    package: str
    variant: str

    @property
    def path(self) -> Path:
        return COMMITTED_ROOT / self.directory


STUDY_CIRCUITS = {
    item.mechanism: item
    for item in (
        StudyCircuit("pairwise", "pairwise", "monolithic_study_pairwise", "flat_full_pairwise"),
        StudyCircuit("presence", "presence", "monolithic_study_presence", "flat_full_presence"),
        StudyCircuit("inverse", "inverse", "monolithic_study_invperm", "flat_full_invperm"),
        StudyCircuit("sort", "sort", "monolithic_study_sort", "flat_full_sort"),
    )
}

COMMITTED_CIRCUITS = {
    item.mechanism: item
    for item in (
        CommittedCircuit("sort", "sort", "monolithic_committed_sort", "flat_merkle_sort"),
        CommittedCircuit(
            "product",
            "product",
            "monolithic_committed_product",
            "flat_merkle_grand_product",
        ),
    )
}


def circuit_for(mechanism: str) -> StudyCircuit:
    try:
        return STUDY_CIRCUITS[mechanism]
    except KeyError as exc:
        raise ValueError(f"unknown study mechanism: {mechanism}") from exc


def committed_circuit_for(mechanism: str) -> CommittedCircuit:
    try:
        return COMMITTED_CIRCUITS[mechanism]
    except KeyError as exc:
        raise ValueError(f"unknown committed mechanism: {mechanism}") from exc


def configure_source(source: str, n: int) -> str:
    if n < 1:
        raise ValueError("nodes must be at least 1")
    pattern = r"^global N: u32 = \d+;$"
    matches = re.findall(pattern, source, flags=re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one compile-time N declaration, found {len(matches)}")
    return re.sub(pattern, f"global N: u32 = {n};", source, flags=re.MULTILINE)


def configure_committed_source(source: str, n: int) -> str:
    if n < 2:
        raise ValueError("committed circuits require at least 2 nodes")
    configured = configure_source(source, n)
    pattern = r"^global DEPTH: u32 = \d+;$"
    matches = re.findall(pattern, configured, flags=re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one compile-time DEPTH declaration, found {len(matches)}"
        )
    return re.sub(
        pattern,
        f"global DEPTH: u32 = {merkle_depth(n)};",
        configured,
        flags=re.MULTILINE,
    )


def write_prover_toml(witness: dict[str, Any], path: Path) -> None:
    lines = [f"cycle = [{_decimal_array(witness['cycle'])}]"]
    if "inv_perm" in witness:
        lines.append(f"inv_perm = [{_decimal_array(witness['inv_perm'])}]")
    lines.extend(
        (
            f"cost_matrix = [{_decimal_array(witness['cost_matrix'])}]",
            f'threshold = "{witness["threshold"]}"',
        )
    )
    path.write_text("\n".join(lines) + "\n")


def _decimal_array(values: Sequence[int]) -> str:
    return ", ".join(f'"{value}"' for value in values)


def _populate_workspace(
    destination: Path,
    mechanism: str,
    n: int,
    instance: dict[str, Any],
    cycle: Sequence[int],
    seed: int,
) -> dict[str, Any]:
    circuit = circuit_for(mechanism)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "src").mkdir()

    source = (circuit.path / "src" / "main.nr").read_text()
    configured = configure_source(source, n)
    shutil.copyfile(circuit.path / "Nargo.toml", destination / "Nargo.toml")
    (destination / "src" / "main.nr").write_text(configured)

    witness = make_study_witness(instance, cycle, mechanism)
    write_prover_toml(witness, destination / "Prover.toml")
    (destination / "instance.json").write_text(json.dumps(instance, indent=2) + "\n")
    (destination / "cycle.json").write_text(
        json.dumps(
            {
                "cycle": list(cycle),
                "cost": cycle_cost(instance["matrix"], cycle),
                "threshold": threshold_for(witness["cost"]),
            },
            indent=2,
        )
        + "\n"
    )
    metadata = {
        "schema": "zk-tsp.workspace.v1",
        "mechanism": mechanism,
        "package": circuit.package,
        "variant": circuit.variant,
        "nodes": n,
        "seed": seed,
        "canonical_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
    }
    (destination / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )
    return witness


def _populate_committed_workspace(
    destination: Path,
    mechanism: str,
    cached: CachedInstance,
    seed: int,
) -> None:
    n = int(cached.instance["metadata"]["n"])
    circuit = committed_circuit_for(mechanism)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "src").mkdir()

    source = (circuit.path / "src" / "main.nr").read_text()
    configured = configure_committed_source(source, n)
    shutil.copyfile(circuit.path / "Nargo.toml", destination / "Nargo.toml")
    (destination / "src" / "main.nr").write_text(configured)
    write_merkle_witness(
        cached.instance,
        cached.cycle,
        cached.threshold,
        destination / "Prover.toml",
        tree_cache=cached.tree_cache,
    )
    (destination / "instance.json").write_text(
        json.dumps(cached.instance, indent=2) + "\n"
    )
    (destination / "cycle.json").write_text(
        json.dumps(
            {
                "cycle": cached.cycle,
                "cost": cached.cost,
                "threshold": cached.threshold,
            },
            indent=2,
        )
        + "\n"
    )
    metadata = {
        "schema": "zk-tsp.workspace.v1",
        "family": "monolithic-committed",
        "mechanism": mechanism,
        "package": circuit.package,
        "variant": circuit.variant,
        "nodes": n,
        "depth": merkle_depth(n),
        "seed": seed,
        "canonical_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
    }
    (destination / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )


def prepare_workspace(
    mechanism: str,
    n: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
) -> Path:
    output = output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"output destination is not empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    instance = generate_instance(n, seed=seed)
    cycle = solve(instance["matrix"])
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        _populate_workspace(staging, mechanism, n, instance, cycle, seed)
        if output.exists():
            output.rmdir()
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output


def prepare_committed_workspace(
    mechanism: str,
    n: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
    cache_dir: Path = DEFAULT_CACHE_ROOT,
) -> Path:
    committed_circuit_for(mechanism)
    if n < 2:
        raise ValueError("committed circuits require at least 2 nodes")
    output = output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"output destination is not empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    cached = InstanceCache(cache_dir).load_or_create(n, seed)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        _populate_committed_workspace(staging, mechanism, cached, seed)
        if output.exists():
            output.rmdir()
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output


@contextmanager
def temporary_workspace(
    mechanism: str,
    n: int,
    instance: dict[str, Any],
    cycle: Sequence[int],
    *,
    seed: int = DEFAULT_SEED,
) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix=f"zk-tsp-{mechanism}-n{n}-") as tmp:
        destination = Path(tmp) / "circuit"
        _populate_workspace(destination, mechanism, n, instance, cycle, seed)
        yield destination


@contextmanager
def temporary_committed_workspace(
    mechanism: str,
    cached: CachedInstance,
    *,
    seed: int = DEFAULT_SEED,
) -> Iterator[Path]:
    n = int(cached.instance["metadata"]["n"])
    with tempfile.TemporaryDirectory(prefix=f"zk-tsp-committed-{mechanism}-n{n}-") as tmp:
        destination = Path(tmp) / "circuit"
        _populate_committed_workspace(destination, mechanism, cached, seed)
        yield destination
