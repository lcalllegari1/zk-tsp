from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Protocol, TextIO

from .backend import compile_circuit, prove_and_verify
from .cache import InstanceCache
from .domain import DEFAULT_SEED, generate_instance, solve
from .workspace import (
    COMMITTED_CIRCUITS,
    DEFAULT_CACHE_ROOT,
    STUDY_CIRCUITS,
    circuit_for,
    committed_circuit_for,
    temporary_committed_workspace,
    temporary_workspace,
)

FIELDNAMES = [
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


class CircuitDescriptor(Protocol):
    package: str
    variant: str


def _benchmark_workspace(
    writer: csv.DictWriter,
    workspace: Path,
    circuit: CircuitDescriptor,
    n: int,
    runs: int,
    stream: TextIO,
) -> None:
    compiled = compile_circuit(workspace, circuit.package)
    for run in range(1, runs + 1):
        print(f"  run {run}/{runs}", flush=True)
        metrics = prove_and_verify(workspace, circuit.package)
        writer.writerow(
            {
                "variant": circuit.variant,
                "n": n,
                "run": run,
                "circuit_size": compiled.circuit_size,
                "acir_opcodes": compiled.acir_opcodes,
                "compile_s": round(compiled.compile_s, 4),
                "witness_s": round(metrics.witness_s, 4),
                "prove_s": round(metrics.prove_s, 4),
                "verify_s": round(metrics.verify_s, 4),
                "proof_bytes": metrics.proof_bytes,
                "peak_mb": round(metrics.peak_mb, 3),
            }
        )
        stream.flush()


def benchmark_study(
    mechanisms: Iterable[str],
    nodes: Iterable[int],
    runs: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
) -> Path:
    selected = list(mechanisms)
    sizes = list(nodes)
    if not selected or any(item not in STUDY_CIRCUITS for item in selected):
        raise ValueError("at least one valid study mechanism is required")
    if not sizes or any(n < 1 for n in sizes):
        raise ValueError("all node counts must be at least 1")
    if runs < 1:
        raise ValueError("runs must be at least 1")

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDNAMES)
        writer.writeheader()
        stream.flush()

        for n in sizes:
            instance = generate_instance(n, seed=seed)
            cycle = solve(instance["matrix"])
            for mechanism in selected:
                circuit = circuit_for(mechanism)
                print(f"N={n} mechanism={mechanism}: compile", flush=True)
                with temporary_workspace(
                    mechanism, n, instance, cycle, seed=seed
                ) as workspace:
                    _benchmark_workspace(writer, workspace, circuit, n, runs, stream)
    return output


def benchmark_monolithic(
    mechanisms: Iterable[str],
    nodes: Iterable[int],
    runs: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
    cache_dir: Path = DEFAULT_CACHE_ROOT,
) -> Path:
    selected = list(mechanisms)
    sizes = list(nodes)
    if not selected or any(item not in COMMITTED_CIRCUITS for item in selected):
        raise ValueError("at least one valid committed mechanism is required")
    if not sizes or any(n < 2 for n in sizes):
        raise ValueError("committed circuits require node counts of at least 2")
    if runs < 1:
        raise ValueError("runs must be at least 1")

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    cache = InstanceCache(cache_dir)
    with output.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDNAMES)
        writer.writeheader()
        stream.flush()

        for n in sizes:
            cached = cache.load_or_create(n, seed)
            for mechanism in selected:
                circuit = committed_circuit_for(mechanism)
                print(f"N={n} mechanism={mechanism}: compile", flush=True)
                with temporary_committed_workspace(
                    mechanism, cached, seed=seed
                ) as workspace:
                    _benchmark_workspace(writer, workspace, circuit, n, runs, stream)
    return output
