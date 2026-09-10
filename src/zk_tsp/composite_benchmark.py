from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Iterable

from .backend import CompiledCircuit, ProofMetrics, compile_circuit, prove_and_verify
from .cache import InstanceCache
from .composite import (
    COMPOSITE_VARIANTS,
    composite_for,
    refresh_composite_witnesses,
    temporary_composite_workspace,
    validate_geometry,
)
from .domain import DEFAULT_SEED
from .external_verify import verify_composite_workspace
from .workspace import DEFAULT_CACHE_ROOT

COMPOSITE_FIELDNAMES = [
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


def benchmark_composite(
    variants: Iterable[str],
    nodes: Iterable[int],
    segments: Iterable[int],
    runs: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
    cache_dir: Path = DEFAULT_CACHE_ROOT,
) -> Path:
    selected = list(variants)
    sizes = list(nodes)
    segment_counts = list(segments)
    if not selected or any(item not in COMPOSITE_VARIANTS for item in selected):
        raise ValueError("at least one valid composite variant is required")
    if not sizes:
        raise ValueError("at least one node count is required")
    if not segment_counts:
        raise ValueError("at least one segment count is required")
    for n in sizes:
        for k in segment_counts:
            validate_geometry(n, k)
    if runs < 1:
        raise ValueError("runs must be at least 1")

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    cache = InstanceCache(cache_dir)
    with output.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COMPOSITE_FIELDNAMES)
        writer.writeheader()
        stream.flush()

        for n in sizes:
            cached = cache.load_or_create(n, seed)
            for k in segment_counts:
                m = validate_geometry(n, k)
                for variant in selected:
                    spec = composite_for(variant)
                    print(f"N={n} K={k} variant={variant}: compile", flush=True)
                    with temporary_composite_workspace(
                        variant, cached, k, seed=seed
                    ) as workspace:
                        segment_compiled, glue_compiled = _compile_proof_set(
                            workspace, spec.segment_package, spec.glue_package, k
                        )
                        for run in range(1, runs + 1):
                            print(f"  run {run}/{runs} (isolated)", flush=True)
                            refresh_composite_witnesses(workspace, variant, cached, k)
                            proof_metrics = _prove_isolated(
                                workspace, spec.segment_package, spec.glue_package, k
                            )
                            report = verify_composite_workspace(workspace)
                            for circuit, metrics in proof_metrics:
                                is_glue = circuit == "glue"
                                compiled = glue_compiled if is_glue else segment_compiled
                                writer.writerow(
                                    _raw_row(
                                        spec.csv_variant,
                                        n,
                                        k,
                                        m,
                                        run,
                                        circuit,
                                        compiled,
                                        metrics,
                                        report.elapsed_s,
                                    )
                                )
                            stream.flush()
    return output


def _compile_proof_set(
    workspace: Path, segment_package: str, glue_package: str, k: int
) -> tuple[CompiledCircuit, CompiledCircuit]:
    segment_results = [
        compile_circuit(workspace / f"sub_{index}", segment_package)
        for index in range(k)
    ]
    reference = segment_results[0]
    for index, compiled in enumerate(segment_results[1:], start=1):
        if (
            compiled.acir_opcodes != reference.acir_opcodes
            or compiled.circuit_size != reference.circuit_size
        ):
            raise RuntimeError(f"sub_{index} compiled to a different circuit shape")
    reference_artifact = _semantic_artifact_hash(
        workspace / "sub_0" / "target" / f"{segment_package}.json"
    )
    reference_key = _sha256(workspace / "sub_0" / "target" / "vk" / "vk")
    for index in range(1, k):
        if (
            _semantic_artifact_hash(
                workspace / f"sub_{index}" / "target" / f"{segment_package}.json"
            )
            != reference_artifact
        ):
            raise RuntimeError(f"sub_{index} compiled to different executable bytecode")
        if _sha256(workspace / f"sub_{index}" / "target" / "vk" / "vk") != reference_key:
            raise RuntimeError(f"sub_{index} produced a different verification key")
    glue = compile_circuit(workspace / "glue", glue_package)
    return reference, glue


def _prove_isolated(
    workspace: Path, segment_package: str, glue_package: str, k: int
) -> list[tuple[str, ProofMetrics]]:
    results = []
    for index in range(k):
        results.append(
            (
                f"sub_{index}",
                prove_and_verify(workspace / f"sub_{index}", segment_package),
            )
        )
    results.append(("glue", prove_and_verify(workspace / "glue", glue_package)))
    return results


def _raw_row(
    variant: str,
    n: int,
    k: int,
    m: int,
    run: int,
    circuit: str,
    compiled: CompiledCircuit,
    metrics: ProofMetrics,
    verify_hier_s: float,
) -> dict:
    return {
        "variant": variant,
        "n": n,
        "k": k,
        "m": m,
        "run": run,
        "circuit": circuit,
        "circuit_size": compiled.circuit_size,
        "acir_opcodes": compiled.acir_opcodes,
        "compile_s": round(compiled.compile_s, 4),
        "witness_s": round(metrics.witness_s, 4),
        "prove_s": round(metrics.prove_s, 4),
        "verify_s": round(metrics.verify_s, 4),
        "proof_bytes": metrics.proof_bytes,
        "peak_mb": round(metrics.peak_mb, 3),
        "verify_hier_s": round(verify_hier_s, 4),
        "xchecks_ok": 1,
    }


def _semantic_artifact_hash(path: Path) -> str:
    artifact = json.loads(path.read_text())
    encoded = json.dumps(
        {
            "bytecode": artifact["bytecode"],
            "parameters": artifact["abi"]["parameters"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
