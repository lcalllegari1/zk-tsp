from __future__ import annotations

import csv
import shutil
from pathlib import Path
from typing import Iterable

from .cache import InstanceCache
from .composite import validate_geometry
from .domain import DEFAULT_SEED, merkle_depth
from .recursive import (
    _prove_recursive_workspace,
    refresh_recursive_witnesses,
    temporary_recursive_workspace,
)
from .recursive_verify import verify_recursive_workspace
from .workspace import DEFAULT_CACHE_ROOT

RECURSIVE_FIELDNAMES = [
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


def benchmark_recursive(
    nodes: Iterable[int],
    segments: Iterable[int],
    runs: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
    cache_dir: Path = DEFAULT_CACHE_ROOT,
) -> Path:
    sizes = list(nodes)
    segment_counts = list(segments)
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
    builds = output.parent / f"{output.stem}_builds"
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    if builds.exists():
        raise FileExistsError(f"build-metadata destination already exists: {builds}")
    output.parent.mkdir(parents=True, exist_ok=True)
    cache = InstanceCache(cache_dir)
    builds.mkdir()

    with output.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=RECURSIVE_FIELDNAMES)
        writer.writeheader()
        stream.flush()
        for n in sizes:
            cached = cache.load_or_create(n, seed)
            for k in segment_counts:
                m = validate_geometry(n, k)
                depth = merkle_depth(n)
                print(f"N={n} K={k} recursive-product: setup", flush=True)
                with temporary_recursive_workspace(
                    cached, k, seed=seed
                ) as (workspace, setup):
                    shutil.copyfile(
                        setup.build_metadata,
                        builds / f"n{n}_k{k}_depth{depth}.json",
                    )
                    for run in range(1, runs + 1):
                        print(f"  run {run}/{runs} (dependent outer)", flush=True)
                        refresh_recursive_witnesses(workspace, cached, k)
                        metrics = _prove_recursive_workspace(
                            workspace, replace=run > 1
                        )
                        verification = verify_recursive_workspace(workspace)
                        for index, inner in enumerate(metrics.inner):
                            writer.writerow(
                                _row(
                                    n=n,
                                    k=k,
                                    m=m,
                                    depth=depth,
                                    run=run,
                                    role="inner_segment",
                                    circuit=f"sub_{index}",
                                    gates=setup.inner.circuit_size,
                                    acir=setup.inner.acir_opcodes,
                                    compile_s=setup.inner.compile_s,
                                    witness_s=inner.witness_s,
                                    prove_s=inner.prove_s,
                                    verify_s="",
                                    proof_bytes="",
                                    peak_mb=inner.peak_mb,
                                )
                            )
                        writer.writerow(
                            _row(
                                n=n,
                                k=k,
                                m=m,
                                depth=depth,
                                run=run,
                                role="outer_recursive",
                                circuit="composite_recursive",
                                gates=setup.outer.circuit_size,
                                acir=setup.outer.acir_opcodes,
                                compile_s=setup.outer.compile_s,
                                witness_s=metrics.outer.witness_s,
                                prove_s=metrics.outer.prove_s,
                                verify_s=verification.backend_elapsed_s,
                                proof_bytes=metrics.proof_bytes,
                                peak_mb=metrics.outer.peak_mb,
                            )
                        )
                        stream.flush()
    return output


def _row(**values: object) -> dict[str, object]:
    row = {"exp": 2, **values}
    for field in ("compile_s", "witness_s", "prove_s", "verify_s"):
        if row[field] != "":
            row[field] = round(float(row[field]), 4)
    if row["peak_mb"] != "":
        row["peak_mb"] = round(float(row["peak_mb"]), 3)
    return row
