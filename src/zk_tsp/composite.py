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
from typing import Iterator

from .cache import CachedInstance, InstanceCache
from .domain import DEFAULT_SEED, merkle_depth
from .merkle import write_composite_witnesses
from .workspace import DEFAULT_CACHE_ROOT, PROJECT_ROOT

COMPOSITE_ROOT = PROJECT_ROOT / "circuits" / "composite"


@dataclass(frozen=True)
class CompositeSpec:
    variant: str
    directory: str
    segment_package: str
    glue_package: str
    csv_variant: str
    committed: bool = False
    glue_uses_segment_length: bool = False

    @property
    def path(self) -> Path:
        return COMPOSITE_ROOT / self.directory

    @property
    def segment_path(self) -> Path:
        return self.path / "segment"

    @property
    def glue_path(self) -> Path:
        return self.path / "glue"


COMPOSITE_VARIANTS = {
    item.variant: item
    for item in (
        CompositeSpec(
            "plain-sort",
            "plain_sort",
            "composite_plain_sort_segment",
            "composite_plain_sort_glue",
            "hier_a_iso",
        ),
        CompositeSpec(
            "plain-product",
            "plain_product",
            "composite_plain_product_segment",
            "composite_plain_product_glue",
            "hier_fs_iso",
        ),
        CompositeSpec(
            "committed-sort",
            "committed_sort",
            "composite_committed_sort_segment",
            "composite_committed_sort_glue",
            "hier_c_iso",
            committed=True,
            glue_uses_segment_length=True,
        ),
        CompositeSpec(
            "committed-product",
            "committed_product",
            "composite_committed_product_segment",
            "composite_committed_product_glue",
            "hier_cfs_iso",
            committed=True,
        ),
    )
}


def composite_for(variant: str) -> CompositeSpec:
    try:
        return COMPOSITE_VARIANTS[variant]
    except KeyError as exc:
        raise ValueError(f"unknown composite variant: {variant}") from exc


def validate_geometry(n: int, k: int) -> int:
    if k < 2:
        raise ValueError("composite circuits require at least 2 segments")
    if n % k != 0:
        raise ValueError(f"nodes {n} must be divisible by segments {k}")
    m = n // k
    if m <= 2:
        raise ValueError(f"segment length must exceed 2, got {m}")
    return m


def configure_composite_source(source: str, **values: int) -> str:
    configured = source
    for name, value in values.items():
        pattern = rf"^global {name}: u32 = \d+;$"
        matches = re.findall(pattern, configured, flags=re.MULTILINE)
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one compile-time {name} declaration, found {len(matches)}"
            )
        configured = re.sub(
            pattern,
            f"global {name}: u32 = {value};",
            configured,
            flags=re.MULTILINE,
        )
    return configured


def populate_composite_workspace(
    destination: Path,
    variant: str,
    cached: CachedInstance,
    k: int,
    seed: int,
) -> dict:
    spec = composite_for(variant)
    n = int(cached.instance["metadata"]["n"])
    m = validate_geometry(n, k)
    depth = merkle_depth(n)
    destination.mkdir(parents=True, exist_ok=True)

    summary = refresh_composite_witnesses(destination, variant, cached, k)
    segment_source = (spec.segment_path / "src" / "main.nr").read_text()
    glue_source = (spec.glue_path / "src" / "main.nr").read_text()
    configured_segment = configure_composite_source(
        segment_source, N=n, M=m, DEPTH=depth
    )
    glue_values = {"N": n, "K": k, "DEPTH": depth}
    if spec.glue_uses_segment_length:
        glue_values["M"] = m
    configured_glue = configure_composite_source(glue_source, **glue_values)

    for index in range(k):
        workspace = destination / f"sub_{index}"
        _install_circuit(
            workspace,
            spec.segment_path / "Nargo.toml",
            configured_segment,
        )
    _install_circuit(
        destination / "glue",
        spec.glue_path / "Nargo.toml",
        configured_glue,
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
    statement = {
        "schema": "zk-tsp.composite-statement.v1",
        "root": summary["root"],
        "threshold": cached.threshold,
    }
    (destination / "statement.json").write_text(
        json.dumps(statement, indent=2, sort_keys=True) + "\n"
    )
    metadata = {
        "schema": "zk-tsp.composite-workspace.v1",
        "variant": variant,
        "csv_variant": spec.csv_variant,
        "nodes": n,
        "segments": k,
        "segment_length": m,
        "depth": depth,
        "seed": seed,
        "segment_package": spec.segment_package,
        "glue_package": spec.glue_package,
        "blinding": "os-random-128-per-segment" if spec.committed else "none",
        "canonical_segment_sha256": hashlib.sha256(segment_source.encode()).hexdigest(),
        "canonical_glue_sha256": hashlib.sha256(glue_source.encode()).hexdigest(),
    }
    (destination / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )
    return metadata


def refresh_composite_witnesses(
    destination: Path,
    variant: str,
    cached: CachedInstance,
    k: int,
) -> dict:
    composite_for(variant)
    n = int(cached.instance["metadata"]["n"])
    validate_geometry(n, k)
    return write_composite_witnesses(
        cached.instance,
        cached.cycle,
        cached.threshold,
        variant,
        k,
        destination,
        tree_cache=cached.tree_cache,
    )


def _install_circuit(workspace: Path, manifest: Path, source: str) -> None:
    (workspace / "src").mkdir(exist_ok=True)
    shutil.copyfile(manifest, workspace / "Nargo.toml")
    (workspace / "src" / "main.nr").write_text(source)


def prepare_composite_workspace(
    variant: str,
    n: int,
    k: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
    cache_dir: Path = DEFAULT_CACHE_ROOT,
) -> Path:
    composite_for(variant)
    validate_geometry(n, k)
    output = output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"output destination is not empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    cached = InstanceCache(cache_dir).load_or_create(n, seed)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        populate_composite_workspace(staging, variant, cached, k, seed)
        if output.exists():
            output.rmdir()
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output


@contextmanager
def temporary_composite_workspace(
    variant: str,
    cached: CachedInstance,
    k: int,
    *,
    seed: int = DEFAULT_SEED,
) -> Iterator[Path]:
    n = int(cached.instance["metadata"]["n"])
    with tempfile.TemporaryDirectory(
        prefix=f"zk-tsp-composite-{variant}-n{n}-k{k}-"
    ) as tmp:
        destination = Path(tmp) / "workspace"
        populate_composite_workspace(destination, variant, cached, k, seed)
        yield destination
