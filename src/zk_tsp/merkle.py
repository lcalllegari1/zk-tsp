from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Sequence

from .domain import flatten_matrix

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = PROJECT_ROOT / "crates" / "merkle_builder" / "Cargo.toml"
TARGET_DIR = PROJECT_ROOT / "build" / "cargo"
BUILDER = TARGET_DIR / "release" / "merkle_builder"


def ensure_builder() -> Path:
    process = subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            str(MANIFEST),
            "--target-dir",
            str(TARGET_DIR),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(f"cannot build Merkle witness builder:\n{process.stderr.strip()}")
    return BUILDER


def write_merkle_witness(
    instance: dict[str, Any],
    cycle: Sequence[int],
    threshold: int,
    output: Path,
    *,
    tree_cache: Path | None = None,
) -> None:
    n = int(instance["metadata"]["n"])
    payload = {
        "n": n,
        "flat_matrix": flatten_matrix(instance["matrix"]),
        "cycle": list(cycle),
        "threshold": threshold,
    }
    command = [str(ensure_builder()), "--out", str(output)]
    if tree_cache is not None:
        command.extend(("--tree-cache", str(tree_cache)))
    process = subprocess.run(
        command,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(f"Merkle witness construction failed:\n{process.stderr.strip()}")


def write_composite_witnesses(
    instance: dict[str, Any],
    cycle: Sequence[int],
    threshold: int,
    variant: str,
    segments: int,
    output: Path,
    *,
    tree_cache: Path | None = None,
) -> dict[str, Any]:
    n = int(instance["metadata"]["n"])
    payload = {
        "n": n,
        "flat_matrix": flatten_matrix(instance["matrix"]),
        "cycle": list(cycle),
        "threshold": threshold,
    }
    command = [
        str(ensure_builder()),
        "--composite",
        variant,
        "--segments",
        str(segments),
        "--out-dir",
        str(output),
    ]
    if tree_cache is not None:
        command.extend(("--tree-cache", str(tree_cache)))
    process = subprocess.run(
        command,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(f"Composite witness construction failed:\n{process.stderr.strip()}")
    try:
        summary = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Composite witness builder returned invalid summary JSON") from exc
    expected = {
        "variant": variant,
        "n": n,
        "k": segments,
        "m": n // segments,
        "threshold": threshold,
    }
    if any(summary.get(name) != value for name, value in expected.items()):
        raise RuntimeError("Composite witness builder returned inconsistent metadata")
    if not isinstance(summary.get("root"), str) or not summary["root"].startswith(
        "0x"
    ):
        raise RuntimeError("Composite witness builder returned an invalid root")
    return summary
