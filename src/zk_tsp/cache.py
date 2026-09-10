from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .domain import cycle_cost, generate_instance, solve, threshold_for

CACHE_SCHEMA = "zk-tsp.instance-cache.v1"
SOLVER_POLICY = "nearest-neighbour+2-opt-through-1000.v1"


@dataclass(frozen=True)
class CachedInstance:
    directory: Path
    instance: dict[str, Any]
    cycle: list[int]
    cost: int
    threshold: int

    @property
    def tree_cache(self) -> Path:
        return self.directory / "tree.bin"


class InstanceCache:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def load_or_create(self, n: int, seed: int) -> CachedInstance:
        if n < 1:
            raise ValueError("nodes must be at least 1")
        directory = self.root / f"n{n}_seed{seed}"
        cached = self._load(directory, n, seed)
        if cached is not None:
            return cached

        instance = generate_instance(n, seed=seed)
        cycle = solve(instance["matrix"])
        cost = cycle_cost(instance["matrix"], cycle)
        threshold = threshold_for(cost)
        metadata = {
            "schema": CACHE_SCHEMA,
            "solver_policy": SOLVER_POLICY,
            "nodes": n,
            "seed": seed,
            "cost": cost,
            "threshold": threshold,
            "instance_sha256": _json_sha256(instance),
            "cycle_sha256": _json_sha256(cycle),
        }
        directory.mkdir(parents=True, exist_ok=True)
        _atomic_json(directory / "instance.json", instance)
        _atomic_json(directory / "cycle.json", cycle)
        _atomic_json(directory / "meta.json", metadata)
        return CachedInstance(directory, instance, cycle, cost, threshold)

    def _load(self, directory: Path, n: int, seed: int) -> CachedInstance | None:
        try:
            metadata = json.loads((directory / "meta.json").read_text())
            instance = json.loads((directory / "instance.json").read_text())
            cycle = json.loads((directory / "cycle.json").read_text())
            if metadata.get("schema") != CACHE_SCHEMA:
                return None
            if metadata.get("solver_policy") != SOLVER_POLICY:
                return None
            if metadata.get("nodes") != n or metadata.get("seed") != seed:
                return None
            if _json_sha256(instance) != metadata.get("instance_sha256"):
                return None
            if _json_sha256(cycle) != metadata.get("cycle_sha256"):
                return None
            if instance.get("metadata", {}).get("n") != n:
                return None
            if instance.get("metadata", {}).get("seed") != seed:
                return None
            matrix = instance["matrix"]
            if len(matrix) != n or any(len(row) != n for row in matrix):
                return None
            if not isinstance(cycle, list) or sorted(cycle) != list(range(n)):
                return None
            cost = cycle_cost(matrix, cycle)
            threshold = threshold_for(cost)
            if metadata.get("cost") != cost or metadata.get("threshold") != threshold:
                return None
            return CachedInstance(directory, instance, cycle, cost, threshold)
        except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None


def _json_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
