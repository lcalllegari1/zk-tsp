from __future__ import annotations

import math
from typing import Any, Sequence

import numpy as np

DEFAULT_SEED = 42
GRID_SIZE = 1000
PRECISION = 1000
TWO_OPT_MAX_N = 1000


def generate_instance(
    n: int,
    *,
    seed: int = DEFAULT_SEED,
    grid_size: int = GRID_SIZE,
    precision: int = PRECISION,
) -> dict[str, Any]:
    if n < 1:
        raise ValueError("nodes must be at least 1")

    # RandomState preserves the MT19937 sequence used by the thesis experiments
    # without modifying NumPy's process-global RNG.
    rng = np.random.RandomState(seed)
    nodes = rng.uniform(0, grid_size, size=(n, 2))
    diff = nodes[:, np.newaxis, :] - nodes[np.newaxis, :, :]
    distances = np.sqrt(np.sum(diff**2, axis=-1))
    matrix = np.floor(distances * precision).astype(int)
    return {
        "metadata": {
            "n": n,
            "grid_size": grid_size,
            "precision": precision,
            "seed": seed,
        },
        "nodes": nodes.tolist(),
        "matrix": matrix.tolist(),
    }


def nearest_neighbour(matrix: Sequence[Sequence[int]], start: int = 0) -> list[int]:
    n = len(matrix)
    if n < 1:
        raise ValueError("matrix must not be empty")
    if not 0 <= start < n:
        raise ValueError("start node is out of range")

    visited = [False] * n
    cycle = [start]
    visited[start] = True
    for _ in range(n - 1):
        current = cycle[-1]
        best = min(
            (node for node in range(n) if not visited[node]),
            key=lambda node: matrix[current][node],
        )
        cycle.append(best)
        visited[best] = True
    return cycle


def two_opt(matrix: Sequence[Sequence[int]], cycle: Sequence[int]) -> list[int]:
    route = list(cycle)
    n = len(route)
    improved = True
    while improved:
        improved = False
        for i in range(1, n - 1):
            for j in range(i + 1, n):
                a, b = route[i - 1], route[i]
                c, d = route[j], route[(j + 1) % n]
                delta = (matrix[a][c] + matrix[b][d]) - (
                    matrix[a][b] + matrix[c][d]
                )
                if delta < 0:
                    route[i : j + 1] = reversed(route[i : j + 1])
                    improved = True
    return route


def solve(
    matrix: Sequence[Sequence[int]], *, two_opt_max_n: int = TWO_OPT_MAX_N
) -> list[int]:
    cycle = nearest_neighbour(matrix)
    if len(matrix) <= two_opt_max_n:
        cycle = two_opt(matrix, cycle)
    return cycle


def cycle_cost(matrix: Sequence[Sequence[int]], cycle: Sequence[int]) -> int:
    n = len(cycle)
    if n < 1:
        raise ValueError("cycle must not be empty")
    return sum(matrix[cycle[i]][cycle[(i + 1) % n]] for i in range(n))


def threshold_for(cost: int, multiplier: float = 1.1) -> int:
    if multiplier <= 0:
        raise ValueError("threshold multiplier must be positive")
    return math.ceil(cost * multiplier)


def merkle_depth(n: int) -> int:
    if n < 1:
        raise ValueError("nodes must be at least 1")
    return (n * n - 1).bit_length()


def flatten_matrix(matrix: Sequence[Sequence[int]]) -> list[int]:
    n = len(matrix)
    if n < 1 or any(len(row) != n for row in matrix):
        raise ValueError("matrix must be nonempty and square")
    return [int(matrix[row][column]) for row in range(n) for column in range(n)]


def inverse_permutation(cycle: Sequence[int]) -> list[int]:
    n = len(cycle)
    if sorted(cycle) != list(range(n)):
        raise ValueError("cycle must be a permutation of 0..N-1")
    inverse = [0] * n
    for position, node in enumerate(cycle):
        inverse[node] = position
    return inverse


def make_study_witness(
    instance: dict[str, Any],
    cycle: Sequence[int],
    mechanism: str,
    *,
    multiplier: float = 1.1,
) -> dict[str, Any]:
    matrix = instance["matrix"]
    n = instance["metadata"]["n"]
    if len(cycle) != n:
        raise ValueError("cycle length does not match the instance")
    if mechanism not in {"pairwise", "presence", "inverse", "sort"}:
        raise ValueError(f"unknown study mechanism: {mechanism}")

    cost = cycle_cost(matrix, cycle)
    witness: dict[str, Any] = {
        "cycle": list(cycle),
        "cost_matrix": [matrix[i][j] for i in range(n) for j in range(n)],
        "threshold": threshold_for(cost, multiplier),
        "cost": cost,
    }
    if mechanism == "inverse":
        witness["inv_perm"] = inverse_permutation(cycle)
    return witness
