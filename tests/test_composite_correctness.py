from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any

from zk_tsp.cache import CachedInstance
from zk_tsp.composite import populate_composite_workspace
from zk_tsp.domain import cycle_cost, threshold_for


def reference_instance(n: int) -> dict[str, Any]:
    matrix = [
        [0 if row == column else (abs(row - column) + 1) * 100 + row * 7 + column
         for column in range(n)]
        for row in range(n)
    ]
    return {
        "metadata": {"n": n, "grid_size": 0, "precision": 1, "seed": 0},
        "nodes": [[float(index), 0.0] for index in range(n)],
        "matrix": matrix,
    }


def write_toml(values: dict[str, Any], path: Path) -> None:
    def encode(value: Any) -> str:
        if isinstance(value, list):
            return "[" + ", ".join(encode(item) for item in value) + "]"
        if isinstance(value, bool):
            return "true" if value else "false"
        return f'"{value}"'

    path.write_text(
        "".join(f"{name} = {encode(value)}\n" for name, value in values.items())
    )


def execute(workspace: Path, witness: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    write_toml(witness, workspace / "Prover.toml")
    return subprocess.run(
        ["nargo", "execute"], cwd=workspace, capture_output=True, text=True
    )


def increment_field(value: str) -> str:
    return "0x" + format(int(value, 16) + 1, "064x")


class CompositeCircuitCorrectnessTests(unittest.TestCase):
    def test_both_variants_accept_valid_alternate_geometry(self) -> None:
        for variant in ("plain-sort", "plain-product"):
            with self.subTest(variant=variant):
                with self._workspace(variant, 6, 2) as workspace:
                    for circuit in ("sub_0", "sub_1", "glue"):
                        witness = tomllib.loads(
                            (workspace / circuit / "Prover.toml").read_text()
                        )
                        self.assertEqual(execute(workspace / circuit, witness).returncode, 0)

    def test_local_constraints_and_global_coverage_reject_tampering(self) -> None:
        for variant in ("plain-sort", "plain-product"):
            with self.subTest(variant=variant):
                self._check_adversarial_witnesses(variant)

    def _check_adversarial_witnesses(self, variant: str) -> None:
        with self._workspace(variant, 8, 2) as workspace:
            segment_path = workspace / "sub_0"
            glue_path = workspace / "glue"
            segment = tomllib.loads((segment_path / "Prover.toml").read_text())
            glue = tomllib.loads((glue_path / "Prover.toml").read_text())
            self.assertEqual(execute(segment_path, segment).returncode, 0)
            self.assertEqual(execute(glue_path, glue).returncode, 0)

            segment_cases = []
            out_of_range = copy.deepcopy(segment)
            out_of_range["cycle_segment"][0] = "8"
            segment_cases.append(out_of_range)
            wrong_cost = copy.deepcopy(segment)
            wrong_cost["edge_costs"][0] = str(int(wrong_cost["edge_costs"][0]) + 1)
            segment_cases.append(wrong_cost)
            wrong_sibling = copy.deepcopy(segment)
            wrong_sibling["siblings"][0] = increment_field(wrong_sibling["siblings"][0])
            segment_cases.append(wrong_sibling)
            wrong_path = copy.deepcopy(segment)
            wrong_path["path_bits"][0] = not wrong_path["path_bits"][0]
            segment_cases.append(wrong_path)
            wrong_partial = copy.deepcopy(segment)
            wrong_partial["partial_cost"] = str(int(wrong_partial["partial_cost"]) + 1)
            segment_cases.append(wrong_partial)
            wrong_root = copy.deepcopy(segment)
            wrong_root["root"] = increment_field(wrong_root["root"])
            segment_cases.append(wrong_root)
            wrong_endpoint = copy.deepcopy(segment)
            wrong_endpoint["start_node"] = str(
                (int(wrong_endpoint["start_node"]) + 1) % 8
            )
            segment_cases.append(wrong_endpoint)
            if variant == "plain-product":
                for field in ("P_i", "h_out_i", "c", "X"):
                    altered = copy.deepcopy(segment)
                    altered[field] = increment_field(altered[field])
                    segment_cases.append(altered)

            for index, altered in enumerate(segment_cases):
                with self.subTest(variant=variant, circuit="segment", case=index):
                    self.assertNotEqual(execute(segment_path, altered).returncode, 0)

            glue_cases = []
            wrong_boundary_cost = copy.deepcopy(glue)
            wrong_boundary_cost["boundary_costs"][0] = str(
                int(wrong_boundary_cost["boundary_costs"][0]) + 1
            )
            glue_cases.append(wrong_boundary_cost)
            wrong_boundary_sibling = copy.deepcopy(glue)
            wrong_boundary_sibling["boundary_siblings"][0] = increment_field(
                wrong_boundary_sibling["boundary_siblings"][0]
            )
            glue_cases.append(wrong_boundary_sibling)
            wrong_boundary_path = copy.deepcopy(glue)
            wrong_boundary_path["boundary_path_bits"][0] = not wrong_boundary_path[
                "boundary_path_bits"
            ][0]
            glue_cases.append(wrong_boundary_path)
            insufficient = copy.deepcopy(glue)
            insufficient["threshold"] = str(self._cost(workspace) - 1)
            glue_cases.append(insufficient)
            if variant == "plain-sort":
                duplicate_summary = copy.deepcopy(glue)
                duplicate_summary["all_sorted_nodes"][-1] = duplicate_summary[
                    "all_sorted_nodes"
                ][0]
                glue_cases.append(duplicate_summary)
            else:
                for field in ("P_is", "h_ins", "h_outs"):
                    altered = copy.deepcopy(glue)
                    altered[field][0] = increment_field(altered[field][0])
                    glue_cases.append(altered)
                for field in ("c", "X"):
                    altered = copy.deepcopy(glue)
                    altered[field] = increment_field(altered[field])
                    glue_cases.append(altered)

            for index, altered in enumerate(glue_cases):
                with self.subTest(variant=variant, circuit="glue", case=index):
                    self.assertNotEqual(execute(glue_path, altered).returncode, 0)

        duplicate_cycle = [0, 1, 2, 3, 0, 5, 6, 7]
        with self._workspace(
            variant, 8, 2, cycle=duplicate_cycle, threshold=(1 << 63)
        ) as duplicate_workspace:
            for circuit in ("sub_0", "sub_1"):
                witness = tomllib.loads(
                    (duplicate_workspace / circuit / "Prover.toml").read_text()
                )
                self.assertEqual(
                    execute(duplicate_workspace / circuit, witness).returncode, 0
                )
            glue = tomllib.loads(
                (duplicate_workspace / "glue" / "Prover.toml").read_text()
            )
            self.assertNotEqual(
                execute(duplicate_workspace / "glue", glue).returncode, 0
            )

    def _workspace(
        self,
        variant: str,
        n: int,
        k: int,
        *,
        cycle: list[int] | None = None,
        threshold: int | None = None,
    ):
        return CompositeWorkspace(variant, n, k, cycle=cycle, threshold=threshold)

    @staticmethod
    def _cost(workspace: Path) -> int:
        return int(json.loads((workspace / "cycle.json").read_text())["cost"])


class CompositeWorkspace:
    def __init__(
        self,
        variant: str,
        n: int,
        k: int,
        *,
        cycle: list[int] | None,
        threshold: int | None,
    ) -> None:
        self.variant = variant
        self.n = n
        self.k = k
        self.cycle = cycle or list(range(n))
        self.threshold = threshold
        self.temporary: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> Path:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=f"zk-tsp-composite-{self.variant}-correctness-"
        )
        root = Path(self.temporary.name)
        instance = reference_instance(self.n)
        cost = cycle_cost(instance["matrix"], self.cycle)
        threshold = self.threshold if self.threshold is not None else threshold_for(cost)
        cache = root / "cache"
        cache.mkdir()
        cached = CachedInstance(cache, instance, self.cycle, cost, threshold)
        workspace = root / "workspace"
        populate_composite_workspace(workspace, self.variant, cached, self.k, 0)
        return workspace

    def __exit__(self, *_args: object) -> None:
        assert self.temporary is not None
        self.temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
