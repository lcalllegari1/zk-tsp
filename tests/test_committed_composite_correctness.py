from __future__ import annotations

import copy
import json
import tomllib
import unittest
from pathlib import Path
from typing import Any

from tests.test_composite_correctness import (
    CompositeWorkspace,
    execute,
    increment_field,
)


class CommittedCompositeCircuitCorrectnessTests(unittest.TestCase):
    def test_both_variants_accept_valid_alternate_geometry(self) -> None:
        for variant in ("committed-sort", "committed-product"):
            with self.subTest(variant=variant):
                with self._workspace(variant, 6, 2) as workspace:
                    for circuit in ("sub_0", "sub_1", "glue"):
                        witness = self._witness(workspace / circuit)
                        self.assertEqual(
                            execute(workspace / circuit, witness).returncode, 0
                        )

    def test_commitments_local_constraints_and_global_checks_reject_tampering(
        self,
    ) -> None:
        for variant in ("committed-sort", "committed-product"):
            with self.subTest(variant=variant):
                self._check_adversarial_witnesses(variant)

    def _check_adversarial_witnesses(self, variant: str) -> None:
        with self._workspace(variant, 8, 2) as workspace:
            segment_path = workspace / "sub_0"
            glue_path = workspace / "glue"
            segment = self._witness(segment_path)
            glue = self._witness(glue_path)
            self.assertEqual(execute(segment_path, segment).returncode, 0)
            self.assertEqual(execute(glue_path, glue).returncode, 0)

            segment_cases = []
            for field in ("r", "C_i", "root"):
                altered = copy.deepcopy(segment)
                altered[field] = increment_field(altered[field])
                segment_cases.append(altered)
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
            if variant == "committed-product":
                for field in ("h_in_i", "X"):
                    altered = copy.deepcopy(segment)
                    altered[field] = increment_field(altered[field])
                    segment_cases.append(altered)

            for index, altered in enumerate(segment_cases):
                with self.subTest(variant=variant, circuit="segment", case=index):
                    self.assertNotEqual(execute(segment_path, altered).returncode, 0)

            glue_cases = []
            for field in ("root",):
                altered = copy.deepcopy(glue)
                altered[field] = increment_field(altered[field])
                glue_cases.append(altered)
            for field in ("r_is", "C_is", "partial_costs"):
                altered = copy.deepcopy(glue)
                if field == "partial_costs":
                    altered[field][0] = str(int(altered[field][0]) + 1)
                else:
                    altered[field][0] = increment_field(altered[field][0])
                glue_cases.append(altered)
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

            if variant == "committed-sort":
                duplicate_summary = copy.deepcopy(glue)
                duplicate_summary["all_nodes"][-1] = duplicate_summary["all_nodes"][0]
                glue_cases.append(duplicate_summary)
            else:
                for field in ("starts", "ends"):
                    altered = copy.deepcopy(glue)
                    altered[field][0] = str((int(altered[field][0]) + 1) % 8)
                    glue_cases.append(altered)
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
            variant, 8, 2, cycle=duplicate_cycle, threshold=1 << 63
        ) as duplicate_workspace:
            for circuit in ("sub_0", "sub_1"):
                self.assertEqual(
                    execute(
                        duplicate_workspace / circuit,
                        self._witness(duplicate_workspace / circuit),
                    ).returncode,
                    0,
                )
            self.assertNotEqual(
                execute(
                    duplicate_workspace / "glue",
                    self._witness(duplicate_workspace / "glue"),
                ).returncode,
                0,
            )

    @staticmethod
    def _workspace(
        variant: str,
        n: int,
        k: int,
        *,
        cycle: list[int] | None = None,
        threshold: int | None = None,
    ) -> CompositeWorkspace:
        return CompositeWorkspace(variant, n, k, cycle=cycle, threshold=threshold)

    @staticmethod
    def _witness(path: Path) -> dict[str, Any]:
        return tomllib.loads((path / "Prover.toml").read_text())

    @staticmethod
    def _cost(workspace: Path) -> int:
        return int(json.loads((workspace / "cycle.json").read_text())["cost"])


if __name__ == "__main__":
    unittest.main()
