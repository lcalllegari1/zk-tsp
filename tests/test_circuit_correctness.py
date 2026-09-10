from __future__ import annotations

import copy
import subprocess
import unittest

from zk_tsp.domain import generate_instance, make_study_witness, solve
from zk_tsp.workspace import STUDY_CIRCUITS, temporary_workspace, write_prover_toml


def reference_instance(n: int) -> dict:
    matrix = [
        [0 if i == j else (abs(i - j) + 1) * 100 + i * 7 + j for j in range(n)]
        for i in range(n)
    ]
    return {
        "metadata": {"n": n, "grid_size": 0, "precision": 1, "seed": 0},
        "nodes": [[float(i), 0.0] for i in range(n)],
        "matrix": matrix,
    }


def execute(workspace, witness: dict) -> subprocess.CompletedProcess[str]:
    write_prover_toml(witness, workspace / "Prover.toml")
    return subprocess.run(
        ["nargo", "execute"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )


class MechanismCorrectnessTests(unittest.TestCase):
    def test_valid_and_invalid_witnesses(self) -> None:
        for mechanism, circuit in STUDY_CIRCUITS.items():
            for n in (1, 3, 5):
                with self.subTest(mechanism=mechanism, n=n):
                    instance = reference_instance(n)
                    cycle = list(range(n))
                    with temporary_workspace(
                        mechanism, n, instance, cycle, seed=0
                    ) as workspace:
                        subprocess.run(
                            ["nargo", "compile"],
                            cwd=workspace,
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                        baseline = make_study_witness(instance, cycle, mechanism)
                        self.assertEqual(execute(workspace, baseline).returncode, 0)

                        if n > 1:
                            rotated = cycle[1:] + cycle[:1]
                            self.assertEqual(
                                execute(
                                    workspace,
                                    make_study_witness(instance, rotated, mechanism),
                                ).returncode,
                                0,
                            )

                            tight = copy.deepcopy(baseline)
                            tight["threshold"] = tight["cost"]
                            self.assertEqual(execute(workspace, tight).returncode, 0)

                            duplicate = copy.deepcopy(baseline)
                            duplicate["cycle"][-1] = duplicate["cycle"][0]
                            self.assertNotEqual(execute(workspace, duplicate).returncode, 0)

                            out_of_range = copy.deepcopy(baseline)
                            out_of_range["cycle"][-1] = n
                            self.assertNotEqual(
                                execute(workspace, out_of_range).returncode, 0
                            )

                            insufficient = copy.deepcopy(baseline)
                            insufficient["threshold"] = insufficient["cost"] - 1
                            self.assertNotEqual(
                                execute(workspace, insufficient).returncode, 0
                            )

                            altered_cost = copy.deepcopy(baseline)
                            edge_index = cycle[0] * n + cycle[1]
                            altered_cost["cost_matrix"][edge_index] += 1_000_000
                            self.assertNotEqual(
                                execute(workspace, altered_cost).returncode, 0
                            )

                            if mechanism == "inverse":
                                bad_inverse = copy.deepcopy(baseline)
                                bad_inverse["inv_perm"][0] = bad_inverse["inv_perm"][1]
                                self.assertNotEqual(
                                    execute(workspace, bad_inverse).returncode, 0
                                )
                                inverse_out_of_range = copy.deepcopy(baseline)
                                inverse_out_of_range["inv_perm"][0] = n
                                self.assertNotEqual(
                                    execute(workspace, inverse_out_of_range).returncode,
                                    0,
                                )

            generated = generate_instance(5, seed=1)
            generated_cycle = solve(generated["matrix"])
            with self.subTest(mechanism=mechanism, case="generated"):
                with temporary_workspace(
                    mechanism, 5, generated, generated_cycle, seed=1
                ) as workspace:
                    subprocess.run(
                        ["nargo", "compile"],
                        cwd=workspace,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    witness = make_study_witness(
                        generated, generated_cycle, mechanism
                    )
                    self.assertEqual(execute(workspace, witness).returncode, 0)


if __name__ == "__main__":
    unittest.main()
