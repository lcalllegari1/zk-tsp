from __future__ import annotations

import copy
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any

from zk_tsp.cache import CachedInstance
from zk_tsp.domain import cycle_cost, threshold_for
from zk_tsp.merkle import write_merkle_witness
from zk_tsp.workspace import temporary_committed_workspace


def reference_instance(n: int, *, offset: int = 0) -> dict[str, Any]:
    matrix = [
        [
            0 if i == j else (abs(i - j) + 1) * 100 + i * 7 + j + offset
            for j in range(n)
        ]
        for i in range(n)
    ]
    return {
        "metadata": {"n": n, "grid_size": 0, "precision": 1, "seed": 0},
        "nodes": [[float(i), 0.0] for i in range(n)],
        "matrix": matrix,
    }


def write_committed_toml(witness: dict[str, Any], path: Path) -> None:
    def quoted(values: list[Any]) -> str:
        return ", ".join(f'"{value}"' for value in values)

    bits = ", ".join("true" if value else "false" for value in witness["path_bits"])
    lines = [
        f"cycle = [{quoted(witness['cycle'])}]",
        f"edge_costs = [{quoted(witness['edge_costs'])}]",
        f"siblings = [{quoted(witness['siblings'])}]",
        f"path_bits = [{bits}]",
        f'root = "{witness["root"]}"',
        f'threshold = "{witness["threshold"]}"',
    ]
    path.write_text("\n".join(lines) + "\n")


def execute(workspace: Path, witness: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    write_committed_toml(witness, workspace / "Prover.toml")
    return subprocess.run(
        ["nargo", "execute"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )


class CommittedCircuitCorrectnessTests(unittest.TestCase):
    def test_sort_and_product_accept_valid_routes_and_reject_adversarial_witnesses(self) -> None:
        cases = {"sort": (2, 3, 5), "product": (2, 4, 6)}
        for mechanism, sizes in cases.items():
            for n in sizes:
                with self.subTest(mechanism=mechanism, n=n):
                    self._check_mechanism(mechanism, n)

    def _check_mechanism(self, mechanism: str, n: int) -> None:
        instance = reference_instance(n)
        cycle = list(range(n))
        cost = cycle_cost(instance["matrix"], cycle)
        threshold = threshold_for(cost)
        with tempfile.TemporaryDirectory(
            prefix=f"zk-tsp-{mechanism}-correctness-"
        ) as tmp:
            root = Path(tmp)
            cache_directory = root / "cache"
            cache_directory.mkdir()
            cached = CachedInstance(cache_directory, instance, cycle, cost, threshold)
            with temporary_committed_workspace(
                mechanism, cached, seed=0
            ) as workspace:
                subprocess.run(
                    ["nargo", "compile"],
                    cwd=workspace,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                baseline = tomllib.loads((workspace / "Prover.toml").read_text())
                self.assertEqual(execute(workspace, baseline).returncode, 0)

                rotated_path = root / "rotated.toml"
                rotated = cycle[1:] + cycle[:1]
                write_merkle_witness(
                    instance,
                    rotated,
                    threshold,
                    rotated_path,
                    tree_cache=cached.tree_cache,
                )
                self.assertEqual(
                    execute(workspace, tomllib.loads(rotated_path.read_text())).returncode,
                    0,
                )

                tight = copy.deepcopy(baseline)
                tight["threshold"] = str(cost)
                self.assertEqual(execute(workspace, tight).returncode, 0)

                duplicate_path = root / "duplicate.toml"
                duplicate_cycle = cycle.copy()
                duplicate_cycle[-1] = duplicate_cycle[0]
                write_merkle_witness(
                    instance,
                    duplicate_cycle,
                    threshold,
                    duplicate_path,
                    tree_cache=cached.tree_cache,
                )
                self.assertNotEqual(
                    execute(
                        workspace, tomllib.loads(duplicate_path.read_text())
                    ).returncode,
                    0,
                )

                invalid_cases = []
                out_of_range = copy.deepcopy(baseline)
                out_of_range["cycle"][-1] = str(n)
                invalid_cases.append(out_of_range)

                insufficient = copy.deepcopy(baseline)
                insufficient["threshold"] = str(cost - 1)
                invalid_cases.append(insufficient)

                wrong_path = copy.deepcopy(baseline)
                wrong_path["path_bits"][0] = not wrong_path["path_bits"][0]
                invalid_cases.append(wrong_path)

                wrong_sibling = copy.deepcopy(baseline)
                wrong_sibling["siblings"][0] = "0x" + format(
                    int(wrong_sibling["siblings"][0], 16) + 1, "064x"
                )
                invalid_cases.append(wrong_sibling)

                wrong_cost = copy.deepcopy(baseline)
                wrong_cost["edge_costs"][0] = str(int(wrong_cost["edge_costs"][0]) + 1)
                invalid_cases.append(wrong_cost)

                other_matrix_path = root / "other-matrix.toml"
                write_merkle_witness(
                    reference_instance(n, offset=17),
                    cycle,
                    threshold,
                    other_matrix_path,
                    tree_cache=root / "other-tree.bin",
                )
                wrong_root = copy.deepcopy(baseline)
                wrong_root["root"] = tomllib.loads(
                    other_matrix_path.read_text()
                )["root"]
                invalid_cases.append(wrong_root)

                for index, witness in enumerate(invalid_cases):
                    with self.subTest(adversarial_case=index):
                        self.assertNotEqual(execute(workspace, witness).returncode, 0)


if __name__ == "__main__":
    unittest.main()
