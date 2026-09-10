from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from zk_tsp.cache import CachedInstance, InstanceCache
from zk_tsp.composite import composite_for, populate_composite_workspace
from zk_tsp.composite_benchmark import _compile_proof_set, _prove_isolated
from zk_tsp.external_verify import (
    VerificationError,
    cross_check,
    parse_glue_public,
    parse_public_inputs,
    parse_segment_public,
    verify_composite_workspace,
)


class PublicInputParsingTests(unittest.TestCase):
    def test_big_endian_field_parsing_and_shape_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "public_inputs"
            values = [0, 1, 2**64 + 7]
            path.write_bytes(b"".join(value.to_bytes(32, "big") for value in values))
            self.assertEqual(parse_public_inputs(path), values)
            path.write_bytes(b"malformed")
            with self.assertRaises(VerificationError):
                parse_public_inputs(path)

        with self.assertRaises(VerificationError):
            parse_segment_public("plain-sort", [0] * 7, 4)
        with self.assertRaises(VerificationError):
            parse_segment_public("plain-product", [0] * 8, 4)
        with self.assertRaises(VerificationError):
            parse_segment_public("committed-sort", [0] * 3, 4)
        with self.assertRaises(VerificationError):
            parse_segment_public("committed-product", [0] * 2, 4)
        with self.assertRaises(VerificationError):
            parse_glue_public("plain-sort", [0] * 15, 8, 2)
        with self.assertRaises(VerificationError):
            parse_glue_public("plain-product", [0] * 15, 8, 2)
        with self.assertRaises(VerificationError):
            parse_glue_public("committed-sort", [0] * 5, 8, 2)
        with self.assertRaises(VerificationError):
            parse_glue_public("committed-product", [0] * 4, 8, 2)

    def test_statement_and_per_segment_reconciliation(self) -> None:
        segments = [
            {
                "sorted_nodes": [0, 1, 2, 3],
                "start": 0,
                "end": 3,
                "partial_cost": 10,
                "root": 99,
            },
            {
                "sorted_nodes": [4, 5, 6, 7],
                "start": 4,
                "end": 7,
                "partial_cost": 20,
                "root": 99,
            },
        ]
        glue = {
            "sorted_nodes": list(range(8)),
            "starts": [0, 4],
            "ends": [3, 7],
            "partial_costs": [10, 20],
            "threshold": 40,
            "root": 99,
        }
        self.assertEqual(
            cross_check(
                "plain-sort",
                segments,
                glue,
                n=8,
                k=2,
                expected_root=99,
                expected_threshold=40,
            ),
            [],
        )
        glue["partial_costs"][1] += 1
        glue["threshold"] += 1
        errors = cross_check(
            "plain-sort",
            segments,
            glue,
            n=8,
            k=2,
            expected_root=99,
            expected_threshold=40,
        )
        self.assertTrue(any("partial-cost" in error for error in errors))
        self.assertTrue(any("threshold" in error for error in errors))


class CompositeProofSetVerificationTests(unittest.TestCase):
    def test_valid_sets_pass_and_individually_valid_mixed_sets_fail(self) -> None:
        for variant in (
            "plain-sort",
            "plain-product",
            "committed-sort",
            "committed-product",
        ):
            with self.subTest(variant=variant):
                self._check_variant(variant)

    def _check_variant(self, variant: str) -> None:
        with tempfile.TemporaryDirectory(
            prefix=f"zk-tsp-{variant}-proof-reconciliation-"
        ) as tmp:
            root = Path(tmp)
            cached = InstanceCache(root / "cache").load_or_create(8, 42)
            rotated_cycle = cached.cycle[1:] + cached.cycle[:1]
            rotated = CachedInstance(
                cached.directory,
                cached.instance,
                rotated_cycle,
                cached.cost,
                cached.threshold,
            )
            workspace_a = root / "a"
            workspace_b = root / "b"
            populate_composite_workspace(workspace_a, variant, cached, 2, 42)
            alternate = cached if variant.startswith("committed-") else rotated
            populate_composite_workspace(workspace_b, variant, alternate, 2, 42)
            spec = composite_for(variant)
            for workspace in (workspace_a, workspace_b):
                _compile_proof_set(
                    workspace, spec.segment_package, spec.glue_package, 2
                )
                _prove_isolated(
                    workspace, spec.segment_package, spec.glue_package, 2
                )
                report = verify_composite_workspace(workspace)
                self.assertEqual(report.proofs, 3)

            source = workspace_b / "glue" / "target" / "proof"
            destination = workspace_a / "glue" / "target" / "proof"
            for filename in ("proof", "public_inputs"):
                shutil.copyfile(source / filename, destination / filename)
            with self.assertRaisesRegex(
                VerificationError, "external reconciliation failed"
            ):
                verify_composite_workspace(workspace_a)


if __name__ == "__main__":
    unittest.main()
