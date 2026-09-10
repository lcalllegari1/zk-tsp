from __future__ import annotations

import unittest

from zk_tsp.workspace import PROJECT_ROOT


class RepositoryCleanlinessTests(unittest.TestCase):
    def test_canonical_sources_contain_no_generated_noir_artifacts(self) -> None:
        circuit_root = PROJECT_ROOT / "circuits"
        forbidden = []
        for path in circuit_root.rglob("*"):
            if path.name == "Prover.toml" or path.name == "target":
                forbidden.append(path.relative_to(PROJECT_ROOT).as_posix())
        self.assertEqual(forbidden, [])

    def test_source_tree_contains_no_legacy_comment_dump(self) -> None:
        for source in (PROJECT_ROOT / "circuits").rglob("*.nr"):
            with self.subTest(source=source.relative_to(PROJECT_ROOT)):
                lines = source.read_text().splitlines()
                comment_lines = sum(line.lstrip().startswith("//") for line in lines)
                self.assertLessEqual(comment_lines, 5)


if __name__ == "__main__":
    unittest.main()
