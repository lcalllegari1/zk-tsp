from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from zk_tsp.merkle import MANIFEST, PROJECT_ROOT, TARGET_DIR


class PoseidonCompatibilityTests(unittest.TestCase):
    def test_rust_and_noir_hashes_match(self) -> None:
        process = subprocess.run(
            [
                "cargo",
                "run",
                "--locked",
                "--quiet",
                "--example",
                "poseidon_vectors",
                "--manifest-path",
                str(MANIFEST),
                "--target-dir",
                str(TARGET_DIR),
            ],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        values = json.loads(process.stdout)
        fixture = PROJECT_ROOT / "tests" / "fixtures" / "poseidon_compat"
        with tempfile.TemporaryDirectory(prefix="zk-tsp-poseidon-") as tmp:
            workspace = Path(tmp) / "circuit"
            shutil.copytree(fixture, workspace)
            lines = [f'{key} = "{value}"' for key, value in values.items()]
            (workspace / "Prover.toml").write_text("\n".join(lines) + "\n")
            subprocess.run(
                ["nargo", "execute"],
                cwd=workspace,
                check=True,
                capture_output=True,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
