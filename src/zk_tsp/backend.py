from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

EXPECTED_NARGO = "1.0.0-beta.20"
EXPECTED_NOIRC_COMMIT = "b4236c1957d0c26cb65d82adc9e5447b6ff1d629"
EXPECTED_BB = "5.0.0-nightly.20260324"


class CommandError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    elapsed_s: float
    stdout: str
    stderr: str


@dataclass(frozen=True)
class CompiledCircuit:
    compile_s: float
    acir_opcodes: int
    circuit_size: int


@dataclass(frozen=True)
class ProofMetrics:
    witness_s: float
    prove_s: float
    verify_s: float
    proof_bytes: int
    peak_mb: float


def run_command(command: Sequence[str], *, cwd: Path | None = None) -> CommandResult:
    started = time.perf_counter()
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    elapsed = time.perf_counter() - started
    if result.returncode != 0:
        rendered = " ".join(command)
        raise CommandError(
            f"command failed ({result.returncode}): {rendered}\n{result.stderr.strip()}"
        )
    return CommandResult(elapsed, result.stdout, result.stderr)


def toolchain_versions() -> dict[str, str]:
    return {
        "nargo": run_command(["nargo", "--version"]).stdout.strip(),
        "bb": run_command(["bb", "--version"]).stdout.strip(),
        "cargo": run_command(["cargo", "--version"]).stdout.strip(),
    }


def validate_toolchain() -> dict[str, str]:
    versions = toolchain_versions()
    failures = []
    if EXPECTED_NARGO not in versions["nargo"]:
        failures.append(f"expected Nargo {EXPECTED_NARGO}")
    if EXPECTED_NOIRC_COMMIT not in versions["nargo"]:
        failures.append(f"expected noirc commit {EXPECTED_NOIRC_COMMIT}")
    if EXPECTED_BB not in versions["bb"]:
        failures.append(f"expected bb {EXPECTED_BB}")
    if failures:
        raise RuntimeError("toolchain mismatch: " + "; ".join(failures))
    return versions


def compile_circuit(workspace: Path, package: str) -> CompiledCircuit:
    compiled = run_command(["nargo", "compile"], cwd=workspace)
    artifact = workspace / "target" / f"{package}.json"
    run_command(
        ["bb", "write_vk", "-b", str(artifact), "-o", "target/vk"],
        cwd=workspace,
    )
    gates = run_command(["bb", "gates", "-b", str(artifact)], cwd=workspace)
    data = json.loads(gates.stdout)
    function = data["functions"][0]
    return CompiledCircuit(
        compile_s=compiled.elapsed_s,
        acir_opcodes=int(function["acir_opcodes"]),
        circuit_size=int(function["circuit_size"]),
    )


def prove_and_verify(workspace: Path, package: str) -> ProofMetrics:
    artifact = workspace / "target" / f"{package}.json"
    witness = workspace / "target" / f"{package}.gz"
    executed = run_command(["nargo", "execute"], cwd=workspace)
    proved = run_command(
        [
            "bb",
            "prove",
            "-b",
            str(artifact),
            "-w",
            str(witness),
            "-k",
            "target/vk/vk",
            "-o",
            "target/proof",
        ],
        cwd=workspace,
    )
    verified = run_command(
        [
            "bb",
            "verify",
            "-k",
            "target/vk/vk",
            "-p",
            "target/proof/proof",
            "-i",
            "target/proof/public_inputs",
        ],
        cwd=workspace,
    )
    memory_values = [
        float(match)
        for match in re.findall(r"mem: ([\d.]+) MiB", proved.stderr)
    ]
    if not memory_values:
        raise RuntimeError("Barretenberg did not report a memory checkpoint")
    return ProofMetrics(
        witness_s=executed.elapsed_s,
        prove_s=proved.elapsed_s,
        verify_s=verified.elapsed_s,
        proof_bytes=(workspace / "target" / "proof" / "proof").stat().st_size,
        peak_mb=max(memory_values),
    )
