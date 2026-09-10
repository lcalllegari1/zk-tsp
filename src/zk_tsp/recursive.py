from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .backend import CompiledCircuit, compile_circuit, run_command
from .cache import CachedInstance, InstanceCache
from .composite import composite_for, configure_composite_source, validate_geometry
from .domain import DEFAULT_SEED, merkle_depth
from .merkle import write_composite_witnesses
from .workspace import DEFAULT_CACHE_ROOT, PROJECT_ROOT

RECURSIVE_OUTER = PROJECT_ROOT / "circuits" / "composite" / "recursive_product" / "outer"
RECURSIVE_PACKAGE = "composite_recursive"
INNER_PACKAGE = "composite_plain_product_segment"
RECURSIVE_SCHEMA = "zk-tsp.recursive-workspace.v1"
BUILD_SCHEMA = "zk-tsp.recursive-build.v1"
STATEMENT_SCHEMA = "zk-tsp.composite-statement.v1"
VK_FIELD_COUNT = 115
INNER_PROOF_FIELDS = 458
INNER_PUBLIC_FIELDS = 9
OUTER_PROOF_BYTES = 14_656


@dataclass(frozen=True)
class RecursiveSetup:
    inner: CompiledCircuit
    outer: CompiledCircuit
    build_metadata: Path


@dataclass(frozen=True)
class RecursiveComponentMetrics:
    witness_s: float
    prove_s: float
    peak_mb: float


@dataclass(frozen=True)
class RecursiveProofMetrics:
    inner: tuple[RecursiveComponentMetrics, ...]
    outer: RecursiveComponentMetrics
    proof_bytes: int


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def semantic_artifact_sha256(path: Path) -> str:
    artifact = json.loads(path.read_text())
    encoded = json.dumps(
        {
            "bytecode": artifact["bytecode"],
            "parameters": artifact["abi"]["parameters"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def prepare_recursive_workspace(
    n: int,
    k: int,
    output: Path,
    *,
    seed: int = DEFAULT_SEED,
    cache_dir: Path = DEFAULT_CACHE_ROOT,
) -> Path:
    validate_geometry(n, k)
    output = output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"output destination is not empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    cached = InstanceCache(cache_dir).load_or_create(n, seed)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        populate_recursive_workspace(staging, cached, k, seed)
        if output.exists():
            output.rmdir()
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output


def populate_recursive_workspace(
    destination: Path,
    cached: CachedInstance,
    k: int,
    seed: int,
) -> RecursiveSetup:
    n = int(cached.instance["metadata"]["n"])
    m = validate_geometry(n, k)
    depth = merkle_depth(n)
    destination.mkdir(parents=True, exist_ok=True)
    summary = refresh_recursive_witnesses(destination, cached, k)

    segment = composite_for("plain-product")
    inner_source = (segment.segment_path / "src" / "main.nr").read_text()
    configured_inner = configure_composite_source(
        inner_source, N=n, M=m, DEPTH=depth
    )
    inner = destination / "inner"
    _install_circuit(inner, segment.segment_path / "Nargo.toml", configured_inner)
    inner_compiled, vk_fields, key_hash = _compile_inner(inner)

    outer_source = (RECURSIVE_OUTER / "src" / "main.nr").read_text()
    configured_outer = configure_composite_source(
        outer_source, N=n, K=k, DEPTH=depth
    )
    outer = destination / "outer"
    _install_circuit(outer, RECURSIVE_OUTER / "Nargo.toml", configured_outer)
    constants = outer / "src" / "expected_segment_vk.nr"
    write_segment_key_constants(
        constants,
        n=n,
        m=m,
        depth=depth,
        vk_fields=vk_fields,
        key_hash=key_hash,
    )
    outer_compiled = compile_circuit(outer, RECURSIVE_PACKAGE)

    build_metadata = _write_build_metadata(
        destination,
        n=n,
        k=k,
        m=m,
        depth=depth,
        vk_fields=vk_fields,
        key_hash=key_hash,
    )
    build_digest = sha256_file(build_metadata)
    statement = {
        "schema": STATEMENT_SCHEMA,
        "root": summary["root"],
        "threshold": cached.threshold,
    }
    (destination / "statement.json").write_text(
        json.dumps(statement, indent=2, sort_keys=True) + "\n"
    )
    (destination / "instance.json").write_text(
        json.dumps(cached.instance, indent=2) + "\n"
    )
    (destination / "cycle.json").write_text(
        json.dumps(
            {
                "cycle": cached.cycle,
                "cost": cached.cost,
                "threshold": cached.threshold,
            },
            indent=2,
        )
        + "\n"
    )
    metadata = {
        "schema": RECURSIVE_SCHEMA,
        "nodes": n,
        "segments": k,
        "segment_length": m,
        "depth": depth,
        "seed": seed,
        "inner_package": INNER_PACKAGE,
        "outer_package": RECURSIVE_PACKAGE,
        "inner_public_inputs": INNER_PUBLIC_FIELDS,
        "outer_public_inputs": 2,
        "build_metadata_sha256": build_digest,
        "canonical_inner_sha256": hashlib.sha256(inner_source.encode()).hexdigest(),
        "canonical_outer_sha256": hashlib.sha256(outer_source.encode()).hexdigest(),
    }
    (destination / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )
    return RecursiveSetup(inner_compiled, outer_compiled, build_metadata)


def refresh_recursive_witnesses(
    workspace: Path,
    cached: CachedInstance,
    k: int,
) -> dict[str, Any]:
    n = int(cached.instance["metadata"]["n"])
    validate_geometry(n, k)
    return write_composite_witnesses(
        cached.instance,
        cached.cycle,
        cached.threshold,
        "plain-product",
        k,
        workspace / "witnesses",
        tree_cache=cached.tree_cache,
    )


def prove_recursive_workspace(workspace: Path) -> RecursiveProofMetrics:
    return _prove_recursive_workspace(workspace.resolve(), replace=False)


def _prove_recursive_workspace(
    workspace: Path, *, replace: bool
) -> RecursiveProofMetrics:
    metadata = load_recursive_metadata(workspace)
    k = int(metadata["segments"])
    proof_destination = workspace / "proofs"
    if proof_destination.exists():
        if not replace:
            raise FileExistsError(f"recursive proof set already exists: {proof_destination}")
        shutil.rmtree(proof_destination)

    staging = Path(tempfile.mkdtemp(prefix=".proofs-", dir=workspace))
    try:
        segments = []
        inner_metrics = []
        for index in range(k):
            segment, metrics = _prove_inner_segment(workspace, staging, index)
            segments.append(segment)
            inner_metrics.append(metrics)

        outer = workspace / "outer"
        (outer / "Prover.toml").write_text(
            assemble_outer_witness(segments, workspace / "witnesses" / "glue" / "Prover.toml")
        )
        executed = run_command(["nargo", "execute"], cwd=outer)
        artifact = outer / "target" / f"{RECURSIVE_PACKAGE}.json"
        witness = outer / "target" / f"{RECURSIVE_PACKAGE}.gz"
        outer_output = staging / "outer"
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
                str(outer_output),
            ],
            cwd=outer,
        )
        peak = _peak_memory(proved.stderr)
        proof = outer_output / "proof"
        public_inputs = outer_output / "public_inputs"
        if not proof.is_file() or not public_inputs.is_file():
            raise RuntimeError("outer prover did not produce a complete proof set")
        proof_bytes = proof.stat().st_size
        if proof_bytes != OUTER_PROOF_BYTES:
            raise RuntimeError(
                f"outer proof is {proof_bytes} bytes; expected {OUTER_PROOF_BYTES} ZK bytes"
            )
        os.replace(staging, proof_destination)
        return RecursiveProofMetrics(
            tuple(inner_metrics),
            RecursiveComponentMetrics(executed.elapsed_s, proved.elapsed_s, peak),
            proof_bytes,
        )
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def assemble_outer_witness(
    segments: list[dict[str, list[str]]], glue_path: Path
) -> str:
    if not segments:
        raise ValueError("at least one inner proof is required")
    glue = tomllib.loads(glue_path.read_text())
    starts = [int(segment["public_inputs"][0], 16) for segment in segments]
    ends = [int(segment["public_inputs"][1], 16) for segment in segments]
    partial_costs = [int(segment["public_inputs"][2], 16) for segment in segments]
    root = segments[0]["public_inputs"][3]
    values = {
        "proofs": [segment["proof"] for segment in segments],
        "sub_pubs": [segment["public_inputs"] for segment in segments],
        "boundary_costs": glue["boundary_costs"],
        "boundary_siblings": glue["boundary_siblings"],
        "boundary_path_bits": glue["boundary_path_bits"],
        "starts": starts,
        "ends": ends,
        "partial_costs": partial_costs,
        "root": root,
        "threshold": int(glue["threshold"]),
    }
    return "".join(f"{name} = {_toml(value)}\n" for name, value in values.items())


def write_segment_key_constants(
    path: Path,
    *,
    n: int,
    m: int,
    depth: int,
    vk_fields: list[str],
    key_hash: str,
) -> None:
    if len(vk_fields) != VK_FIELD_COUNT:
        raise ValueError(f"expected {VK_FIELD_COUNT} VK fields, got {len(vk_fields)}")
    field_pattern = re.compile(r"0x[0-9a-f]{64}")
    if any(field_pattern.fullmatch(value) is None for value in [*vk_fields, key_hash]):
        raise ValueError("verification-key values must be 32-byte lowercase field literals")
    rows = [
        "    " + ", ".join(vk_fields[offset : offset + 4]) + ","
        for offset in range(0, len(vk_fields), 4)
    ]
    source = (
        f"pub global EXPECTED_SEGMENT_N: u32 = {n};\n"
        f"pub global EXPECTED_SEGMENT_M: u32 = {m};\n"
        f"pub global EXPECTED_SEGMENT_DEPTH: u32 = {depth};\n"
        "pub global EXPECTED_SEGMENT_VK: [Field; 115] = [\n"
        + "\n".join(rows)
        + "\n];\n"
        f"pub global EXPECTED_SEGMENT_KEY_HASH: Field = {key_hash};\n"
    )
    path.write_text(source)


def load_recursive_metadata(workspace: Path) -> dict[str, Any]:
    try:
        metadata = json.loads((workspace / "metadata.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid recursive workspace metadata") from exc
    if metadata.get("schema") != RECURSIVE_SCHEMA:
        raise ValueError("unsupported recursive workspace schema")
    try:
        n = int(metadata["nodes"])
        k = int(metadata["segments"])
        m = int(metadata["segment_length"])
        depth = int(metadata["depth"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid recursive workspace geometry") from exc
    if validate_geometry(n, k) != m or merkle_depth(n) != depth:
        raise ValueError("recursive workspace geometry is inconsistent")
    if (
        metadata.get("inner_package") != INNER_PACKAGE
        or metadata.get("outer_package") != RECURSIVE_PACKAGE
    ):
        raise ValueError("recursive workspace package metadata is inconsistent")
    return metadata


@contextmanager
def temporary_recursive_workspace(
    cached: CachedInstance,
    k: int,
    *,
    seed: int = DEFAULT_SEED,
) -> Iterator[tuple[Path, RecursiveSetup]]:
    n = int(cached.instance["metadata"]["n"])
    with tempfile.TemporaryDirectory(prefix=f"zk-tsp-recursive-n{n}-k{k}-") as tmp:
        workspace = Path(tmp) / "workspace"
        setup = populate_recursive_workspace(workspace, cached, k, seed)
        yield workspace, setup


def _compile_inner(
    inner: Path,
) -> tuple[CompiledCircuit, list[str], str]:
    compiled = run_command(["nargo", "compile"], cwd=inner)
    artifact = inner / "target" / f"{INNER_PACKAGE}.json"
    run_command(
        [
            "bb",
            "write_vk",
            "-b",
            str(artifact),
            "-t",
            "noir-recursive",
            "-o",
            "target/recursive_vk",
        ],
        cwd=inner,
    )
    run_command(
        [
            "bb",
            "write_vk",
            "-b",
            str(artifact),
            "-t",
            "noir-recursive",
            "--output_format",
            "json",
            "-o",
            "target/recursive_vk_json",
        ],
        cwd=inner,
    )
    gates = json.loads(run_command(["bb", "gates", "-b", str(artifact)], cwd=inner).stdout)[
        "functions"
    ][0]
    vk = json.loads((inner / "target" / "recursive_vk_json" / "vk.json").read_text())
    fields = vk.get("vk")
    key_hash = vk.get("hash")
    if not isinstance(fields, list) or not isinstance(key_hash, str):
        raise RuntimeError("recursive verification-key JSON has an invalid shape")
    return (
        CompiledCircuit(
            compiled.elapsed_s,
            int(gates["acir_opcodes"]),
            int(gates["circuit_size"]),
        ),
        fields,
        key_hash,
    )


def _write_build_metadata(
    workspace: Path,
    *,
    n: int,
    k: int,
    m: int,
    depth: int,
    vk_fields: list[str],
    key_hash: str,
) -> Path:
    inner_artifact = workspace / "inner" / "target" / f"{INNER_PACKAGE}.json"
    inner_vk = workspace / "inner" / "target" / "recursive_vk" / "vk"
    constants = workspace / "outer" / "src" / "expected_segment_vk.nr"
    outer_artifact = workspace / "outer" / "target" / f"{RECURSIVE_PACKAGE}.json"
    outer_vk = workspace / "outer" / "target" / "vk" / "vk"
    metadata = {
        "schema": BUILD_SCHEMA,
        "parameters": {"n": n, "k": k, "m": m, "depth": depth},
        "segment": {
            "circuit": INNER_PACKAGE,
            "artifact_sha256": sha256_file(inner_artifact),
            "executable_sha256": semantic_artifact_sha256(inner_artifact),
            "verification_key_sha256": sha256_file(inner_vk),
            "verification_key_fields": vk_fields,
            "key_hash": key_hash,
        },
        "generated_constants": {"sha256": sha256_file(constants)},
        "outer": {
            "circuit": RECURSIVE_PACKAGE,
            "artifact_sha256": sha256_file(outer_artifact),
            "executable_sha256": semantic_artifact_sha256(outer_artifact),
            "verification_key_sha256": sha256_file(outer_vk),
        },
    }
    path = workspace / "build-metadata.json"
    path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return path


def _prove_inner_segment(
    workspace: Path,
    staging: Path,
    index: int,
) -> tuple[dict[str, list[str]], RecursiveComponentMetrics]:
    inner = workspace / "inner"
    shutil.copyfile(
        workspace / "witnesses" / f"sub_{index}" / "Prover.toml",
        inner / "Prover.toml",
    )
    executed = run_command(["nargo", "execute"], cwd=inner)
    output = staging / "inner" / f"sub_{index}"
    output.mkdir(parents=True)
    proved = run_command(
        [
            "bb",
            "prove",
            "-b",
            f"target/{INNER_PACKAGE}.json",
            "-w",
            f"target/{INNER_PACKAGE}.gz",
            "-k",
            "target/recursive_vk/vk",
            "-t",
            "noir-recursive",
            "--output_format",
            "json",
            "--verify",
            "-o",
            str(output),
        ],
        cwd=inner,
    )
    proof = json.loads((output / "proof.json").read_text()).get("proof")
    public_inputs = json.loads((output / "public_inputs.json").read_text()).get(
        "public_inputs"
    )
    if not isinstance(proof, list) or len(proof) != INNER_PROOF_FIELDS:
        raise RuntimeError(
            f"sub_{index} produced {len(proof) if isinstance(proof, list) else 'invalid'} "
            f"proof fields; expected {INNER_PROOF_FIELDS}"
        )
    if not isinstance(public_inputs, list) or len(public_inputs) != INNER_PUBLIC_FIELDS:
        raise RuntimeError(
            f"sub_{index} produced an invalid public-input vector; "
            f"expected {INNER_PUBLIC_FIELDS} fields"
        )
    return (
        {"proof": proof, "public_inputs": public_inputs},
        RecursiveComponentMetrics(
            executed.elapsed_s, proved.elapsed_s, _peak_memory(proved.stderr)
        ),
    )


def _peak_memory(stderr: str) -> float:
    values = [float(value) for value in re.findall(r"mem: ([\d.]+) MiB", stderr)]
    if not values:
        raise RuntimeError("Barretenberg did not report a memory checkpoint")
    return max(values)


def _install_circuit(workspace: Path, manifest: Path, source: str) -> None:
    (workspace / "src").mkdir(parents=True)
    shutil.copyfile(manifest, workspace / "Nargo.toml")
    (workspace / "src" / "main.nr").write_text(source)


def _toml(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    return f'"{value}"'
