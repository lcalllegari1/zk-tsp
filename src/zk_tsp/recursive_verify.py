from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .backend import CommandError, run_command
from .external_verify import parse_public_inputs
from .recursive import (
    BUILD_SCHEMA,
    INNER_PACKAGE,
    OUTER_PROOF_BYTES,
    RECURSIVE_PACKAGE,
    STATEMENT_SCHEMA,
    VK_FIELD_COUNT,
    load_recursive_metadata,
    semantic_artifact_sha256,
    sha256_file,
)


class RecursiveVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class RecursiveVerificationReport:
    nodes: int
    segments: int
    proofs: int
    public_inputs: int
    trust_mode: str
    build_metadata: str
    backend_elapsed_s: float


def verify_recursive_workspace(
    workspace: Path,
    build_metadata: Path | None = None,
) -> RecursiveVerificationReport:
    workspace = workspace.resolve()
    try:
        metadata = load_recursive_metadata(workspace)
        statement = json.loads((workspace / "statement.json").read_text())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RecursiveVerificationError("invalid recursive workspace") from exc
    if statement.get("schema") != STATEMENT_SCHEMA:
        raise RecursiveVerificationError("unsupported recursive statement schema")
    try:
        expected_root = int(statement["root"], 0)
        expected_threshold = int(statement["threshold"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RecursiveVerificationError("invalid recursive statement") from exc

    default_metadata = (workspace / "build-metadata.json").resolve()
    selected_metadata = (
        default_metadata if build_metadata is None else build_metadata.resolve()
    )
    trust_mode = (
        "workspace-local" if selected_metadata == default_metadata else "explicit"
    )
    try:
        build = json.loads(selected_metadata.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RecursiveVerificationError("cannot read recursive build metadata") from exc
    try:
        _validate_build_metadata(workspace, metadata, build, selected_metadata)
    except OSError as exc:
        raise RecursiveVerificationError(
            "cannot validate recursive build metadata"
        ) from exc

    proof_directory = workspace / "proofs" / "outer"
    proof = proof_directory / "proof"
    public_inputs_path = proof_directory / "public_inputs"
    try:
        proof_bytes = proof.stat().st_size
    except OSError as exc:
        raise RecursiveVerificationError("cannot read recursive outer proof") from exc
    if proof_bytes != OUTER_PROOF_BYTES:
        raise RecursiveVerificationError(
            f"outer proof contains {proof_bytes} bytes; expected {OUTER_PROOF_BYTES} ZK bytes"
        )
    try:
        public_inputs = parse_public_inputs(public_inputs_path)
    except Exception as exc:
        raise RecursiveVerificationError("cannot parse recursive public inputs") from exc
    if len(public_inputs) != 2:
        raise RecursiveVerificationError(
            f"recursive outer proof has {len(public_inputs)} public inputs; expected 2"
        )
    if public_inputs[0] != expected_root:
        raise RecursiveVerificationError("outer root does not match the intended statement")
    if public_inputs[1] != expected_threshold:
        raise RecursiveVerificationError(
            "outer threshold does not match the intended statement"
        )

    outer_vk = workspace / "outer" / "target" / "vk" / "vk"
    started = time.perf_counter()
    try:
        run_command(
            [
                "bb",
                "verify",
                "-k",
                str(outer_vk),
                "-p",
                str(proof),
                "-i",
                str(public_inputs_path),
            ]
        )
    except (CommandError, FileNotFoundError) as exc:
        raise RecursiveVerificationError("backend verification failed for outer") from exc
    return RecursiveVerificationReport(
        nodes=int(metadata["nodes"]),
        segments=int(metadata["segments"]),
        proofs=1,
        public_inputs=2,
        trust_mode=trust_mode,
        build_metadata=str(selected_metadata),
        backend_elapsed_s=time.perf_counter() - started,
    )


def _validate_build_metadata(
    workspace: Path,
    workspace_metadata: dict[str, Any],
    build: dict[str, Any],
    build_path: Path,
) -> None:
    if build.get("schema") != BUILD_SCHEMA:
        raise RecursiveVerificationError("unsupported recursive build-metadata schema")
    expected_parameters = {
        "n": int(workspace_metadata["nodes"]),
        "k": int(workspace_metadata["segments"]),
        "m": int(workspace_metadata["segment_length"]),
        "depth": int(workspace_metadata["depth"]),
    }
    if build.get("parameters") != expected_parameters:
        raise RecursiveVerificationError("build metadata uses different parameters")
    if sha256_file(build_path) != workspace_metadata.get("build_metadata_sha256"):
        raise RecursiveVerificationError("workspace references different build metadata")

    segment = build.get("segment", {})
    outer = build.get("outer", {})
    constants = build.get("generated_constants", {})
    fields = segment.get("verification_key_fields")
    key_hash = segment.get("key_hash")
    field_pattern = re.compile(r"0x[0-9a-f]{64}")
    if segment.get("circuit") != INNER_PACKAGE:
        raise RecursiveVerificationError("build metadata names the wrong inner circuit")
    if outer.get("circuit") != RECURSIVE_PACKAGE:
        raise RecursiveVerificationError("build metadata names the wrong outer circuit")
    if (
        not isinstance(fields, list)
        or len(fields) != VK_FIELD_COUNT
        or any(
            not isinstance(value, str) or field_pattern.fullmatch(value) is None
            for value in fields
        )
        or not isinstance(key_hash, str)
        or field_pattern.fullmatch(key_hash) is None
    ):
        raise RecursiveVerificationError("build metadata has an invalid inner key")

    inner_artifact = workspace / "inner" / "target" / f"{INNER_PACKAGE}.json"
    inner_vk = workspace / "inner" / "target" / "recursive_vk" / "vk"
    constants_path = workspace / "outer" / "src" / "expected_segment_vk.nr"
    outer_artifact = workspace / "outer" / "target" / f"{RECURSIVE_PACKAGE}.json"
    outer_vk = workspace / "outer" / "target" / "vk" / "vk"
    checks = (
        ("inner artifact", sha256_file(inner_artifact), segment.get("artifact_sha256")),
        (
            "inner executable",
            semantic_artifact_sha256(inner_artifact),
            segment.get("executable_sha256"),
        ),
        ("inner verification key", sha256_file(inner_vk), segment.get("verification_key_sha256")),
        ("generated constants", sha256_file(constants_path), constants.get("sha256")),
        ("outer artifact", sha256_file(outer_artifact), outer.get("artifact_sha256")),
        (
            "outer executable",
            semantic_artifact_sha256(outer_artifact),
            outer.get("executable_sha256"),
        ),
        ("outer verification key", sha256_file(outer_vk), outer.get("verification_key_sha256")),
    )
    for label, actual, expected in checks:
        if not expected or actual != expected:
            raise RecursiveVerificationError(f"{label} does not match build metadata")
