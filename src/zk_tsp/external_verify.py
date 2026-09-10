from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .backend import CommandError, run_command
from .composite import composite_for, validate_geometry

FIELD_BYTES = 32


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerificationReport:
    variant: str
    nodes: int
    segments: int
    proofs: int
    elapsed_s: float


def parse_public_inputs(path: Path) -> list[int]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"cannot read public inputs: {path}") from exc
    if len(data) % FIELD_BYTES != 0:
        raise VerificationError(
            f"public inputs {path} contain {len(data)} bytes; expected a multiple of 32"
        )
    return [
        int.from_bytes(data[offset : offset + FIELD_BYTES], "big")
        for offset in range(0, len(data), FIELD_BYTES)
    ]


def parse_segment_public(variant: str, values: list[int], m: int) -> dict[str, Any]:
    if variant == "plain-sort":
        expected = m + 4
        if len(values) != expected:
            raise VerificationError(
                f"plain-sort segment has {len(values)} public inputs; expected {expected}"
            )
        return {
            "sorted_nodes": values[:m],
            "start": values[m],
            "end": values[m + 1],
            "partial_cost": values[m + 2],
            "root": values[m + 3],
        }
    if variant == "plain-product":
        if len(values) != 9:
            raise VerificationError(
                f"plain-product segment has {len(values)} public inputs; expected 9"
            )
        return dict(
            zip(
                (
                    "start",
                    "end",
                    "partial_cost",
                    "root",
                    "product",
                    "h_in",
                    "h_out",
                    "c",
                    "x",
                ),
                values,
                strict=True,
            )
        )
    if variant == "committed-sort":
        if len(values) != 2:
            raise VerificationError(
                f"committed-sort segment has {len(values)} public inputs; expected 2"
            )
        return {"root": values[0], "commitment": values[1]}
    if variant == "committed-product":
        if len(values) != 3:
            raise VerificationError(
                f"committed-product segment has {len(values)} public inputs; expected 3"
            )
        return {"root": values[0], "x": values[1], "commitment": values[2]}
    raise VerificationError(f"unknown composite variant: {variant}")


def parse_glue_public(
    variant: str, values: list[int], n: int, k: int
) -> dict[str, Any]:
    if variant == "plain-sort":
        expected = n + 3 * k + 2
        if len(values) != expected:
            raise VerificationError(
                f"plain-sort glue has {len(values)} public inputs; expected {expected}"
            )
        offset = 0
        result = {"sorted_nodes": values[offset : offset + n]}
        offset += n
        for name in ("starts", "ends", "partial_costs"):
            result[name] = values[offset : offset + k]
            offset += k
        result["threshold"] = values[offset]
        result["root"] = values[offset + 1]
        return result
    if variant == "plain-product":
        expected = 6 * k + 4
        if len(values) != expected:
            raise VerificationError(
                f"plain-product glue has {len(values)} public inputs; expected {expected}"
            )
        offset = 0
        result = {}
        for name in ("starts", "ends", "partial_costs"):
            result[name] = values[offset : offset + k]
            offset += k
        result["threshold"] = values[offset]
        result["root"] = values[offset + 1]
        offset += 2
        for name in ("products", "h_ins", "h_outs"):
            result[name] = values[offset : offset + k]
            offset += k
        result["c"] = values[offset]
        result["x"] = values[offset + 1]
        return result
    if variant == "committed-sort":
        expected = k + 2
        if len(values) != expected:
            raise VerificationError(
                f"committed-sort glue has {len(values)} public inputs; expected {expected}"
            )
        return {
            "root": values[0],
            "threshold": values[1],
            "commitments": values[2:],
        }
    if variant == "committed-product":
        expected = k + 3
        if len(values) != expected:
            raise VerificationError(
                f"committed-product glue has {len(values)} public inputs; expected {expected}"
            )
        return {
            "root": values[0],
            "threshold": values[1],
            "x": values[2],
            "commitments": values[3:],
        }
    raise VerificationError(f"unknown composite variant: {variant}")


def cross_check(
    variant: str,
    segments: list[dict[str, Any]],
    glue: dict[str, Any],
    *,
    n: int,
    k: int,
    expected_root: int,
    expected_threshold: int,
) -> list[str]:
    errors = []
    if len(segments) != k:
        errors.append(f"received {len(segments)} segment summaries; expected {k}")
        return errors
    if glue["root"] != expected_root:
        errors.append("glue root does not match the intended statement")
    if glue["threshold"] != expected_threshold:
        errors.append("glue threshold does not match the intended statement")
    for index, segment in enumerate(segments):
        if segment["root"] != expected_root:
            errors.append(f"sub_{index} root does not match the intended statement")

    if variant == "plain-sort":
        _check_plain_summaries(segments, glue, errors)
        m = n // k
        for index, segment in enumerate(segments):
            if glue["sorted_nodes"][index * m : (index + 1) * m] != segment[
                "sorted_nodes"
            ]:
                errors.append(f"sorted-node mismatch at segment {index}")
    elif variant == "plain-product":
        _check_plain_summaries(segments, glue, errors)
        for index, segment in enumerate(segments):
            for glue_name, segment_name in (
                ("products", "product"),
                ("h_ins", "h_in"),
                ("h_outs", "h_out"),
            ):
                if glue[glue_name][index] != segment[segment_name]:
                    errors.append(f"{glue_name} mismatch at segment {index}")
            if segment["c"] != glue["c"]:
                errors.append(f"terminal mismatch at segment {index}")
            if segment["x"] != glue["x"]:
                errors.append(f"challenge mismatch at segment {index}")
    elif variant in {"committed-sort", "committed-product"}:
        for index, segment in enumerate(segments):
            if glue["commitments"][index] != segment["commitment"]:
                errors.append(f"commitment mismatch at segment {index}")
            if variant == "committed-product" and segment["x"] != glue["x"]:
                errors.append(f"challenge mismatch at segment {index}")
    else:
        errors.append(f"unknown composite variant: {variant}")
    return errors


def _check_plain_summaries(
    segments: list[dict[str, Any]], glue: dict[str, Any], errors: list[str]
) -> None:
    for index, segment in enumerate(segments):
        if glue["starts"][index] != segment["start"]:
            errors.append(f"start mismatch at segment {index}")
        if glue["ends"][index] != segment["end"]:
            errors.append(f"end mismatch at segment {index}")
        if glue["partial_costs"][index] != segment["partial_cost"]:
            errors.append(f"partial-cost mismatch at segment {index}")


def verify_composite_workspace(workspace: Path) -> VerificationReport:
    workspace = workspace.resolve()
    try:
        metadata = json.loads((workspace / "metadata.json").read_text())
        statement = json.loads((workspace / "statement.json").read_text())
        variant = metadata["variant"]
        n = int(metadata["nodes"])
        k = int(metadata["segments"])
        m = int(metadata["segment_length"])
        expected_root = int(statement["root"], 0)
        expected_threshold = int(statement["threshold"])
    except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise VerificationError("invalid composite workspace metadata") from exc
    if metadata.get("schema") != "zk-tsp.composite-workspace.v1":
        raise VerificationError("unsupported composite workspace schema")
    try:
        spec = composite_for(variant)
        expected_m = validate_geometry(n, k)
    except ValueError as exc:
        raise VerificationError("workspace variant or geometry is invalid") from exc
    if expected_m != m:
        raise VerificationError("workspace geometry is inconsistent")
    if (
        metadata.get("segment_package") != spec.segment_package
        or metadata.get("glue_package") != spec.glue_package
    ):
        raise VerificationError("workspace package metadata is inconsistent")
    if statement.get("schema") != "zk-tsp.composite-statement.v1":
        raise VerificationError("unsupported composite statement schema")

    segment_key = workspace / "sub_0" / "target" / "vk" / "vk"
    glue_key = workspace / "glue" / "target" / "vk" / "vk"
    started = time.perf_counter()
    proof_directories = [
        workspace / f"sub_{index}" / "target" / "proof" for index in range(k)
    ]
    proof_directories.append(workspace / "glue" / "target" / "proof")
    for index, proof_directory in enumerate(proof_directories):
        key = glue_key if index == k else segment_key
        try:
            run_command(
                [
                    "bb",
                    "verify",
                    "-k",
                    str(key),
                    "-p",
                    str(proof_directory / "proof"),
                    "-i",
                    str(proof_directory / "public_inputs"),
                ]
            )
        except (CommandError, FileNotFoundError) as exc:
            label = "glue" if index == k else f"sub_{index}"
            raise VerificationError(f"backend verification failed for {label}") from exc

    segment_public = [
        parse_segment_public(
            variant,
            parse_public_inputs(
                workspace / f"sub_{index}" / "target" / "proof" / "public_inputs"
            ),
            m,
        )
        for index in range(k)
    ]
    glue_public = parse_glue_public(
        variant,
        parse_public_inputs(workspace / "glue" / "target" / "proof" / "public_inputs"),
        n,
        k,
    )
    errors = cross_check(
        variant,
        segment_public,
        glue_public,
        n=n,
        k=k,
        expected_root=expected_root,
        expected_threshold=expected_threshold,
    )
    if errors:
        raise VerificationError("external reconciliation failed: " + "; ".join(errors))
    return VerificationReport(
        variant=variant,
        nodes=n,
        segments=k,
        proofs=k + 1,
        elapsed_s=time.perf_counter() - started,
    )
