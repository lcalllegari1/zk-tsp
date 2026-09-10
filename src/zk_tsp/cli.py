from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Sequence

from .backend import validate_toolchain
from .benchmark import benchmark_monolithic, benchmark_study
from .composite import COMPOSITE_VARIANTS, prepare_composite_workspace
from .composite_benchmark import benchmark_composite
from .domain import DEFAULT_SEED
from .external_verify import verify_composite_workspace
from .recursive import prepare_recursive_workspace, prove_recursive_workspace
from .recursive_benchmark import benchmark_recursive
from .recursive_verify import verify_recursive_workspace
from .results import reproduce_results, validate_results
from .workspace import (
    COMMITTED_CIRCUITS,
    DEFAULT_CACHE_ROOT,
    STUDY_CIRCUITS,
    prepare_committed_workspace,
    prepare_workspace,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zk-tsp")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("check-toolchain", help="validate the measured build toolchain")

    prepare = commands.add_parser("prepare", help="create a configured circuit workspace")
    prepare_families = prepare.add_subparsers(dest="family", required=True)
    prepare_study = prepare_families.add_parser("study")
    prepare_study.add_argument("--mechanism", choices=sorted(STUDY_CIRCUITS), required=True)
    prepare_study.add_argument("--nodes", type=int, required=True)
    prepare_study.add_argument("--seed", type=int, default=DEFAULT_SEED)
    prepare_study.add_argument("--output", type=Path, required=True)
    prepare_monolithic = prepare_families.add_parser("monolithic")
    prepare_monolithic.add_argument(
        "--mechanism", choices=sorted(COMMITTED_CIRCUITS), required=True
    )
    prepare_monolithic.add_argument(
        "--nodes", type=int, required=True, help="number of nodes (at least 2)"
    )
    prepare_monolithic.add_argument("--seed", type=int, default=DEFAULT_SEED)
    prepare_monolithic.add_argument("--output", type=Path, required=True)
    prepare_monolithic.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_ROOT)
    prepare_composite = prepare_families.add_parser("composite")
    prepare_composite.add_argument(
        "--variant", choices=sorted(COMPOSITE_VARIANTS), required=True
    )
    prepare_composite.add_argument("--nodes", type=int, required=True)
    prepare_composite.add_argument("--segments", type=int, required=True)
    prepare_composite.add_argument("--seed", type=int, default=DEFAULT_SEED)
    prepare_composite.add_argument("--output", type=Path, required=True)
    prepare_composite.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_ROOT)

    prepare_recursive = prepare_families.add_parser("recursive")
    prepare_recursive.add_argument("--nodes", type=int, required=True)
    prepare_recursive.add_argument("--segments", type=int, required=True)
    prepare_recursive.add_argument("--seed", type=int, default=DEFAULT_SEED)
    prepare_recursive.add_argument("--output", type=Path, required=True)
    prepare_recursive.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_ROOT)

    prove = commands.add_parser("prove", help="produce a retained proof set")
    prove_families = prove.add_subparsers(dest="family", required=True)
    prove_recursive = prove_families.add_parser("recursive")
    prove_recursive.add_argument("--workspace", type=Path, required=True)

    benchmark = commands.add_parser("benchmark", help="run a benchmark grid")
    benchmark_families = benchmark.add_subparsers(dest="family", required=True)
    benchmark_study_parser = benchmark_families.add_parser("study")
    benchmark_study_parser.add_argument(
        "--mechanism", choices=["all", *sorted(STUDY_CIRCUITS)], required=True
    )
    benchmark_study_parser.add_argument("--nodes", nargs="+", type=int, required=True)
    benchmark_study_parser.add_argument("--runs", type=int, default=5)
    benchmark_study_parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    benchmark_study_parser.add_argument("--output", type=Path, required=True)
    benchmark_monolithic_parser = benchmark_families.add_parser("monolithic")
    benchmark_monolithic_parser.add_argument(
        "--mechanism", choices=["all", *sorted(COMMITTED_CIRCUITS)], required=True
    )
    benchmark_monolithic_parser.add_argument(
        "--nodes",
        nargs="+",
        type=int,
        required=True,
        help="node counts (each at least 2)",
    )
    benchmark_monolithic_parser.add_argument("--runs", type=int, default=5)
    benchmark_monolithic_parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    benchmark_monolithic_parser.add_argument("--output", type=Path, required=True)
    benchmark_monolithic_parser.add_argument(
        "--cache-dir", type=Path, default=DEFAULT_CACHE_ROOT
    )
    benchmark_composite_parser = benchmark_families.add_parser("composite")
    benchmark_composite_parser.add_argument(
        "--variant", choices=["all", *sorted(COMPOSITE_VARIANTS)], required=True
    )
    benchmark_composite_parser.add_argument(
        "--nodes", nargs="+", type=int, required=True
    )
    benchmark_composite_parser.add_argument(
        "--segments", nargs="+", type=int, required=True
    )
    benchmark_composite_parser.add_argument("--runs", type=int, default=3)
    benchmark_composite_parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    benchmark_composite_parser.add_argument("--output", type=Path, required=True)
    benchmark_composite_parser.add_argument(
        "--cache-dir", type=Path, default=DEFAULT_CACHE_ROOT
    )
    benchmark_recursive_parser = benchmark_families.add_parser("recursive")
    benchmark_recursive_parser.add_argument(
        "--nodes", nargs="+", type=int, required=True
    )
    benchmark_recursive_parser.add_argument(
        "--segments", nargs="+", type=int, required=True
    )
    benchmark_recursive_parser.add_argument("--runs", type=int, default=2)
    benchmark_recursive_parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    benchmark_recursive_parser.add_argument("--output", type=Path, required=True)
    benchmark_recursive_parser.add_argument(
        "--cache-dir", type=Path, default=DEFAULT_CACHE_ROOT
    )

    verify = commands.add_parser("verify", help="verify a prepared proof set")
    verify_families = verify.add_subparsers(dest="family", required=True)
    verify_composite = verify_families.add_parser("composite")
    verify_composite.add_argument("--workspace", type=Path, required=True)
    verify_recursive = verify_families.add_parser("recursive")
    verify_recursive.add_argument("--workspace", type=Path, required=True)
    verify_recursive.add_argument("--build-metadata", type=Path)

    results = commands.add_parser(
        "results", help="validate and reproduce the frozen quantitative results"
    )
    results_commands = results.add_subparsers(dest="results_command", required=True)
    results_commands.add_parser("validate")
    reproduce = results_commands.add_parser("reproduce")
    reproduce.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check-toolchain":
            print(json.dumps(validate_toolchain(), indent=2))
            return 0
        if args.command == "prepare" and args.family == "study":
            output = prepare_workspace(
                args.mechanism, args.nodes, args.output, seed=args.seed
            )
            print(output)
            return 0
        if args.command == "prepare" and args.family == "monolithic":
            output = prepare_committed_workspace(
                args.mechanism,
                args.nodes,
                args.output,
                seed=args.seed,
                cache_dir=args.cache_dir,
            )
            print(output)
            return 0
        if args.command == "prepare" and args.family == "composite":
            output = prepare_composite_workspace(
                args.variant,
                args.nodes,
                args.segments,
                args.output,
                seed=args.seed,
                cache_dir=args.cache_dir,
            )
            print(output)
            return 0
        if args.command == "prepare" and args.family == "recursive":
            output = prepare_recursive_workspace(
                args.nodes,
                args.segments,
                args.output,
                seed=args.seed,
                cache_dir=args.cache_dir,
            )
            print(output)
            return 0
        if args.command == "prove" and args.family == "recursive":
            report = prove_recursive_workspace(args.workspace)
            print(json.dumps(dataclasses.asdict(report), indent=2))
            return 0
        if args.command == "benchmark" and args.family == "study":
            mechanisms = (
                list(STUDY_CIRCUITS)
                if args.mechanism == "all"
                else [args.mechanism]
            )
            output = benchmark_study(
                mechanisms,
                args.nodes,
                args.runs,
                args.output,
                seed=args.seed,
            )
            print(output)
            return 0
        if args.command == "benchmark" and args.family == "monolithic":
            mechanisms = (
                list(COMMITTED_CIRCUITS)
                if args.mechanism == "all"
                else [args.mechanism]
            )
            output = benchmark_monolithic(
                mechanisms,
                args.nodes,
                args.runs,
                args.output,
                seed=args.seed,
                cache_dir=args.cache_dir,
            )
            print(output)
            return 0
        if args.command == "benchmark" and args.family == "composite":
            variants = (
                list(COMPOSITE_VARIANTS) if args.variant == "all" else [args.variant]
            )
            output = benchmark_composite(
                variants,
                args.nodes,
                args.segments,
                args.runs,
                args.output,
                seed=args.seed,
                cache_dir=args.cache_dir,
            )
            print(output)
            return 0
        if args.command == "benchmark" and args.family == "recursive":
            output = benchmark_recursive(
                args.nodes,
                args.segments,
                args.runs,
                args.output,
                seed=args.seed,
                cache_dir=args.cache_dir,
            )
            print(output)
            return 0
        if args.command == "verify" and args.family == "composite":
            report = verify_composite_workspace(args.workspace)
            print(json.dumps(dataclasses.asdict(report), indent=2))
            return 0
        if args.command == "verify" and args.family == "recursive":
            report = verify_recursive_workspace(
                args.workspace, args.build_metadata
            )
            if report.trust_mode == "workspace-local":
                print(
                    "warning: workspace-local build metadata proves internal "
                    "consistency, not independent key authentication",
                    file=sys.stderr,
                )
            print(json.dumps(dataclasses.asdict(report), indent=2))
            return 0
        if args.command == "results" and args.results_command == "validate":
            print(json.dumps(dataclasses.asdict(validate_results()), indent=2))
            return 0
        if args.command == "results" and args.results_command == "reproduce":
            print(reproduce_results(args.output))
            return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2
