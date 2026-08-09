"""Command-line interface for the Git DAG evidence lab."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys
from typing import TextIO

from .lab import LabError, run_lab
from .pack import run_pack_lab


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m git_dag_lab",
        description="Build and independently verify a deterministic Git object graph.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify", help="print a compact verification receipt")

    inspect_parser = subparsers.add_parser(
        "inspect", help="print the complete machine-readable evidence document"
    )
    inspect_parser.add_argument(
        "--compact",
        action="store_true",
        help="emit canonical JSON on one line instead of indented JSON",
    )

    subparsers.add_parser(
        "pack-verify",
        help="build and independently verify a real Git pack v2/index v2 pair",
    )
    pack_inspect_parser = subparsers.add_parser(
        "pack-inspect",
        help="print the complete machine-readable pack/index evidence document",
    )
    pack_inspect_parser.add_argument(
        "--compact",
        action="store_true",
        help="emit canonical JSON on one line instead of indented JSON",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI without mutating process environment or working directory."""

    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)

    try:
        if args.command.startswith("pack-"):
            report = run_pack_lab(root if root is not None else Path.cwd())
        else:
            report = run_lab(root if root is not None else Path.cwd())
    except LabError as exc:
        errors.write(f"ERROR git-dag-lab: {exc}\n")
        return 1

    if args.command in {"verify", "pack-verify"}:
        output.write(report.receipt_line + "\n")
    else:
        output.write(report.to_json(pretty=not args.compact) + "\n")
    return 0
