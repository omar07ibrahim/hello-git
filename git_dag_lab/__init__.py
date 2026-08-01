"""Deterministic experiments with real Git objects."""

from .lab import LabError, LabReport, git_object_oid, parse_commit, parse_tree, run_lab

__all__ = [
    "LabError",
    "LabReport",
    "git_object_oid",
    "parse_commit",
    "parse_tree",
    "run_lab",
]

__version__ = "0.1.0"
