"""Build and verify a small, deterministic graph in a real Git object database.

The scenario is intentionally created with plumbing commands.  That keeps the
object bytes explicit and lets this module verify Git's object IDs independently
instead of trusting the command that wrote each object.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from types import MappingProxyType
from typing import Any


SCHEMA_VERSION = "git-dag-lab/v1"
OBJECT_FORMAT = "sha1"
OID_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTITY_NAME = "Git DAG Lab"
IDENTITY_EMAIL = "dag-lab@example.invalid"
MAX_OUTPUT_BYTES = 1_048_576
COMMAND_TIMEOUT_SECONDS = 10.0

README_BLOB = (
    b"# Deterministic Git DAG Lab\n\n"
    b"This file is stored as a real Git blob.\n"
)
FEATURE_BLOB = (
    b"def object_envelope(kind: str, payload: bytes) -> bytes:\n"
    b"    header = f\"{kind} {len(payload)}\\0\".encode(\"ascii\")\n"
    b"    return header + payload\n"
)
DOCS_BLOB = (
    b"# Object graph\n\n"
    b"A commit points to one tree and zero or more ordered parents.\n"
)

_ALLOWED_GIT_COMMANDS = frozenset(
    {
        "cat-file",
        "commit-tree",
        "for-each-ref",
        "fsck",
        "hash-object",
        "merge-base",
        "mktree",
        "pack-objects",
        "rev-list",
        "symbolic-ref",
        "update-ref",
    }
)


class LabError(RuntimeError):
    """Base class for deterministic, path-free lab failures."""


class GitUnavailableError(LabError):
    """Raised when a usable Git executable cannot be found."""


class GitCommandError(LabError):
    """Raised when an allow-listed Git command fails."""


class GitTimeoutError(LabError):
    """Raised when an isolated Git command exceeds its deadline."""


class GitOutputLimitError(LabError):
    """Raised when a Git command produces unexpectedly large output."""


class VerificationError(LabError):
    """Raised when Git output does not match the independently derived model."""


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Captured bytes from one argv-only process invocation."""

    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class TreeEntry:
    """One raw Git tree entry; directory mode is encoded as ``40000``."""

    mode: str
    name: str
    oid: str

    @property
    def object_type(self) -> str:
        return "tree" if self.mode == "40000" else "blob"

    def as_dict(self) -> dict[str, str]:
        return {
            "mode": self.mode,
            "name": self.name,
            "oid": self.oid,
            "type": self.object_type,
        }


@dataclass(frozen=True, slots=True)
class ParsedCommit:
    """Relevant fields decoded from a commit object."""

    tree: str
    parents: tuple[str, ...]
    author: str
    committer: str
    message: str


@dataclass(frozen=True, slots=True)
class LabReport:
    """Canonical evidence document and its non-recursive receipt."""

    payload: Mapping[str, Any]
    receipt_sha256: str

    @property
    def document(self) -> dict[str, Any]:
        return {
            "report": _mutable_copy(self.payload),
            "receipt": {
                "algorithm": "sha256",
                "canonicalization": "UTF-8 JSON; sorted keys; compact separators",
                "sha256": self.receipt_sha256,
            },
        }

    @property
    def receipt_line(self) -> str:
        inventory = self.payload["inventory"]
        return (
            f"PASS {SCHEMA_VERSION} "
            f"objects={inventory['total']} commits={inventory['by_type']['commit']} "
            "same_tree=true different_history=true "
            f"receipt_sha256={self.receipt_sha256}"
        )

    def to_json(self, *, pretty: bool = False) -> str:
        if pretty:
            return json.dumps(
                self.document,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
        return _canonical_json(self.document).decode("utf-8")


@dataclass(frozen=True, slots=True)
class _Workspace:
    root: Path
    private: Path
    home: Path
    xdg: Path
    tmp: Path
    template: Path
    repository: Path


@dataclass(frozen=True, slots=True)
class _CommitSpec:
    name: str
    tree: str
    parents: tuple[str, ...]
    message: str
    timestamp: int


def _mutable_copy(value: Any) -> Any:
    """Copy nested immutable/report values into JSON-compatible containers."""

    if isinstance(value, Mapping):
        return {key: _mutable_copy(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_mutable_copy(item) for item in value]
    if isinstance(value, list):
        return [_mutable_copy(item) for item in value]
    return value


def _deep_freeze(value: Any) -> Any:
    """Recursively freeze a report so its receipt cannot outlive its bytes."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def git_object_oid(object_type: str, payload: bytes) -> str:
    """Compute Git's SHA-1 object ID from the canonical object envelope."""

    if object_type not in {"blob", "tree", "commit"}:
        raise ValueError(f"unsupported Git object type: {object_type}")
    header = f"{object_type} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _git_tree_sort_key(entry: TreeEntry) -> bytes:
    """Model Git's name ordering, where a directory compares as ``name/``."""

    suffix = b"/" if entry.mode == "40000" else b""
    return entry.name.encode("utf-8") + suffix


def parse_tree(payload: bytes) -> tuple[TreeEntry, ...]:
    """Parse raw binary tree bytes without invoking Git."""

    entries: list[TreeEntry] = []
    cursor = 0
    while cursor < len(payload):
        mode_end = payload.find(b" ", cursor)
        name_end = payload.find(b"\0", mode_end + 1)
        if mode_end < 0 or name_end < 0 or name_end + 21 > len(payload):
            raise VerificationError("tree payload is truncated")
        try:
            mode = payload[cursor:mode_end].decode("ascii")
            name = payload[mode_end + 1 : name_end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError("tree payload contains invalid text") from exc
        oid = payload[name_end + 1 : name_end + 21].hex()
        if mode not in {"100644", "40000"} or not name or "/" in name:
            raise VerificationError("tree payload contains an unsupported entry")
        entries.append(TreeEntry(mode=mode, name=name, oid=oid))
        cursor = name_end + 21
    if cursor != len(payload):
        raise VerificationError("tree payload has trailing bytes")
    encoded_names = [entry.name.encode("utf-8") for entry in entries]
    sort_keys = [_git_tree_sort_key(entry) for entry in entries]
    if sort_keys != sorted(sort_keys) or len(set(encoded_names)) != len(entries):
        raise VerificationError("tree entries are not uniquely byte-sorted")
    return tuple(entries)


def parse_commit(payload: bytes) -> ParsedCommit:
    """Parse the fixed, continuation-free headers used by this scenario."""

    header_bytes, separator, message_bytes = payload.partition(b"\n\n")
    if not separator:
        raise VerificationError("commit payload has no header separator")
    headers: dict[str, list[str]] = {}
    for raw_line in header_bytes.splitlines():
        if raw_line.startswith(b" ") or b" " not in raw_line:
            raise VerificationError("commit payload contains an unsupported header")
        key_bytes, value_bytes = raw_line.split(b" ", 1)
        try:
            key = key_bytes.decode("ascii")
            value = value_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError("commit payload contains invalid text") from exc
        headers.setdefault(key, []).append(value)

    required_singletons = {"tree", "author", "committer"}
    if any(len(headers.get(key, [])) != 1 for key in required_singletons):
        raise VerificationError("commit payload has invalid required headers")
    if set(headers) - {"tree", "parent", "author", "committer"}:
        raise VerificationError("commit payload contains unexpected headers")
    try:
        message = message_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("commit message is not UTF-8") from exc
    return ParsedCommit(
        tree=headers["tree"][0],
        parents=tuple(headers.get("parent", [])),
        author=headers["author"][0],
        committer=headers["committer"][0],
        message=message,
    )


def _validate_root(root: Path) -> Path:
    """Reject missing roots and symlinks in every named path component."""

    raw = root if root.is_absolute() else Path.cwd() / root
    absolute = Path(os.path.abspath(os.fspath(raw)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError as exc:
            raise LabError("workspace root does not exist") from exc
        if stat.S_ISLNK(mode):
            raise LabError("workspace root may not contain symlink components")
    if not absolute.is_dir():
        raise LabError("workspace root is not a directory")
    return absolute


def _find_git() -> Path:
    """Resolve Git once, then execute only that absolute path."""

    candidate = shutil.which("git")
    if candidate is None:
        raise GitUnavailableError("Git executable was not found")
    try:
        resolved = Path(candidate).resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as exc:
        raise GitUnavailableError("Git executable could not be resolved") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise GitUnavailableError("Git executable is not runnable")
    return resolved


def _minimal_git_environment(workspace: _Workspace) -> dict[str, str]:
    """Return a fresh environment with no inherited Git redirect variables."""

    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_PAGER": "cat",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": os.fspath(workspace.home),
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "TMPDIR": os.fspath(workspace.tmp),
        "TZ": "UTC",
        "XDG_CONFIG_HOME": os.fspath(workspace.xdg),
    }


def _execute(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    label: str,
    stdin: bytes | None = None,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> ProcessResult:
    """Execute one argv-only command with deterministic, bounded diagnostics."""

    if not command or any(not isinstance(part, str) or "\0" in part for part in command):
        raise ValueError("command must contain non-NUL string arguments")
    if timeout <= 0 or max_output_bytes <= 0:
        raise ValueError("process limits must be positive")
    try:
        with tempfile.TemporaryFile(mode="w+b", dir=cwd) as stdout_buffer, tempfile.TemporaryFile(
            mode="w+b", dir=cwd
        ) as stderr_buffer:
            try:
                completed = subprocess.run(
                    list(command),
                    input=stdin,
                    cwd=cwd,
                    env=dict(env),
                    stdout=stdout_buffer,
                    stderr=stderr_buffer,
                    check=False,
                    shell=False,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise GitTimeoutError(f"git {label} exceeded its time limit") from exc

            stdout_size = stdout_buffer.tell()
            stderr_size = stderr_buffer.tell()
            if stdout_size > max_output_bytes or stderr_size > max_output_bytes:
                raise GitOutputLimitError(f"git {label} exceeded its output limit")
            stdout_buffer.seek(0)
            stderr_buffer.seek(0)
            stdout = stdout_buffer.read()
            stderr = stderr_buffer.read()
    except OSError as exc:
        raise GitCommandError(f"git {label} could not be executed") from exc
    return ProcessResult(
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
    )


class _GitRunner:
    """Small allow-listed adapter around one isolated bare repository."""

    def __init__(self, git: Path, workspace: _Workspace):
        self._git = git
        self._workspace = workspace
        self._env = _minimal_git_environment(workspace)
        self.trace: list[str] = []

    @property
    def environment(self) -> Mapping[str, str]:
        return MappingProxyType(self._env)

    def initialize(self) -> None:
        command = [
            os.fspath(self._git),
            "init",
            "--bare",
            "--object-format=sha1",
            "--initial-branch=main",
            f"--template={self._workspace.template}",
            os.fspath(self._workspace.repository),
        ]
        result = _execute(
            command,
            cwd=self._workspace.private,
            env=self._env,
            label="init",
        )
        self.trace.append("init")
        if result.returncode != 0:
            raise GitCommandError(
                "git init failed; Git 2.29 or newer with SHA-1 object-format support is required"
            )

    def run(
        self,
        subcommand: str,
        *arguments: str,
        stdin: bytes | None = None,
        env_overlay: Mapping[str, str] | None = None,
        allowed_returncodes: Iterable[int] = (0,),
    ) -> ProcessResult:
        if subcommand not in _ALLOWED_GIT_COMMANDS:
            raise ValueError(f"Git subcommand is not allow-listed: {subcommand}")
        if any("://" in argument for argument in arguments):
            raise ValueError("remote-looking Git arguments are not allowed")
        environment = dict(self._env)
        if env_overlay:
            allowed_overlay = {
                "GIT_AUTHOR_DATE",
                "GIT_AUTHOR_EMAIL",
                "GIT_AUTHOR_NAME",
                "GIT_COMMITTER_DATE",
                "GIT_COMMITTER_EMAIL",
                "GIT_COMMITTER_NAME",
            }
            if set(env_overlay) - allowed_overlay:
                raise ValueError("unsupported Git environment overlay")
            environment.update(env_overlay)
        command = [
            os.fspath(self._git),
            "-c",
            f"core.hooksPath={self._workspace.template}",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            f"--git-dir={self._workspace.repository}",
            subcommand,
            *arguments,
        ]
        result = _execute(
            command,
            cwd=self._workspace.private,
            env=environment,
            label=subcommand,
            stdin=stdin,
        )
        self.trace.append(subcommand)
        if result.returncode not in set(allowed_returncodes):
            raise GitCommandError(
                f"git {subcommand} failed with exit code {result.returncode}"
            )
        return result


def _new_workspace(root: Path, private: Path) -> _Workspace:
    resolved_root = root.resolve(strict=True)
    resolved_private = private.resolve(strict=True)
    if os.path.commonpath((resolved_root, resolved_private)) != os.fspath(resolved_root):
        raise LabError("isolated workspace escaped the requested root")
    os.chmod(resolved_private, 0o700)
    children = {
        "home": resolved_private / "home",
        "xdg": resolved_private / "xdg",
        "tmp": resolved_private / "tmp",
        "template": resolved_private / "empty-template",
    }
    for child in children.values():
        child.mkdir(mode=0o700)
    return _Workspace(
        root=resolved_root,
        private=resolved_private,
        home=children["home"],
        xdg=children["xdg"],
        tmp=children["tmp"],
        template=children["template"],
        repository=resolved_private / "objects.git",
    )


def _decode_oid(output: bytes, operation: str) -> str:
    try:
        oid = output.strip().decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"git {operation} returned a non-ASCII object ID") from exc
    if not OID_RE.fullmatch(oid):
        raise VerificationError(f"git {operation} returned an invalid object ID")
    return oid


def _store_blob(runner: _GitRunner, payload: bytes) -> str:
    oid = _decode_oid(
        runner.run("hash-object", "-w", "--stdin", stdin=payload).stdout,
        "hash-object",
    )
    if oid != git_object_oid("blob", payload):
        raise VerificationError("Git blob ID differs from the independent envelope hash")
    return oid


def _tree_payload(entries: Sequence[TreeEntry]) -> bytes:
    names = [entry.name.encode("utf-8") for entry in entries]
    sort_keys = [_git_tree_sort_key(entry) for entry in entries]
    if sort_keys != sorted(sort_keys) or len(set(names)) != len(names):
        raise ValueError("tree entries must be uniquely byte-sorted")
    chunks: list[bytes] = []
    for entry in entries:
        if entry.mode not in {"100644", "40000"} or not OID_RE.fullmatch(entry.oid):
            raise ValueError("invalid tree entry")
        chunks.append(
            entry.mode.encode("ascii")
            + b" "
            + entry.name.encode("utf-8")
            + b"\0"
            + bytes.fromhex(entry.oid)
        )
    return b"".join(chunks)


def _store_tree(runner: _GitRunner, entries: Sequence[TreeEntry]) -> str:
    raw = _tree_payload(entries)
    lines = b"".join(
        (
            f"{entry.mode} {entry.object_type} {entry.oid}\t{entry.name}\n".encode(
                "utf-8"
            )
        )
        for entry in entries
    )
    oid = _decode_oid(runner.run("mktree", stdin=lines).stdout, "mktree")
    if oid != git_object_oid("tree", raw):
        raise VerificationError("Git tree ID differs from the independent envelope hash")
    stored = runner.run("cat-file", "tree", oid).stdout
    if stored != raw or parse_tree(stored) != tuple(entries):
        raise VerificationError("stored tree bytes differ from the declared entries")
    return oid


def _identity_line(timestamp: int) -> str:
    return f"{IDENTITY_NAME} <{IDENTITY_EMAIL}> {timestamp} +0000"


def _commit_payload(spec: _CommitSpec) -> bytes:
    lines = [f"tree {spec.tree}"]
    lines.extend(f"parent {parent}" for parent in spec.parents)
    identity = _identity_line(spec.timestamp)
    lines.extend((f"author {identity}", f"committer {identity}", "", spec.message))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _store_commit(runner: _GitRunner, spec: _CommitSpec) -> tuple[str, bytes]:
    environment = {
        "GIT_AUTHOR_DATE": f"{spec.timestamp} +0000",
        "GIT_AUTHOR_EMAIL": IDENTITY_EMAIL,
        "GIT_AUTHOR_NAME": IDENTITY_NAME,
        "GIT_COMMITTER_DATE": f"{spec.timestamp} +0000",
        "GIT_COMMITTER_EMAIL": IDENTITY_EMAIL,
        "GIT_COMMITTER_NAME": IDENTITY_NAME,
    }
    arguments: list[str] = [spec.tree]
    for parent in spec.parents:
        arguments.extend(("-p", parent))
    oid = _decode_oid(
        runner.run(
            "commit-tree",
            *arguments,
            stdin=(spec.message + "\n").encode("utf-8"),
            env_overlay=environment,
        ).stdout,
        "commit-tree",
    )
    expected = _commit_payload(spec)
    stored = runner.run("cat-file", "commit", oid).stdout
    if stored != expected or oid != git_object_oid("commit", expected):
        raise VerificationError("stored commit bytes differ from the fixed commit model")
    parsed = parse_commit(stored)
    if parsed != ParsedCommit(
        tree=spec.tree,
        parents=spec.parents,
        author=_identity_line(spec.timestamp),
        committer=_identity_line(spec.timestamp),
        message=spec.message + "\n",
    ):
        raise VerificationError("stored commit fields differ from the fixed commit model")
    return oid, stored


def _parse_object_inventory(output: bytes) -> dict[str, tuple[str, int]]:
    inventory: dict[str, tuple[str, int]] = {}
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise VerificationError("object inventory is not ASCII") from exc
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 3 or not OID_RE.fullmatch(parts[0]):
            raise VerificationError("object inventory row is malformed")
        object_type, size_text = parts[1:]
        if object_type not in {"blob", "tree", "commit"} or not size_text.isdigit():
            raise VerificationError("object inventory row has invalid fields")
        inventory[parts[0]] = (object_type, int(size_text))
    if len(inventory) != len(lines):
        raise VerificationError("object inventory contains duplicate IDs")
    return inventory


def _parse_refs(output: bytes) -> dict[str, str]:
    refs: dict[str, str] = {}
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise VerificationError("reference inventory is not ASCII") from exc
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 2 or not parts[0].startswith("refs/") or not OID_RE.fullmatch(parts[1]):
            raise VerificationError("reference inventory row is malformed")
        refs[parts[0]] = parts[1]
    if len(refs) != len(lines):
        raise VerificationError("reference inventory contains duplicate names")
    return refs


def _assert_ancestor(
    runner: _GitRunner,
    ancestor: str,
    descendant: str,
    *,
    expected: bool,
) -> None:
    result = runner.run(
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
        allowed_returncodes=(0, 1),
    )
    if (result.returncode == 0) is not expected:
        raise VerificationError("commit ancestry differs from the scenario model")


def _build_and_verify(runner: _GitRunner) -> LabReport:
    runner.initialize()

    blobs = {
        "readme": _store_blob(runner, README_BLOB),
        "feature": _store_blob(runner, FEATURE_BLOB),
        "docs": _store_blob(runner, DOCS_BLOB),
    }
    trees: dict[str, str] = {}
    tree_entries: dict[str, tuple[TreeEntry, ...]] = {}

    tree_entries["root"] = (TreeEntry("100644", "README.md", blobs["readme"]),)
    trees["root"] = _store_tree(runner, tree_entries["root"])

    tree_entries["src"] = (TreeEntry("100644", "feature.py", blobs["feature"]),)
    trees["src"] = _store_tree(runner, tree_entries["src"])

    tree_entries["feature"] = (
        TreeEntry("100644", "README.md", blobs["readme"]),
        TreeEntry("40000", "src", trees["src"]),
    )
    trees["feature"] = _store_tree(runner, tree_entries["feature"])

    tree_entries["docs-directory"] = (
        TreeEntry("100644", "guide.md", blobs["docs"]),
    )
    trees["docs-directory"] = _store_tree(runner, tree_entries["docs-directory"])

    tree_entries["docs"] = (
        TreeEntry("100644", "README.md", blobs["readme"]),
        TreeEntry("40000", "docs", trees["docs-directory"]),
    )
    trees["docs"] = _store_tree(runner, tree_entries["docs"])

    tree_entries["combined"] = (
        TreeEntry("100644", "README.md", blobs["readme"]),
        TreeEntry("40000", "docs", trees["docs-directory"]),
        TreeEntry("40000", "src", trees["src"]),
    )
    trees["combined"] = _store_tree(runner, tree_entries["combined"])

    commit_specs: list[_CommitSpec] = []
    commits: dict[str, str] = {}
    commit_payloads: dict[str, bytes] = {}

    def add_commit(spec: _CommitSpec) -> None:
        oid, payload = _store_commit(runner, spec)
        commit_specs.append(spec)
        commits[spec.name] = oid
        commit_payloads[spec.name] = payload

    add_commit(
        _CommitSpec("root", trees["root"], (), "seed: add lab readme", 1_704_067_200)
    )
    add_commit(
        _CommitSpec(
            "feature",
            trees["feature"],
            (commits["root"],),
            "feat: add deterministic analyzer",
            1_704_153_600,
        )
    )
    add_commit(
        _CommitSpec(
            "docs",
            trees["docs"],
            (commits["root"],),
            "docs: explain object graph",
            1_704_240_000,
        )
    )
    add_commit(
        _CommitSpec(
            "merge",
            trees["combined"],
            (commits["feature"], commits["docs"]),
            "merge: combine feature and docs",
            1_704_326_400,
        )
    )
    add_commit(
        _CommitSpec(
            "replay",
            trees["combined"],
            (commits["docs"],),
            "feat: replay analyzer on docs",
            1_704_412_800,
        )
    )

    expected_refs = {
        "refs/heads/docs": commits["docs"],
        "refs/heads/feature": commits["feature"],
        "refs/heads/main": commits["merge"],
        "refs/results/rebased-feature": commits["replay"],
    }
    update_commands = b"".join(
        f"create {name} {oid}\n".encode("ascii")
        for name, oid in sorted(expected_refs.items())
    )
    runner.run("update-ref", "--stdin", stdin=update_commands)
    runner.run("symbolic-ref", "HEAD", "refs/heads/main")

    actual_refs = _parse_refs(
        runner.run("for-each-ref", "--format=%(refname) %(objectname)").stdout
    )
    if actual_refs != expected_refs:
        raise VerificationError("reference inventory differs from the scenario model")
    head = runner.run("symbolic-ref", "HEAD").stdout.decode("ascii").strip()
    if head != "refs/heads/main":
        raise VerificationError("HEAD is not attached to refs/heads/main")

    expected_objects: dict[str, tuple[str, bytes]] = {}
    for name, oid in blobs.items():
        expected_objects[oid] = (
            "blob",
            {"readme": README_BLOB, "feature": FEATURE_BLOB, "docs": DOCS_BLOB}[name],
        )
    for name, oid in trees.items():
        expected_objects[oid] = ("tree", _tree_payload(tree_entries[name]))
    for name, oid in commits.items():
        expected_objects[oid] = ("commit", commit_payloads[name])
    if len(expected_objects) != 14:
        raise VerificationError("scenario does not contain exactly 14 unique objects")

    inventory = _parse_object_inventory(
        runner.run(
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ).stdout
    )
    expected_inventory = {
        oid: (object_type, len(payload))
        for oid, (object_type, payload) in expected_objects.items()
    }
    if inventory != expected_inventory:
        raise VerificationError("object database differs from the 14-object model")

    for oid, (object_type, payload) in expected_objects.items():
        stored = runner.run("cat-file", object_type, oid).stdout
        if stored != payload or git_object_oid(object_type, stored) != oid:
            raise VerificationError("an object failed independent envelope verification")

    reachable_lines = runner.run("rev-list", "--objects", "--all").stdout.splitlines()
    reachable = {line.split(b" ", 1)[0].decode("ascii") for line in reachable_lines}
    if reachable != set(expected_objects):
        raise VerificationError("not every expected object is reachable from a published ref")

    fsck = runner.run("fsck", "--full", "--strict", "--no-reflogs")
    if fsck.stdout or fsck.stderr:
        raise VerificationError("strict fsck produced unexpected diagnostics")

    ancestry = {
        "root->feature": True,
        "root->docs": True,
        "root->merge": True,
        "root->replay": True,
        "feature->merge": True,
        "docs->merge": True,
        "docs->replay": True,
        "feature->replay": False,
        "merge->replay": False,
        "replay->merge": False,
    }
    for relationship, expected in ancestry.items():
        source, destination = relationship.split("->")
        _assert_ancestor(
            runner,
            commits[source],
            commits[destination],
            expected=expected,
        )

    if commits["merge"] == commits["replay"] or trees["combined"] != commit_specs[3].tree:
        raise VerificationError("merge and replay identity invariant failed")
    merge_commit = parse_commit(commit_payloads["merge"])
    replay_commit = parse_commit(commit_payloads["replay"])
    if merge_commit.tree != replay_commit.tree:
        raise VerificationError("merge and replay do not resolve to the same tree")
    if merge_commit.parents == replay_commit.parents:
        raise VerificationError("merge and replay unexpectedly have the same history")

    type_counts = Counter(object_type for object_type, _ in expected_objects.values())
    object_rows = [
        {
            "oid": oid,
            "sha1_verified": True,
            "size": len(payload),
            "type": object_type,
        }
        for oid, (object_type, payload) in sorted(expected_objects.items())
    ]
    graph_nodes = []
    for spec in commit_specs:
        graph_nodes.append(
            {
                "id": spec.name,
                "message": spec.message,
                "oid": commits[spec.name],
                "parents": list(spec.parents),
                "timestamp": spec.timestamp,
                "tree": spec.tree,
            }
        )

    merge_payload = commit_payloads["merge"]
    command_counts = Counter(runner.trace)

    payload: dict[str, Any] = {
        "checks": [
            {"id": "independent-object-envelopes", "passed": True, "verified": 14},
            {"id": "exact-object-inventory", "passed": True, "objects": 14},
            {"id": "exact-reference-inventory", "passed": True, "refs": 4},
            {"id": "all-objects-reachable", "passed": True, "objects": 14},
            {"id": "strict-fsck", "passed": True, "diagnostics": 0},
            {"id": "exact-commit-parent-order", "passed": True, "commits": 5},
            {"id": "same-tree", "passed": True, "tree": merge_commit.tree},
            {
                "id": "different-history",
                "passed": True,
                "merge_parents": len(merge_commit.parents),
                "replay_parents": len(replay_commit.parents),
            },
            {"id": "ancestry-matrix", "passed": True, "relationships": len(ancestry)},
        ],
        "execution_policy": {
            "global_and_system_config": "ignored",
            "host_repository": "not read",
            "network_capable_git_commands": 0,
            "process_environment": "minimal and isolated",
            "shell": False,
            "synthetic_identity": f"{IDENTITY_NAME} <{IDENTITY_EMAIL}>",
        },
        "execution": {
            "by_subcommand": dict(sorted(command_counts.items())),
            "git_invocations": sum(command_counts.values()),
            "subcommands": sorted(command_counts),
        },
        "graph": {
            "ancestry": ancestry,
            "head": head,
            "nodes": graph_nodes,
            "refs": dict(sorted(expected_refs.items())),
            "same_tree_different_history": {
                "merge_commit": commits["merge"],
                "rebase_shaped_commit": commits["replay"],
                "same_tree": trees["combined"],
            },
        },
        "inventory": {
            "by_type": dict(sorted(type_counts.items())),
            "objects": object_rows,
            "total": len(expected_objects),
        },
        "blobs": {
            name: {
                "oid": oid,
                "size": len(
                    {"readme": README_BLOB, "feature": FEATURE_BLOB, "docs": DOCS_BLOB}[
                        name
                    ]
                ),
            }
            for name, oid in sorted(blobs.items())
        },
        "object_format": OBJECT_FORMAT,
        "proofs": {
            "object_envelope": {
                "envelope_sha1": commits["merge"],
                "header_utf8": f"commit {len(merge_payload)}\0",
                "oid": commits["merge"],
                "payload_sha256": hashlib.sha256(merge_payload).hexdigest(),
                "payload_size": len(merge_payload),
                "payload_utf8": merge_payload.decode("utf-8"),
                "role": "merge",
                "type": "commit",
                "verified": True,
            }
        },
        "scenario": {
            "description": "A merge and a rebase-shaped replay produce one tree with different parent topology.",
            "fixed_clock": "2024-01-01T00:00:00Z..2024-01-05T00:00:00Z",
            "name": "same-tree-different-history",
        },
        "schema_version": SCHEMA_VERSION,
        "trees": {
            name: {
                "entries": [entry.as_dict() for entry in tree_entries[name]],
                "oid": trees[name],
            }
            for name in sorted(trees)
        },
    }
    receipt = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return LabReport(payload=_deep_freeze(payload), receipt_sha256=receipt)


def run_lab(root: Path | str = ".") -> LabReport:
    """Run the lab below ``root`` and remove every temporary object on return."""

    try:
        validated_root = _validate_root(Path(root))
        git = _find_git()
        with tempfile.TemporaryDirectory(
            prefix=".git-dag-lab-", dir=validated_root
        ) as private_name:
            workspace = _new_workspace(validated_root, Path(private_name))
            runner = _GitRunner(git, workspace)
            return _build_and_verify(runner)
    except LabError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise LabError("isolated lab setup failed") from exc
