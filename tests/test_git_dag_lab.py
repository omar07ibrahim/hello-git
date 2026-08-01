from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from git_dag_lab.cli import main
from git_dag_lab.lab import (
    DOCS_BLOB,
    FEATURE_BLOB,
    IDENTITY_EMAIL,
    MAX_OUTPUT_BYTES,
    README_BLOB,
    GitCommandError,
    GitOutputLimitError,
    GitTimeoutError,
    LabError,
    ProcessResult,
    VerificationError,
    _GitRunner,
    _Workspace,
    _execute,
    git_object_oid,
    parse_commit,
    parse_tree,
    run_lab,
)


GIT_AVAILABLE = shutil.which("git") is not None
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(GIT_AVAILABLE, "Git is required for integration tests")
class ScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = run_lab(REPOSITORY_ROOT)
        cls.document = cls.report.document
        cls.payload = cls.document["report"]

    def test_schema_and_object_format_are_explicit(self) -> None:
        self.assertEqual(self.payload["schema_version"], "git-dag-lab/v1")
        self.assertEqual(self.payload["object_format"], "sha1")

    def test_inventory_contains_exactly_fourteen_objects(self) -> None:
        inventory = self.payload["inventory"]
        self.assertEqual(inventory["total"], 14)
        self.assertEqual(inventory["by_type"], {"blob": 3, "commit": 5, "tree": 6})
        self.assertEqual(len(inventory["objects"]), 14)

    def test_every_inventory_row_was_independently_verified(self) -> None:
        rows = self.payload["inventory"]["objects"]
        self.assertTrue(all(row["sha1_verified"] for row in rows))
        self.assertTrue(all(len(row["oid"]) == 40 for row in rows))

    def test_fixed_blob_ids_match_independent_envelopes(self) -> None:
        expected = {
            git_object_oid("blob", README_BLOB),
            git_object_oid("blob", FEATURE_BLOB),
            git_object_oid("blob", DOCS_BLOB),
        }
        actual = {
            row["oid"]
            for row in self.payload["inventory"]["objects"]
            if row["type"] == "blob"
        }
        self.assertEqual(actual, expected)

    def test_merge_and_replay_share_tree_but_not_commit(self) -> None:
        proof = self.payload["graph"]["same_tree_different_history"]
        self.assertNotEqual(proof["merge_commit"], proof["rebase_shaped_commit"])
        nodes = {node["id"]: node for node in self.payload["graph"]["nodes"]}
        self.assertEqual(nodes["merge"]["tree"], nodes["replay"]["tree"])
        self.assertEqual(nodes["merge"]["tree"], proof["same_tree"])

    def test_parent_order_is_exact(self) -> None:
        nodes = {node["id"]: node for node in self.payload["graph"]["nodes"]}
        self.assertEqual(nodes["merge"]["parents"], [nodes["feature"]["oid"], nodes["docs"]["oid"]])
        self.assertEqual(nodes["replay"]["parents"], [nodes["docs"]["oid"]])

    def test_ancestry_matrix_captures_topology_difference(self) -> None:
        ancestry = self.payload["graph"]["ancestry"]
        self.assertTrue(ancestry["feature->merge"])
        self.assertTrue(ancestry["docs->merge"])
        self.assertTrue(ancestry["docs->replay"])
        self.assertFalse(ancestry["feature->replay"])
        self.assertFalse(ancestry["merge->replay"])
        self.assertFalse(ancestry["replay->merge"])

    def test_refs_are_exact_and_head_is_symbolic(self) -> None:
        refs = self.payload["graph"]["refs"]
        self.assertEqual(
            set(refs),
            {
                "refs/heads/docs",
                "refs/heads/feature",
                "refs/heads/main",
                "refs/results/rebased-feature",
            },
        )
        self.assertEqual(self.payload["graph"]["head"], "refs/heads/main")

    def test_every_check_passes(self) -> None:
        self.assertEqual(len(self.payload["checks"]), 9)
        self.assertTrue(all(check["passed"] for check in self.payload["checks"]))

    def test_object_envelope_proof_reconstructs_merge_oid(self) -> None:
        proof = self.payload["proofs"]["object_envelope"]
        payload = proof["payload_utf8"].encode("utf-8")
        merge = next(
            node for node in self.payload["graph"]["nodes"] if node["id"] == "merge"
        )
        self.assertEqual(proof["header_utf8"], f"commit {len(payload)}\0")
        self.assertEqual(proof["payload_size"], len(payload))
        self.assertEqual(proof["payload_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(proof["envelope_sha1"], git_object_oid("commit", payload))
        self.assertEqual(proof["oid"], merge["oid"])
        self.assertTrue(proof["verified"])

    def test_blob_roles_are_explicit(self) -> None:
        self.assertEqual(set(self.payload["blobs"]), {"docs", "feature", "readme"})
        self.assertEqual(
            self.payload["blobs"]["readme"]["oid"],
            git_object_oid("blob", README_BLOB),
        )

    def test_execution_summary_is_actual_and_network_free(self) -> None:
        execution = self.payload["execution"]
        self.assertEqual(
            execution["git_invocations"], sum(execution["by_subcommand"].values())
        )
        self.assertEqual(execution["by_subcommand"]["commit-tree"], 5)
        self.assertEqual(execution["by_subcommand"]["mktree"], 6)
        self.assertEqual(execution["by_subcommand"]["hash-object"], 3)
        self.assertEqual(execution["by_subcommand"]["fsck"], 1)
        self.assertTrue(
            {"clone", "fetch", "pull", "push", "remote"}.isdisjoint(
                execution["subcommands"]
            )
        )

    def test_output_contains_only_synthetic_email(self) -> None:
        rendered = self.report.to_json()
        self.assertIn(IDENTITY_EMAIL, rendered)
        self.assertNotIn("@gmail.com", rendered.lower())
        self.assertNotIn("/home/", rendered)

    def test_receipt_is_hash_of_report_only(self) -> None:
        report_bytes = json.dumps(
            self.payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            self.document["receipt"]["sha256"], hashlib.sha256(report_bytes).hexdigest()
        )

    def test_nested_report_state_is_immutable(self) -> None:
        with self.assertRaises(TypeError):
            self.report.payload["inventory"]["total"] = 999
        with self.assertRaises(TypeError):
            self.report.payload["graph"]["nodes"][0]["id"] = "tampered"
        reparsed = json.loads(self.report.to_json())
        canonical = json.dumps(
            reparsed["report"],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            reparsed["receipt"]["sha256"],
        )

    def test_report_is_deterministic_across_runs(self) -> None:
        second = run_lab(REPOSITORY_ROOT)
        self.assertEqual(second.to_json(), self.report.to_json())
        self.assertEqual(second.receipt_line, self.report.receipt_line)

    def test_concurrent_runs_have_identical_receipts(self) -> None:
        receipts: list[str] = []
        failures: list[BaseException] = []

        def worker() -> None:
            try:
                receipts.append(run_lab(REPOSITORY_ROOT).receipt_sha256)
            except BaseException as exc:  # pragma: no cover - diagnostic collection
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertFalse(failures)
        self.assertEqual(receipts, [self.report.receipt_sha256] * 2)

    def test_temporary_workspaces_are_removed(self) -> None:
        real_temporary_directory = tempfile.TemporaryDirectory
        created: list[Path] = []

        def tracked_temporary_directory(*args: object, **kwargs: object):
            directory = real_temporary_directory(*args, **kwargs)
            created.append(Path(directory.name))
            return directory

        with mock.patch(
            "git_dag_lab.lab.tempfile.TemporaryDirectory",
            side_effect=tracked_temporary_directory,
        ):
            run_lab(REPOSITORY_ROOT)
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())

    def test_environment_and_working_directory_are_unchanged(self) -> None:
        before_env = dict(os.environ)
        before_cwd = Path.cwd()
        run_lab(REPOSITORY_ROOT)
        self.assertEqual(dict(os.environ), before_env)
        self.assertEqual(Path.cwd(), before_cwd)

    def test_hostile_git_environment_cannot_change_receipt_or_write_trap(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT) as temporary:
            trap = Path(temporary) / "object-trap"
            trap.mkdir()
            hostile = {
                "GIT_AUTHOR_NAME": "Host Identity",
                "GIT_AUTHOR_EMAIL": "host@example.com",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "user.name",
                "GIT_CONFIG_VALUE_0": "Leaked Config",
                "GIT_OBJECT_DIRECTORY": os.fspath(trap),
            }
            with mock.patch.dict(os.environ, hostile, clear=False):
                actual = run_lab(REPOSITORY_ROOT)
            self.assertEqual(actual.receipt_sha256, self.report.receipt_sha256)
            self.assertEqual(list(trap.iterdir()), [])

    def test_fake_home_gitconfig_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT) as temporary:
            fake_home = Path(temporary)
            (fake_home / ".gitconfig").write_text(
                "[user]\nname = Host Leak\nemail = leak@example.com\n",
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"HOME": os.fspath(fake_home)}):
                actual = run_lab(REPOSITORY_ROOT)
            self.assertEqual(actual.receipt_sha256, self.report.receipt_sha256)
            self.assertNotIn("Host Leak", actual.to_json())


class ParserTests(unittest.TestCase):
    def test_git_object_oid_uses_type_size_nul_payload(self) -> None:
        payload = b"hello\n"
        expected = hashlib.sha1(b"blob 6\0hello\n", usedforsecurity=False).hexdigest()
        self.assertEqual(git_object_oid("blob", payload), expected)

    def test_git_object_oid_rejects_unknown_type(self) -> None:
        with self.assertRaises(ValueError):
            git_object_oid("tag", b"payload")

    def test_parse_tree_reads_binary_oid_and_modes(self) -> None:
        oid = "ab" * 20
        payload = b"100644 file.txt\0" + bytes.fromhex(oid)
        entries = parse_tree(payload)
        self.assertEqual(entries[0].mode, "100644")
        self.assertEqual(entries[0].name, "file.txt")
        self.assertEqual(entries[0].oid, oid)

    def test_parse_tree_uses_git_directory_sorting(self) -> None:
        oid = bytes.fromhex("ab" * 20)
        payload = b"100644 foo.bar\0" + oid + b"40000 foo\0" + oid
        entries = parse_tree(payload)
        self.assertEqual([entry.name for entry in entries], ["foo.bar", "foo"])

    def test_parse_tree_rejects_plain_sort_when_git_order_differs(self) -> None:
        oid = bytes.fromhex("ab" * 20)
        payload = b"40000 foo\0" + oid + b"100644 foo.bar\0" + oid
        with self.assertRaises(VerificationError):
            parse_tree(payload)

    def test_parse_tree_rejects_truncation(self) -> None:
        with self.assertRaises(VerificationError):
            parse_tree(b"100644 file.txt\0short")

    def test_parse_tree_rejects_unsorted_entries(self) -> None:
        oid = bytes.fromhex("ab" * 20)
        payload = b"100644 z\0" + oid + b"100644 a\0" + oid
        with self.assertRaises(VerificationError):
            parse_tree(payload)

    def test_parse_commit_preserves_parent_order_and_message(self) -> None:
        raw = (
            b"tree " + b"1" * 40 + b"\n"
            b"parent " + b"2" * 40 + b"\n"
            b"parent " + b"3" * 40 + b"\n"
            b"author Test <test@example.invalid> 1 +0000\n"
            b"committer Test <test@example.invalid> 1 +0000\n\nmessage\n"
        )
        parsed = parse_commit(raw)
        self.assertEqual(parsed.parents, ("2" * 40, "3" * 40))
        self.assertEqual(parsed.message, "message\n")

    def test_parse_commit_rejects_unexpected_headers(self) -> None:
        raw = (
            b"tree " + b"1" * 40 + b"\n"
            b"author Test <test@example.invalid> 1 +0000\n"
            b"committer Test <test@example.invalid> 1 +0000\n"
            b"gpgsig nope\n\nmessage\n"
        )
        with self.assertRaises(VerificationError):
            parse_commit(raw)


class ProcessBoundaryTests(unittest.TestCase):
    def test_execute_uses_argv_without_shell_and_fresh_environment(self) -> None:
        def complete(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            kwargs["stdout"].write(b"ok")
            return subprocess.CompletedProcess(args[0], 0)

        with mock.patch("subprocess.run", side_effect=complete) as run:
            result = _execute(
                ["/usr/bin/git", "--version"],
                cwd=Path("/tmp"),
                env={"LC_ALL": "C"},
                label="version",
            )
        self.assertEqual(result.stdout, b"ok")
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["env"], {"LC_ALL": "C"})
        self.assertNotIn("executable", kwargs)

    def test_execute_converts_timeout_to_path_free_error(self) -> None:
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["git"], 1)):
            with self.assertRaisesRegex(GitTimeoutError, "git cat-file exceeded") as raised:
                _execute(
                    ["/usr/bin/git", "cat-file"],
                    cwd=REPOSITORY_ROOT,
                    env={},
                    label="cat-file",
                )
        self.assertNotIn(os.fspath(REPOSITORY_ROOT), str(raised.exception))

    def test_execute_enforces_output_limit(self) -> None:
        def overflow(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            kwargs["stdout"].write(b"x" * (MAX_OUTPUT_BYTES + 1))
            return subprocess.CompletedProcess(args[0], 0)

        with mock.patch("subprocess.run", side_effect=overflow):
            with self.assertRaises(GitOutputLimitError):
                _execute(
                    ["/usr/bin/git", "cat-file"],
                    cwd=Path("/tmp"),
                    env={},
                    label="cat-file",
                )

    def test_runner_rejects_non_allowlisted_and_remote_looking_arguments(self) -> None:
        workspace = _Workspace(
            root=Path("/tmp"),
            private=Path("/tmp"),
            home=Path("/tmp"),
            xdg=Path("/tmp"),
            tmp=Path("/tmp"),
            template=Path("/tmp"),
            repository=Path("/tmp/repo.git"),
        )
        runner = _GitRunner(Path("/usr/bin/git"), workspace)
        with self.assertRaises(ValueError):
            runner.run("fetch", "origin")
        with self.assertRaises(ValueError):
            runner.run("cat-file", "https://example.invalid/repo")

    def test_runner_sanitizes_nonzero_failure(self) -> None:
        workspace = _Workspace(
            root=Path("/tmp"),
            private=Path("/tmp/private-secret"),
            home=Path("/tmp/home"),
            xdg=Path("/tmp/xdg"),
            tmp=Path("/tmp/tmp"),
            template=Path("/tmp/template"),
            repository=Path("/tmp/private-secret/repo.git"),
        )
        runner = _GitRunner(Path("/usr/bin/git"), workspace)
        with mock.patch(
            "git_dag_lab.lab._execute",
            return_value=ProcessResult(128, b"", b"fatal: /tmp/private-secret"),
        ):
            with self.assertRaises(GitCommandError) as raised:
                runner.run("cat-file", "blob", "0" * 40)
        self.assertNotIn("private-secret", str(raised.exception))


class WorkspaceBoundaryTests(unittest.TestCase):
    def test_symlink_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT) as temporary:
            base = Path(temporary)
            real = base / "real"
            link = base / "link"
            real.mkdir()
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(LabError, "symlink"):
                run_lab(link)

    def test_symlinked_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT) as temporary:
            base = Path(temporary)
            real = base / "real"
            child = real / "child"
            link = base / "link"
            child.mkdir(parents=True)
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(LabError, "symlink"):
                run_lab(link / "child")

    def test_missing_and_file_roots_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT) as temporary:
            base = Path(temporary)
            with self.assertRaisesRegex(LabError, "does not exist"):
                run_lab(base / "missing")
            file_root = base / "file"
            file_root.write_text("not a directory", encoding="utf-8")
            with self.assertRaisesRegex(LabError, "not a directory"):
                run_lab(file_root)

    def test_nul_root_is_normalized_to_path_free_lab_error(self) -> None:
        with self.assertRaisesRegex(LabError, "isolated lab setup failed") as raised:
            run_lab("private-name\0suffix")
        self.assertNotIn("private-name", str(raised.exception))


@unittest.skipUnless(GIT_AVAILABLE, "Git is required for CLI tests")
class CliTests(unittest.TestCase):
    def test_verify_writes_one_line_and_no_stderr(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = main(
            ["verify"], root=REPOSITORY_ROOT, stdout=stdout, stderr=stderr
        )
        self.assertEqual(exit_code, 0)
        self.assertRegex(
            stdout.getvalue(),
            r"^PASS git-dag-lab/v1 objects=14 commits=5 same_tree=true "
            r"different_history=true receipt_sha256=[0-9a-f]{64}\n$",
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_inspect_compact_is_canonical_json(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = main(
            ["inspect", "--compact"],
            root=REPOSITORY_ROOT,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(exit_code, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["report"]["inventory"]["total"], 14)
        self.assertNotIn("\n", stdout.getvalue().rstrip("\n"))
        self.assertEqual(stderr.getvalue(), "")

    def test_cli_error_is_stable_and_path_free(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = main(
            ["verify"],
            root=REPOSITORY_ROOT / "missing-private-name",
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "ERROR git-dag-lab: workspace root does not exist\n",
        )
        self.assertNotIn("missing-private-name", stderr.getvalue())

    def test_module_entrypoint_matches_in_process_cli(self) -> None:
        expected = io.StringIO()
        self.assertEqual(
            main(["verify"], root=REPOSITORY_ROOT, stdout=expected, stderr=io.StringIO()),
            0,
        )
        completed = subprocess.run(
            [sys.executable, "-m", "git_dag_lab", "verify"],
            cwd=REPOSITORY_ROOT,
            env={"PATH": os.environ.get("PATH", "")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, expected.getvalue())
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
