from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import unittest

from tools import generate_ofs_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]


class OfsEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generated = evidence.build_artifacts(allow_missing_screenshot=False)
        cls.document = json.loads(cls.generated[evidence.EVIDENCE_PATH])
        cls.manifest = json.loads(cls.generated[evidence.MANIFEST_PATH])
        cls.receipt = cls.document["receipt"]["sha256"]

    def test_checked_in_generated_files_are_current(self) -> None:
        for path, expected in self.generated.items():
            with self.subTest(path=path.as_posix()):
                self.assertEqual((ROOT / path).read_bytes(), expected)

    def test_two_fresh_evidence_builds_are_byte_identical(self) -> None:
        first = evidence.build_artifacts(allow_missing_screenshot=False)
        second = evidence.build_artifacts(allow_missing_screenshot=False)
        self.assertEqual(first, second)

    def test_expected_generated_inventory_is_exact(self) -> None:
        self.assertEqual(
            set(self.generated),
            {
                evidence.EVIDENCE_PATH,
                evidence.VERIFY_PATH,
                evidence.INSPECT_PATH,
                evidence.REPORT_PATH,
                evidence.MANIFEST_PATH,
                evidence.RECONSTRUCTION_PATH,
                evidence.WORKFLOW_PATH,
                evidence.CLI_PATH,
            },
        )
        rows = {row["path"] for row in self.manifest["artifacts"]}
        self.assertEqual(
            rows,
            {
                evidence.EVIDENCE_PATH.as_posix(),
                evidence.VERIFY_PATH.as_posix(),
                evidence.INSPECT_PATH.as_posix(),
                evidence.REPORT_PATH.as_posix(),
                evidence.RECONSTRUCTION_PATH.as_posix(),
                evidence.WORKFLOW_PATH.as_posix(),
                evidence.CLI_PATH.as_posix(),
                evidence.SCREENSHOT_PATH.as_posix(),
                evidence.RENDERED_DOM_PATH.as_posix(),
                evidence.ATTESTATION_PATH.as_posix(),
            },
        )

    def test_compact_pretty_and_verify_outputs_share_one_receipt(self) -> None:
        compact = json.loads((ROOT / evidence.EVIDENCE_PATH).read_text())
        pretty = json.loads((ROOT / evidence.INSPECT_PATH).read_text())
        verify = (ROOT / evidence.VERIFY_PATH).read_text()
        self.assertEqual(compact, pretty)
        self.assertEqual(compact, self.document)
        self.assertIn(f"receipt_sha256={self.receipt}\n", verify)
        self.assertIn("objects=2", verify)
        self.assertIn("deltas=1", verify)
        report = self.document["report"]
        self.assertEqual(report["pack"]["ofs_delta_count"], 1)
        self.assertEqual(report["pack"]["ref_delta_count"], 0)
        self.assertTrue(all(report["checks"].values()))

    def test_manifest_binds_artifacts_sources_and_git_build(self) -> None:
        rows = {row["path"]: row for row in self.manifest["artifacts"]}
        for relative, row in rows.items():
            content = (ROOT / relative).read_bytes()
            self.assertEqual(row["size"], len(content))
            self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())
        sources = {row["path"]: row for row in self.manifest["sources"]}
        self.assertEqual(
            set(sources),
            {
                "git_dag_lab/__init__.py",
                "git_dag_lab/__main__.py",
                "git_dag_lab/cli.py",
                "git_dag_lab/lab.py",
                "git_dag_lab/pack.py",
                "tools/generate_evidence.py",
                "tools/generate_pack_evidence.py",
                "tools/generate_ofs_evidence.py",
                "tools/capture_ofs_report.sh",
            },
        )
        for relative, row in sources.items():
            content = (ROOT / relative).read_bytes()
            self.assertEqual(row["size"], len(content))
            self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())
        git_build = self.manifest["git_build"]
        self.assertRegex(git_build["version"], r"^git version [0-9]+(?:\.[0-9]+){1,3}$")
        self.assertRegex(git_build["frontend_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(git_build["pack_objects_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            git_build["byte_identity_scope"],
            "same recorded Git build",
        )

    def test_browser_capture_and_attestation_are_current(self) -> None:
        screenshot = (ROOT / evidence.SCREENSHOT_PATH).read_bytes()
        rendered_dom = (ROOT / evidence.RENDERED_DOM_PATH).read_bytes()
        attestation_bytes = (ROOT / evidence.ATTESTATION_PATH).read_bytes()
        self.assertEqual(
            evidence._parse_pack_png(screenshot),
            evidence.PNG_DIMENSIONS,
        )
        capture = self.manifest["capture"]
        self.assertEqual(capture["status"], "attested")
        self.assertEqual(capture["screenshot_sha256"], hashlib.sha256(screenshot).hexdigest())
        self.assertEqual(
            capture["rendered_dom_sha256"],
            hashlib.sha256(rendered_dom).hexdigest(),
        )
        attestation = json.loads(attestation_bytes)
        payload = attestation["attestation"]
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            attestation["receipt"]["sha256"],
            hashlib.sha256(canonical).hexdigest(),
        )
        self.assertEqual(
            capture["attestation_receipt_sha256"],
            attestation["receipt"]["sha256"],
        )
        self.assertEqual(payload["isolation"]["network"], "none")
        self.assertEqual(payload["isolation"]["root_filesystem"], "read-only")
        self.assertTrue(payload["isolation"]["no_new_privileges"])

    def test_svg_visuals_are_accessible_receipt_bound_and_factual(self) -> None:
        report = self.document["report"]
        full, delta = report["objects_in_pack_order"]
        for path in (
            evidence.RECONSTRUCTION_PATH,
            evidence.WORKFLOW_PATH,
            evidence.CLI_PATH,
        ):
            text = (ROOT / path).read_text()
            with self.subTest(path=path.as_posix()):
                self.assertIn("<title", text)
                self.assertIn("<desc", text)
                self.assertIn('role="img"', text)
                self.assertIn(self.receipt, text)
                self.assertNotIn("/home/", text)
        reconstruction = (ROOT / evidence.RECONSTRUCTION_PATH).read_text()
        self.assertIn(full["oid"], reconstruction)
        self.assertIn(delta["oid"], reconstruction)
        self.assertIn(str(delta["ofs_distance"]), reconstruction)
        workflow = (ROOT / evidence.WORKFLOW_PATH).read_text()
        self.assertIn(report["pack_objects"]["stdin_sha256"], workflow)
        self.assertIn(self.manifest["git_build"]["frontend_sha256"], workflow)
        cli = (ROOT / evidence.CLI_PATH).read_text()
        self.assertIn(report["pack"]["trailer_sha1"], cli)

    def test_offline_report_has_no_executable_or_external_content(self) -> None:
        report = (ROOT / evidence.REPORT_PATH).read_text()
        self.assertNotIn("<script", report.lower())
        self.assertIn("default-src 'none'", report)
        self.assertNotRegex(
            report.replace("http://www.w3.org/2000/svg", ""),
            r"https?://",
        )
        self.assertIn(f'data-ofs-receipt="{self.receipt}"', report)
        self.assertIn('data-object-count="2"', report)
        self.assertIn('data-check-count="12"', report)
        self.assertIn("actual OFS_DELTA", report)
        self.assertIn("Base → target", report)

    def test_document_validator_rejects_claim_and_integrity_drift(self) -> None:
        verify = (ROOT / evidence.VERIFY_PATH).read_bytes()
        mutations = []

        changed_count = deepcopy(self.document)
        changed_count["report"]["pack"]["delta_count"] = 0
        mutations.append(changed_count)

        changed_distance = deepcopy(self.document)
        changed_distance["report"]["objects_in_pack_order"][1]["ofs_distance"] += 1
        mutations.append(changed_distance)

        changed_command = deepcopy(self.document)
        changed_command["report"]["pack_objects"]["normalized_argv"][2] = "--window=99"
        mutations.append(changed_command)

        changed_scope = deepcopy(self.document)
        changed_scope["report"]["scope"]["authentication_claim"] = True
        mutations.append(changed_scope)

        for mutation in mutations:
            with self.assertRaises(evidence.EvidenceError):
                evidence._validate_document(mutation, verify)

    def test_public_evidence_has_no_host_secret_or_personal_markers(self) -> None:
        text_paths = [
            evidence.EVIDENCE_PATH,
            evidence.VERIFY_PATH,
            evidence.INSPECT_PATH,
            evidence.REPORT_PATH,
            evidence.MANIFEST_PATH,
            evidence.RENDERED_DOM_PATH,
            evidence.ATTESTATION_PATH,
            evidence.RECONSTRUCTION_PATH,
            evidence.WORKFLOW_PATH,
            evidence.CLI_PATH,
        ]
        combined = "\n".join((ROOT / path).read_text() for path in text_paths)
        for marker in (
            "/home/",
            "@gmail.com",
            "github.com/",
            "AKIA",
            "ghp_",
            "github_pat_",
            "Omar Ibrahim",
        ):
            self.assertNotIn(marker.lower(), combined.lower())

    def test_readme_exposes_the_real_ofs_workflow_and_visuals(self) -> None:
        readme = (ROOT / "README.md").read_text()
        for path in (
            evidence.EVIDENCE_PATH,
            evidence.SCREENSHOT_PATH,
            evidence.RECONSTRUCTION_PATH,
            evidence.WORKFLOW_PATH,
            evidence.CLI_PATH,
            evidence.MANIFEST_PATH,
        ):
            self.assertIn(path.as_posix(), readme)
        self.assertIn("python3 -m git_dag_lab pack-ofs-verify", readme)
        self.assertIn("python3 -m git_dag_lab pack-ofs-inspect", readme)
        self.assertIn("python3 -B tools/generate_ofs_evidence.py --check", readme)
        self.assertIn("tools/capture_ofs_report.sh", readme)
        self.assertIn("12/12 OFS checks", readme)

    def test_capture_toolchain_is_digest_pinned_and_network_disabled(self) -> None:
        script = (ROOT / "tools/capture_ofs_report.sh").read_text()
        self.assertRegex(
            script,
            r"mcr\.microsoft\.com/playwright@sha256:[0-9a-f]{64}",
        )
        self.assertIn("--network none", script)
        self.assertIn("--pull=never", script)
        self.assertIn("--read-only", script)
        self.assertIn("--cap-drop ALL", script)
        self.assertIn("--security-opt no-new-privileges", script)
        self.assertIn(
            'chmod 0600 "$temporary_root/output/git-pack-ofs-report.png"',
            script,
        )
        self.assertNotRegex(script, re.compile(r"(?m)^\s*curl\b|\bwget\b"))


if __name__ == "__main__":
    unittest.main()
