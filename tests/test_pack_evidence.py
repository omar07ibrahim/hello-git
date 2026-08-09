from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import unittest

from tools import generate_pack_evidence as evidence

ROOT = Path(__file__).resolve().parents[1]


class PackEvidenceTests(unittest.TestCase):
    def test_expected_generated_inventory_is_exact(self) -> None:
        generated = evidence.build_artifacts(allow_missing_screenshot=False)
        self.assertEqual(
            set(generated),
            {
                evidence.EVIDENCE_PATH,
                evidence.VERIFY_PATH,
                evidence.INSPECT_PATH,
                evidence.REPORT_PATH,
                evidence.MANIFEST_PATH,
                evidence.LAYOUT_PATH,
                evidence.FANOUT_PATH,
                evidence.INTEGRITY_PATH,
                evidence.CLI_PATH,
            },
        )

    def test_checked_in_generated_files_are_current(self) -> None:
        generated = evidence.build_artifacts(allow_missing_screenshot=False)
        for path, expected in generated.items():
            with self.subTest(path=path.as_posix()):
                self.assertEqual((ROOT / path).read_bytes(), expected)

    def test_compact_pretty_and_verify_outputs_share_one_receipt(self) -> None:
        compact = json.loads((ROOT / evidence.EVIDENCE_PATH).read_text())
        pretty = json.loads((ROOT / evidence.INSPECT_PATH).read_text())
        verify = (ROOT / evidence.VERIFY_PATH).read_text()
        self.assertEqual(compact, pretty)
        self.assertIn(
            f"receipt_sha256={compact['receipt']['sha256']}",
            verify,
        )
        canonical = json.dumps(
            compact,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        self.assertEqual((ROOT / evidence.EVIDENCE_PATH).read_bytes(), canonical)

    def test_two_fresh_evidence_builds_are_byte_identical(self) -> None:
        first = evidence.build_artifacts(allow_missing_screenshot=False)
        second = evidence.build_artifacts(allow_missing_screenshot=False)
        self.assertEqual(first, second)

    def test_manifest_binds_artifacts_capture_and_sources(self) -> None:
        manifest = json.loads((ROOT / evidence.MANIFEST_PATH).read_text())
        rows = {row["path"]: row for row in manifest["artifacts"]}
        expected = {
            evidence.EVIDENCE_PATH,
            evidence.VERIFY_PATH,
            evidence.INSPECT_PATH,
            evidence.REPORT_PATH,
            evidence.LAYOUT_PATH,
            evidence.FANOUT_PATH,
            evidence.INTEGRITY_PATH,
            evidence.CLI_PATH,
            evidence.SCREENSHOT_PATH,
            evidence.RENDERED_DOM_PATH,
            evidence.ATTESTATION_PATH,
        }
        self.assertEqual(set(rows), {path.as_posix() for path in expected})
        for path in expected:
            content = (ROOT / path).read_bytes()
            row = rows[path.as_posix()]
            self.assertEqual(row["size"], len(content))
            self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(manifest["capture"]["status"], "attested")
        sources = {row["path"]: row for row in manifest["sources"]}
        self.assertEqual(
            set(sources),
            {
                "git_dag_lab/pack.py",
                "git_dag_lab/cli.py",
                "tools/generate_evidence.py",
                "tools/generate_pack_evidence.py",
                "tools/capture_pack_report.sh",
            },
        )
        for relative, row in sources.items():
            content = (ROOT / relative).read_bytes()
            self.assertEqual(row["size"], len(content))
            self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())

    def test_svg_visuals_are_accessible_and_receipt_bound(self) -> None:
        document = json.loads((ROOT / evidence.EVIDENCE_PATH).read_text())
        receipt = document["receipt"]["sha256"]
        for path in (
            evidence.LAYOUT_PATH,
            evidence.FANOUT_PATH,
            evidence.INTEGRITY_PATH,
            evidence.CLI_PATH,
        ):
            text = (ROOT / path).read_text()
            with self.subTest(path=path.as_posix()):
                self.assertIn("<title", text)
                self.assertIn("<desc", text)
                self.assertIn('role="img"', text)
                self.assertIn(receipt, text)
                metadata = json.loads(
                    text.split("<metadata>", 1)[1].split("</metadata>", 1)[0]
                )
                self.assertEqual(
                    metadata["source"],
                    evidence.EVIDENCE_PATH.as_posix(),
                )
                self.assertEqual(metadata["report_receipt_sha256"], receipt)
                self.assertNotIn("/home/", text)
                self.assertNotIn("github.com/", text)

    def test_offline_report_has_no_executable_or_external_content(self) -> None:
        report = (ROOT / evidence.REPORT_PATH).read_text()
        self.assertNotIn("<script", report.lower())
        self.assertNotIn("http://", report)
        self.assertNotIn("https://", report)
        self.assertIn("Pack v2.", report)
        self.assertIn("Index v2.", report)
        self.assertIn('data-object-count="3"', report)
        self.assertIn('data-check-count="7"', report)

    def test_browser_capture_and_attestation_are_current(self) -> None:
        screenshot = (ROOT / evidence.SCREENSHOT_PATH).read_bytes()
        self.assertEqual(evidence._parse_pack_png(screenshot), evidence.PNG_DIMENSIONS)
        attestation = json.loads((ROOT / evidence.ATTESTATION_PATH).read_text())
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
        self.assertEqual(payload["isolation"]["network"], "none")
        self.assertEqual(
            payload["input"]["report"]["report_receipt_sha256"],
            json.loads((ROOT / evidence.EVIDENCE_PATH).read_text())["receipt"][
                "sha256"
            ],
        )

    def test_public_pack_evidence_has_no_host_or_secret_markers(self) -> None:
        paths = (
            evidence.EVIDENCE_PATH,
            evidence.VERIFY_PATH,
            evidence.INSPECT_PATH,
            evidence.REPORT_PATH,
            evidence.MANIFEST_PATH,
            evidence.RENDERED_DOM_PATH,
            evidence.ATTESTATION_PATH,
            evidence.LAYOUT_PATH,
            evidence.FANOUT_PATH,
            evidence.INTEGRITY_PATH,
            evidence.CLI_PATH,
        )
        forbidden = (
            "/home/",
            "@gmail.com",
            "AKIA",
            "ghp_",
            "github_pat_",
            "OPENAI_API_KEY",
        )
        for path in paths:
            text = (ROOT / path).read_text(errors="strict")
            with self.subTest(path=path.as_posix()):
                for marker in forbidden:
                    self.assertNotIn(marker.lower(), text.lower())

    def test_document_validator_rejects_claim_and_integrity_drift(self) -> None:
        document = json.loads((ROOT / evidence.EVIDENCE_PATH).read_text())
        verify = (ROOT / evidence.VERIFY_PATH).read_bytes()
        mutations = []

        missing_check = deepcopy(document)
        del missing_check["report"]["checks"]["pack_trailer_verified"]
        mutations.append(missing_check)

        delta_claim = deepcopy(document)
        delta_claim["report"]["scope"]["delta_entries_supported"] = True
        mutations.append(delta_claim)

        authentication_claim = deepcopy(document)
        authentication_claim["report"]["scope"]["authentication_claim"] = True
        mutations.append(authentication_claim)

        changed_crc = deepcopy(document)
        changed_crc["report"]["objects_in_pack_order"][0]["index_crc32"] = "00000000"
        mutations.append(changed_crc)

        for mutation in mutations:
            with self.assertRaises(evidence.EvidenceError):
                evidence._validate_document(mutation, verify)

    def test_readme_exposes_real_pack_workflow_and_visuals(self) -> None:
        readme = (ROOT / "README.md").read_text()
        for path in (
            evidence.SCREENSHOT_PATH,
            evidence.LAYOUT_PATH,
            evidence.FANOUT_PATH,
            evidence.INTEGRITY_PATH,
            evidence.CLI_PATH,
        ):
            self.assertIn(path.as_posix(), readme)
        self.assertIn("python3 -m git_dag_lab pack-verify", readme)
        self.assertIn("python3 -m git_dag_lab pack-inspect", readme)
        self.assertIn("Delta", readme)
        self.assertRegex(readme, r"\*\*[0-9]+ tests\*\*")

    def test_capture_toolchain_is_digest_pinned_and_network_disabled(self) -> None:
        script = (ROOT / "tools/capture_pack_report.sh").read_text()
        self.assertRegex(script, r"mcr\.microsoft\.com/playwright@sha256:[0-9a-f]{64}")
        self.assertIn("--network none", script)
        self.assertIn("--pull=never", script)
        self.assertIn("--read-only", script)
        self.assertNotRegex(script, re.compile(r"(?m)^\s*curl\b|\bwget\b"))


if __name__ == "__main__":
    unittest.main()
