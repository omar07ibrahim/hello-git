from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
import re
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from tools import generate_evidence


ROOT = Path(__file__).resolve().parents[1]


class EvidencePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generated = generate_evidence.build_artifacts(
            allow_missing_screenshot=False
        )
        cls.evidence = json.loads(cls.generated[generate_evidence.EVIDENCE_PATH])
        cls.manifest = json.loads(cls.generated[generate_evidence.MANIFEST_PATH])
        cls.receipt = cls.evidence["receipt"]["sha256"]

    def test_expected_generated_inventory_is_exact(self) -> None:
        self.assertEqual(
            set(self.generated),
            {
                generate_evidence.EVIDENCE_PATH,
                generate_evidence.VERIFY_PATH,
                generate_evidence.INSPECT_PATH,
                generate_evidence.REPORT_PATH,
                generate_evidence.MANIFEST_PATH,
                generate_evidence.TOPOLOGY_PATH,
                generate_evidence.ENVELOPE_PATH,
                generate_evidence.CLI_PATH,
                generate_evidence.PIPELINE_PATH,
            },
        )

    def test_checked_in_generated_files_are_current(self) -> None:
        for path, expected in self.generated.items():
            with self.subTest(path=path.as_posix()):
                self.assertEqual((ROOT / path).read_bytes(), expected)

    def test_two_fresh_builds_are_byte_identical(self) -> None:
        second = generate_evidence.build_artifacts(allow_missing_screenshot=False)
        self.assertEqual(self.generated, second)

    def test_compact_evidence_and_pretty_transcript_match(self) -> None:
        pretty = json.loads(self.generated[generate_evidence.INSPECT_PATH])
        self.assertEqual(self.evidence, pretty)
        compact_lines = self.generated[generate_evidence.EVIDENCE_PATH].splitlines()
        self.assertEqual(len(compact_lines), 1)

    def test_verify_transcript_is_bound_to_report_receipt(self) -> None:
        transcript = self.generated[generate_evidence.VERIFY_PATH].decode("utf-8")
        self.assertRegex(
            transcript,
            r"^PASS git-dag-lab/v1 objects=14 commits=5 same_tree=true "
            r"different_history=true receipt_sha256=[0-9a-f]{64}\n$",
        )
        self.assertIn(self.receipt, transcript)
        cli_visual = self.generated[generate_evidence.CLI_PATH].decode("utf-8")
        self.assertIn("python3 -B -m git_dag_lab verify", cli_visual)

    def test_manifest_binds_every_generated_artifact(self) -> None:
        rows = {row["path"]: row for row in self.manifest["artifacts"]}
        self.assertNotIn(generate_evidence.MANIFEST_PATH.as_posix(), rows)
        for path, content in self.generated.items():
            if path == generate_evidence.MANIFEST_PATH:
                continue
            with self.subTest(path=path.as_posix()):
                row = rows[path.as_posix()]
                self.assertEqual(row["size"], len(content))
                self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())

    def test_manifest_binds_real_browser_capture(self) -> None:
        rows = {row["path"]: row for row in self.manifest["artifacts"]}
        for path in (
            generate_evidence.SCREENSHOT_PATH,
            generate_evidence.RENDERED_DOM_PATH,
            generate_evidence.ATTESTATION_PATH,
        ):
            content = (ROOT / path).read_bytes()
            row = rows[path.as_posix()]
            self.assertEqual(row["size"], len(content))
            self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())
        screenshot_row = rows[generate_evidence.SCREENSHOT_PATH.as_posix()]
        self.assertEqual(
            self.manifest["capture"]["screenshot_sha256"], screenshot_row["sha256"]
        )
        attestation = json.loads((ROOT / generate_evidence.ATTESTATION_PATH).read_bytes())
        self.assertEqual(
            self.manifest["capture"]["attestation_receipt_sha256"],
            attestation["receipt"]["sha256"],
        )
        self.assertEqual(self.manifest["capture"]["status"], "attested")

    def test_browser_capture_is_expected_png_size(self) -> None:
        content = (ROOT / generate_evidence.SCREENSHOT_PATH).read_bytes()
        self.assertEqual(
            generate_evidence._parse_png(content),
            generate_evidence.PNG_DIMENSIONS,
        )

    def test_png_parser_rejects_structural_spoofs(self) -> None:
        valid = (ROOT / generate_evidence.SCREENSHOT_PATH).read_bytes()

        def chunk(kind: bytes, payload: bytes) -> bytes:
            checksum = zlib.crc32(kind + payload) & 0xFFFFFFFF
            return (
                struct.pack(">I", len(payload))
                + kind
                + payload
                + struct.pack(">I", checksum)
            )

        ihdr = struct.pack(
            ">IIBBBBB",
            *generate_evidence.PNG_DIMENSIONS,
            8,
            2,
            0,
            0,
            0,
        )
        undecodable_spoof = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", b"not-a-zlib-stream")
            + chunk(b"IEND", b"")
        )
        minimal_spoof = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13)
            + b"IHDR"
            + struct.pack(">II", *generate_evidence.PNG_DIMENSIONS)
            + b"\x08\x06\x00\x00\x00"
            + b"\x00\x00\x00\x00"
        )
        corrupt_crc = valid[:-1] + bytes((valid[-1] ^ 1,))
        trailing_bytes = valid + b"not-png"
        for candidate in (
            undecodable_spoof,
            minimal_spoof,
            corrupt_crc,
            trailing_bytes,
        ):
            with self.subTest(size=len(candidate)):
                with self.assertRaises(generate_evidence.EvidenceError):
                    generate_evidence._validate_png(candidate)

    def test_capture_toolchain_is_digest_pinned(self) -> None:
        capture = self.manifest["capture"]
        self.assertRegex(capture["container_image"], r"@sha256:[0-9a-f]{64}$")
        self.assertRegex(capture["browser_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(capture["network"], "none")
        self.assertEqual(capture["viewport"], {"height": 1800, "width": 1440})
        script = (ROOT / "tools/capture_report.sh").read_text()
        self.assertIn(
            'chmod 0600 "$temporary_root/output/git-dag-report.png"',
            script,
        )
        self.assertIn('chmod 0600 "$dom_path"', script)
        self.assertIn("os.chmod(temporary_path, 0o600)", script)
        self.assertNotIn("chmod 0644", script)

    def test_sources_are_hashed_and_path_relative(self) -> None:
        for source in self.manifest["sources"]:
            path = Path(source["path"])
            self.assertFalse(path.is_absolute())
            content = (ROOT / path).read_bytes()
            self.assertEqual(source["size"], len(content))
            self.assertEqual(source["sha256"], hashlib.sha256(content).hexdigest())

    def test_svg_assets_are_accessible_and_receipt_bound(self) -> None:
        for path in (
            generate_evidence.TOPOLOGY_PATH,
            generate_evidence.ENVELOPE_PATH,
            generate_evidence.CLI_PATH,
            generate_evidence.PIPELINE_PATH,
        ):
            with self.subTest(path=path.as_posix()):
                text = self.generated[path].decode("utf-8")
                self.assertIn('role="img"', text)
                self.assertIn("<title", text)
                self.assertIn("<desc", text)
                self.assertIn(self.receipt, text)
                self.assertNotIn("https://", text)
                self.assertNotIn("/home/", text)
        pipeline = self.generated[generate_evidence.PIPELINE_PATH].decode("utf-8")
        self.assertIn(
            self.manifest["capture"]["attestation_receipt_sha256"], pipeline
        )
        self.assertIn(self.manifest["capture"]["screenshot_sha256"], pipeline)

    def test_topology_visual_contains_every_actual_commit_oid(self) -> None:
        topology = self.generated[generate_evidence.TOPOLOGY_PATH].decode("utf-8")
        for node in self.evidence["report"]["graph"]["nodes"]:
            self.assertIn(node["oid"], topology)

    def test_envelope_visual_uses_actual_proof(self) -> None:
        visual = self.generated[generate_evidence.ENVELOPE_PATH].decode("utf-8")
        proof = self.evidence["report"]["proofs"]["object_envelope"]
        self.assertIn(proof["envelope_sha1"], visual)
        for line in proof["payload_utf8"].splitlines():
            self.assertIn(html.escape(line, quote=False), visual)

    def test_offline_report_has_no_executable_or_external_content(self) -> None:
        report = self.generated[generate_evidence.REPORT_PATH].decode("utf-8")
        self.assertIn("default-src 'none'", report)
        self.assertIn(self.receipt, report)
        self.assertIn('data-object-count="14"', report)
        self.assertIn('data-check-count="9"', report)
        self.assertNotIn("<script", report.lower())
        self.assertIsNone(re.search(r"https?://", report))

    def test_public_evidence_has_no_host_or_personal_markers(self) -> None:
        external = [
            (ROOT / generate_evidence.RENDERED_DOM_PATH).read_bytes(),
            (ROOT / generate_evidence.ATTESTATION_PATH).read_bytes(),
        ]
        combined = b"\n".join([*self.generated.values(), *external]).decode("utf-8")
        for marker in (
            "/home/",
            "@gmail.com",
            "github.com/",
            "AKIA",
            "ghp_",
            "github_pat_",
        ):
            self.assertNotIn(marker.lower(), combined.lower())

    def test_sha1_nonclaim_is_visible(self) -> None:
        report = self.generated[generate_evidence.REPORT_PATH].decode("utf-8")
        self.assertIn("not authentication or a signature", report)

    def test_readme_baseline_matches_current_evidence(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        test_count = unittest.defaultTestLoader.discover(
            str(ROOT / "tests")
        ).countTestCases()
        screenshot_sha = self.manifest["capture"]["screenshot_sha256"]
        receipt_label = f"{self.receipt[:8]}…{self.receipt[-5:]}"
        screenshot_label = f"{screenshot_sha[:8]}…{screenshot_sha[-4:]}"
        self.assertIn(f"**{test_count} tests**", readme)
        self.assertIn("**9/9 graph invariants**", readme)
        self.assertIn("**57 isolated Git invocations**", readme)
        self.assertIn(f"report receipt `{receipt_label}`", readme)
        self.assertIn(f"screenshot SHA-256 `{screenshot_label}`", readme)
        self.assertIn("11 local subcommands are allow-listed", readme)


    def test_writer_keeps_generated_files_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            root = Path(temporary_root)
            with patch.object(generate_evidence, "ROOT", root):
                generate_evidence._write_artifacts(
                    {Path("nested/evidence.txt"): b"public synthetic evidence\n"}
                )
            target = root / "nested/evidence.txt"
            self.assertEqual(target.read_bytes(), b"public synthetic evidence\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
