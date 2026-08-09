from __future__ import annotations

import binascii
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zlib
from unittest import mock

from git_dag_lab import pack as pack_module
from git_dag_lab.cli import main
from git_dag_lab.lab import VerificationError, git_object_oid
from git_dag_lab.pack import (
    INDEX_MAGIC,
    INDEX_VERSION,
    MAX_PACK_BYTES,
    PACK_MAGIC,
    PACK_SCHEMA_VERSION,
    PACK_VERSION,
    parse_index,
    parse_pack,
    run_pack_lab,
)


def _entry_header(type_code: int, size: int) -> bytes:
    first = (type_code << 4) | (size & 0x0F)
    size >>= 4
    output = bytearray((first,))
    if size:
        output[0] |= 0x80
    while size:
        current = size & 0x7F
        size >>= 7
        if size:
            current |= 0x80
        output.append(current)
    return bytes(output)


def _resign_pack(prefix: bytes) -> bytes:
    return prefix + hashlib.sha1(prefix, usedforsecurity=False).digest()


def _build_pack(payloads: tuple[bytes, ...]) -> tuple[bytes, list[dict[str, int | str]]]:
    body = bytearray(PACK_MAGIC)
    body.extend(PACK_VERSION.to_bytes(4, "big"))
    body.extend(len(payloads).to_bytes(4, "big"))
    rows: list[dict[str, int | str]] = []
    for payload in payloads:
        offset = len(body)
        packed = _entry_header(3, len(payload)) + zlib.compress(payload, level=9)
        body.extend(packed)
        rows.append(
            {
                "crc32": binascii.crc32(packed) & 0xFFFFFFFF,
                "offset": offset,
                "oid": git_object_oid("blob", payload),
            }
        )
    return _resign_pack(bytes(body)), rows


def _resign_index(prefix: bytes) -> bytes:
    return prefix + hashlib.sha1(prefix, usedforsecurity=False).digest()


def _build_index(
    rows: list[dict[str, int | str]],
    pack_sha1: str,
) -> bytes:
    ordered = sorted(rows, key=lambda row: str(row["oid"]))
    counts = [0] * 256
    for row in ordered:
        counts[int(str(row["oid"])[:2], 16)] += 1
    fanout: list[int] = []
    total = 0
    for count in counts:
        total += count
        fanout.append(total)

    body = bytearray(INDEX_MAGIC)
    body.extend(INDEX_VERSION.to_bytes(4, "big"))
    for value in fanout:
        body.extend(value.to_bytes(4, "big"))
    for row in ordered:
        body.extend(bytes.fromhex(str(row["oid"])))
    for row in ordered:
        body.extend(int(row["crc32"]).to_bytes(4, "big"))
    for row in ordered:
        body.extend(int(row["offset"]).to_bytes(4, "big"))
    body.extend(bytes.fromhex(pack_sha1))
    return _resign_index(bytes(body))


class PackParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payloads = (b"fixture\n", b"\x00binary\xff\n")
        self.pack_bytes, self.rows = _build_pack(self.payloads)

    def test_decodes_real_envelopes_and_verifies_trailer(self) -> None:
        parsed = parse_pack(self.pack_bytes)
        self.assertEqual(parsed.version, PACK_VERSION)
        self.assertEqual(len(parsed.entries), 2)
        self.assertEqual(
            {entry.oid for entry in parsed.entries},
            {git_object_oid("blob", payload) for payload in self.payloads},
        )
        self.assertEqual(
            parsed.trailer_sha1,
            hashlib.sha1(self.pack_bytes[:-20], usedforsecurity=False).hexdigest(),
        )
        for entry, payload in zip(parsed.entries, self.payloads, strict=True):
            self.assertEqual(entry.object_type, "blob")
            self.assertEqual(entry.size, len(payload))
            self.assertEqual(entry.payload_sha256, hashlib.sha256(payload).hexdigest())
            self.assertGreater(entry.packed_size, 1)

    def test_rejects_non_bytes_and_outer_boundary_drift(self) -> None:
        cases = (
            bytearray(self.pack_bytes),
            b"",
            self.pack_bytes[:31],
            b"x" * (MAX_PACK_BYTES + 1),
        )
        for content in cases:
            with self.subTest(size=len(content)), self.assertRaises(VerificationError):
                parse_pack(content)  # type: ignore[arg-type]

    def test_rejects_signature_version_and_count_drift(self) -> None:
        bad_signature = b"FAIL" + self.pack_bytes[4:]
        bad_version = bytearray(self.pack_bytes)
        bad_version[4:8] = (3).to_bytes(4, "big")
        bad_count = bytearray(self.pack_bytes)
        bad_count[8:12] = (0).to_bytes(4, "big")
        for content in (
            bad_signature,
            _resign_pack(bytes(bad_version[:-20])),
            _resign_pack(bytes(bad_count[:-20])),
        ):
            with self.assertRaises(VerificationError):
                parse_pack(content)

    def test_rejects_delta_type_size_zlib_and_trailer_mutations(self) -> None:
        delta = bytearray(self.pack_bytes[:-20])
        delta[12] = (delta[12] & 0x8F) | 0x60

        wrong_size = bytearray(self.pack_bytes[:-20])
        wrong_size[12] = (wrong_size[12] & 0xF0) | ((len(self.payloads[0]) + 1) & 0x0F)

        corrupt_zlib = bytearray(self.pack_bytes[:-20])
        corrupt_zlib[14] ^= 0xFF

        bad_trailer = bytearray(self.pack_bytes)
        bad_trailer[-1] ^= 0x01

        for content in (
            _resign_pack(bytes(delta)),
            _resign_pack(bytes(wrong_size)),
            _resign_pack(bytes(corrupt_zlib)),
            bytes(bad_trailer),
        ):
            with self.assertRaises(VerificationError):
                parse_pack(content)

    def test_rejects_declared_extra_object_and_trailing_body_bytes(self) -> None:
        extra_object = bytearray(self.pack_bytes[:-20])
        extra_object[8:12] = (3).to_bytes(4, "big")
        trailing = self.pack_bytes[:-20] + b"\x00"
        for content in (
            _resign_pack(bytes(extra_object)),
            _resign_pack(trailing),
        ):
            with self.assertRaises(VerificationError):
                parse_pack(content)


class IndexParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pack_bytes, self.rows = _build_pack((b"alpha\n", b"omega\n"))
        self.pack = parse_pack(self.pack_bytes)
        self.index_bytes = _build_index(self.rows, self.pack.trailer_sha1)

    def test_decodes_fanout_rows_and_both_checksums(self) -> None:
        parsed = parse_index(self.index_bytes)
        self.assertEqual(parsed.version, INDEX_VERSION)
        self.assertEqual(parsed.pack_sha1, self.pack.trailer_sha1)
        self.assertEqual(parsed.fanout[-1], len(self.rows))
        self.assertEqual(
            tuple(entry.oid for entry in parsed.entries),
            tuple(sorted(str(row["oid"]) for row in self.rows)),
        )
        self.assertEqual(
            parsed.index_sha1,
            hashlib.sha1(self.index_bytes[:-20], usedforsecurity=False).hexdigest(),
        )
        pack_module._cross_check(self.pack, parsed)

    def test_rejects_signature_version_checksum_and_length_drift(self) -> None:
        bad_version = bytearray(self.index_bytes)
        bad_version[4:8] = (3).to_bytes(4, "big")
        bad_checksum = bytearray(self.index_bytes)
        bad_checksum[-1] ^= 0x01
        trailing = self.index_bytes[:-20] + b"\x00"
        for content in (
            b"FAIL" + self.index_bytes[4:],
            _resign_index(bytes(bad_version[:-20])),
            bytes(bad_checksum),
            _resign_index(trailing),
        ):
            with self.assertRaises(VerificationError):
                parse_index(content)

    def test_rejects_fanout_oid_and_large_offset_drift(self) -> None:
        oid_start = 8 + (256 * 4)
        wrong_oid = bytearray(self.index_bytes[:-20])
        wrong_oid[oid_start] ^= 0x01

        count = len(self.rows)
        offset_start = oid_start + (count * 20) + (count * 4)
        bad_large_offset = bytearray(self.index_bytes[:-20])
        bad_large_offset[offset_start : offset_start + 4] = (
            0x80000001
        ).to_bytes(4, "big")

        for content in (
            _resign_index(bytes(wrong_oid)),
            _resign_index(bytes(bad_large_offset)),
        ):
            with self.assertRaises(VerificationError):
                parse_index(content)

    def test_cross_check_rejects_crc_offset_inventory_and_pack_binding_drift(self) -> None:
        parsed = parse_index(self.index_bytes)

        changed_crc = bytearray(self.index_bytes[:-20])
        count = len(self.rows)
        oid_start = 8 + (256 * 4)
        crc_start = oid_start + (count * 20)
        changed_crc[crc_start + 3] ^= 0x01

        changed_offset = bytearray(self.index_bytes[:-20])
        offset_start = crc_start + (count * 4)
        changed_offset[offset_start + 3] ^= 0x01

        changed_pack = bytearray(self.index_bytes[:-20])
        changed_pack[-1] ^= 0x01

        for content in (
            _resign_index(bytes(changed_crc)),
            _resign_index(bytes(changed_offset)),
            _resign_index(bytes(changed_pack)),
        ):
            with self.assertRaises(VerificationError):
                pack_module._cross_check(self.pack, parse_index(content))
        self.assertEqual(len(parsed.entries), 2)


class PackRuntimeTests(unittest.TestCase):
    def test_real_pack_and_index_are_deterministic_and_leave_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = run_pack_lab(root)
            self.assertEqual(list(root.iterdir()), [])
            second = run_pack_lab(root)
            self.assertEqual(list(root.iterdir()), [])

        self.assertEqual(first.to_json(), second.to_json())
        report = first.document["report"]
        self.assertEqual(report["schema_version"], PACK_SCHEMA_VERSION)
        self.assertEqual(report["pack"]["version"], PACK_VERSION)
        self.assertEqual(report["index"]["version"], INDEX_VERSION)
        self.assertEqual(report["pack"]["object_count"], 3)
        self.assertEqual(report["pack"]["delta_count"], 0)
        self.assertEqual(
            report["command_trace"],
            ["init", "hash-object", "hash-object", "hash-object", "pack-objects"],
        )
        self.assertTrue(all(report["checks"].values()))
        self.assertFalse(report["scope"]["delta_entries_supported"])
        self.assertFalse(report["scope"]["authentication_claim"])

    def test_receipt_binds_the_complete_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_pack_lab(Path(temporary))
        document = result.document
        canonical = json.dumps(
            document["report"],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            document["receipt"]["sha256"],
            hashlib.sha256(canonical).hexdigest(),
        )
        self.assertEqual(json.loads(result.to_json()), document)

    def test_pack_cli_exposes_receipt_and_canonical_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = io.StringIO()
            stderr = io.StringIO()
            self.assertEqual(
                main(
                    ["pack-verify"],
                    root=root,
                    stdout=stdout,
                    stderr=stderr,
                ),
                0,
            )
            self.assertEqual(stderr.getvalue(), "")
            self.assertRegex(
                stdout.getvalue(),
                rf"^PASS {PACK_SCHEMA_VERSION} objects=3 .* receipt_sha256=[0-9a-f]{{64}}\n$",
            )

            inspect_output = io.StringIO()
            self.assertEqual(
                main(
                    ["pack-inspect", "--compact"],
                    root=root,
                    stdout=inspect_output,
                    stderr=io.StringIO(),
                ),
                0,
            )
            inspected = json.loads(inspect_output.getvalue())
            self.assertEqual(inspected["report"]["schema_version"], PACK_SCHEMA_VERSION)

    def test_pack_cli_returns_sanitized_lab_errors(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch(
            "git_dag_lab.cli.run_pack_lab",
            side_effect=VerificationError("reviewed failure"),
        ):
            self.assertEqual(
                main(
                    ["pack-verify"],
                    root=Path.cwd(),
                    stdout=stdout,
                    stderr=stderr,
                ),
                1,
            )
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "ERROR git-dag-lab: reviewed failure\n")


class PackFileBoundaryTests(unittest.TestCase):
    def test_reads_one_regular_single_link_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pack"
            path.write_bytes(b"bounded")
            self.assertEqual(
                pack_module._read_regular_file(path, label="fixture"),
                b"bounded",
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support is required")
    def test_rejects_symlink_and_hardlink_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(b"bounded")
            symlink = root / "symlink"
            symlink.symlink_to(target.name)
            hardlink = root / "hardlink"
            os.link(target, hardlink)
            for path in (symlink, target, hardlink):
                with self.subTest(path=path.name), self.assertRaises(
                    VerificationError
                ):
                    pack_module._read_regular_file(path, label="fixture")

    def test_rejects_empty_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / "empty"
            empty.write_bytes(b"")
            oversized = root / "oversized"
            with oversized.open("wb") as stream:
                stream.truncate(MAX_PACK_BYTES + 1)
            for path in (empty, oversized):
                with self.assertRaises(VerificationError):
                    pack_module._read_regular_file(path, label="fixture")


if __name__ == "__main__":
    unittest.main()
