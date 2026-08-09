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
    MAX_DELTA_DEPTH,
    MAX_DELTA_INSTRUCTIONS,
    MAX_OBJECT_BYTES,
    MAX_PACK_BYTES,
    MAX_TOTAL_EXPANDED_BYTES,
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


def _delta_size(value: int) -> bytes:
    output = bytearray()
    while True:
        current = value & 0x7F
        value >>= 7
        if value:
            current |= 0x80
        output.append(current)
        if not value:
            return bytes(output)


def _ofs_distance(distance: int) -> bytes:
    output = bytearray((distance & 0x7F,))
    while distance >> 7:
        distance = (distance >> 7) - 1
        output.append(0x80 | (distance & 0x7F))
    output.reverse()
    return bytes(output)


def _copy_instruction(*, offset: int = 0, size: int) -> bytes:
    command = 0x80
    parameters = bytearray()
    for bit, shift in ((0x01, 0), (0x02, 8), (0x04, 16), (0x08, 24)):
        value = (offset >> shift) & 0xFF
        if value:
            command |= bit
            parameters.append(value)
    if size != 0x10000:
        for bit, shift in ((0x10, 0), (0x20, 8), (0x40, 16)):
            value = (size >> shift) & 0xFF
            if value:
                command |= bit
                parameters.append(value)
    return bytes((command,)) + bytes(parameters)


def _program(base_size: int, result_size: int, instructions: bytes) -> bytes:
    return _delta_size(base_size) + _delta_size(result_size) + instructions


def _build_ofs_pack(
    base_payload: bytes,
    deltas: tuple[tuple[int, bytes], ...],
) -> tuple[bytes, tuple[int, ...]]:
    body = bytearray(PACK_MAGIC)
    body.extend(PACK_VERSION.to_bytes(4, "big"))
    body.extend((1 + len(deltas)).to_bytes(4, "big"))
    offsets = [len(body)]
    body.extend(_entry_header(3, len(base_payload)))
    body.extend(zlib.compress(base_payload, level=9))
    for base_index, program in deltas:
        entry_offset = len(body)
        distance = entry_offset - offsets[base_index]
        body.extend(_entry_header(6, len(program)))
        body.extend(_ofs_distance(distance))
        body.extend(zlib.compress(program, level=9))
        offsets.append(entry_offset)
    return _resign_pack(bytes(body)), tuple(offsets)


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

    def test_ofs_codec_matches_independent_git_vectors(self) -> None:
        vectors = (
            (1, "01"),
            (127, "7f"),
            (128, "8000"),
            (129, "8001"),
            (255, "807f"),
            (256, "8100"),
            (16_511, "ff7f"),
            (16_512, "808000"),
            (1_048_576, "beff00"),
        )
        for distance, expected_hex in vectors:
            encoded = bytes.fromhex(expected_hex)
            self.assertEqual(pack_module._encode_ofs_distance(distance), encoded)
            decoded, consumed = pack_module._decode_ofs_base_offset(
                encoded,
                0,
                end=len(encoded),
                entry_offset=distance + 12,
            )
            self.assertEqual(decoded, 12)
            self.assertEqual(consumed, len(encoded))

        for malformed in (b"\x00", b"\x80", b"\x80\x80\x80\x00"):
            with self.subTest(encoded=malformed.hex()), self.assertRaises(
                VerificationError
            ):
                pack_module._decode_ofs_base_offset(
                    malformed,
                    0,
                    end=len(malformed),
                    entry_offset=128,
                )

    def test_delta_size_codec_matches_independent_git_vectors(self) -> None:
        vectors = (
            (0, "00"),
            (127, "7f"),
            (128, "8001"),
            (16_383, "ff7f"),
            (16_384, "808001"),
            (262_144, "808010"),
        )
        for value, expected_hex in vectors:
            encoded = bytes.fromhex(expected_hex)
            self.assertEqual(pack_module._encode_delta_size(value), encoded)
            decoded, consumed = pack_module._decode_delta_size(
                encoded,
                0,
                label="fixture size",
            )
            self.assertEqual(decoded, value)
            self.assertEqual(consumed, len(encoded))

        for malformed in (b"\x80", b"\x80\x00", b"\x80\x80\x80\x00"):
            with self.subTest(encoded=malformed.hex()), self.assertRaises(
                VerificationError
            ):
                pack_module._decode_delta_size(
                    malformed,
                    0,
                    label="fixture size",
                )

    def test_decodes_bounded_ofs_delta_copy_and_insert(self) -> None:
        base = b"bounded base\n"
        target = base + b"delta\n"
        program = _program(
            len(base),
            len(target),
            _copy_instruction(size=len(base)) + bytes((6,)) + b"delta\n",
        )
        content, offsets = _build_ofs_pack(base, ((0, program),))

        parsed = parse_pack(content)

        self.assertEqual(len(parsed.entries), 2)
        delta = parsed.entries[1]
        self.assertEqual(delta.representation, "ofs-delta")
        self.assertEqual(delta.base_offset, offsets[0])
        self.assertEqual(delta.base_oid, parsed.entries[0].oid)
        self.assertEqual(delta.delta_depth, 1)
        self.assertEqual(delta.object_type, "blob")
        self.assertEqual(delta.size, len(target))
        self.assertEqual(delta.stored_size, len(program))
        self.assertEqual(delta.oid, git_object_oid("blob", target))
        self.assertEqual(delta.payload_sha256, hashlib.sha256(target).hexdigest())

    def test_resolves_two_deltas_that_share_one_base(self) -> None:
        base = b"shared base\n"
        first_target = base + b"one\n"
        second_target = base + b"two\n"
        first_program = _program(
            len(base),
            len(first_target),
            _copy_instruction(size=len(base)) + b"\x04one\n",
        )
        second_program = _program(
            len(base),
            len(second_target),
            _copy_instruction(size=len(base)) + b"\x04two\n",
        )
        content, offsets = _build_ofs_pack(
            base,
            ((0, first_program), (0, second_program)),
        )

        parsed = parse_pack(content)

        self.assertEqual(len(parsed.entries), 3)
        self.assertEqual(parsed.entries[1].base_offset, offsets[0])
        self.assertEqual(parsed.entries[2].base_offset, offsets[0])
        self.assertEqual(parsed.entries[1].delta_depth, 1)
        self.assertEqual(parsed.entries[2].delta_depth, 1)
        self.assertEqual(parsed.entries[1].oid, git_object_oid("blob", first_target))
        self.assertEqual(parsed.entries[2].oid, git_object_oid("blob", second_target))

    def test_decodes_the_default_64k_copy_size(self) -> None:
        base = b"a" * 0x10000
        target = base + b"!"
        program = _program(
            len(base),
            len(target),
            _copy_instruction(size=0x10000) + b"\x01!",
        )
        content, _ = _build_ofs_pack(base, ((0, program),))

        parsed = parse_pack(content)

        self.assertEqual(parsed.entries[1].size, len(target))
        self.assertEqual(parsed.entries[1].oid, git_object_oid("blob", target))

    def test_rejects_ref_delta_even_when_its_base_is_present(self) -> None:
        base = b"base\n"
        target = base + b"ref\n"
        program = _program(
            len(base),
            len(target),
            _copy_instruction(size=len(base)) + b"\x04ref\n",
        )
        body = bytearray(PACK_MAGIC)
        body.extend(PACK_VERSION.to_bytes(4, "big"))
        body.extend((2).to_bytes(4, "big"))
        body.extend(_entry_header(3, len(base)))
        body.extend(zlib.compress(base, level=9))
        body.extend(_entry_header(7, len(program)))
        body.extend(bytes.fromhex(git_object_oid("blob", base)))
        body.extend(zlib.compress(program, level=9))

        with self.assertRaisesRegex(VerificationError, "REF_DELTA"):
            parse_pack(_resign_pack(bytes(body)))

    def test_rejects_zero_middle_and_underflow_ofs_offsets(self) -> None:
        base = b"base\n"
        target = base + b"x"
        program = _program(
            len(base),
            len(target),
            _copy_instruction(size=len(base)) + b"\x01x",
        )
        valid, offsets = _build_ofs_pack(base, ((0, program),))
        header_size = len(_entry_header(6, len(program)))
        offset_position = offsets[1] + header_size
        distances = (
            b"\x00",
            _ofs_distance(offsets[1] - (offsets[0] + 1)),
            _ofs_distance(offsets[1] - 11),
        )
        for distance in distances:
            self.assertEqual(len(distance), 1)
            changed = bytearray(valid[:-20])
            changed[offset_position] = distance[0]
            with self.subTest(distance=distance.hex()), self.assertRaises(
                VerificationError
            ):
                parse_pack(_resign_pack(bytes(changed)))

    def test_rejects_malformed_delta_programs(self) -> None:
        base = b"base"
        cases = (
            _program(len(base) + 1, 0, b""),
            _program(len(base), MAX_OBJECT_BYTES + 1, b""),
            _program(len(base), 1, b"\x00"),
            _program(len(base), 2, b"\x02x"),
            _program(
                len(base),
                1,
                _copy_instruction(offset=len(base), size=1),
            ),
            _program(len(base), 2, b"\x01x"),
            _program(len(base), 1, b"\x02xy"),
            b"\x00\x00\x00",
            b"\x80" * 6,
        )
        for program in cases:
            with self.subTest(program=program.hex()), self.assertRaises(
                VerificationError
            ):
                pack_module._apply_delta(base, program)

    def test_enforces_depth_instruction_and_aggregate_budgets(self) -> None:
        base = b"a"
        previous = base
        deltas: list[tuple[int, bytes]] = []
        for depth in range(MAX_DELTA_DEPTH + 1):
            target = previous + b"x"
            deltas.append(
                (
                    depth,
                    _program(
                        len(previous),
                        len(target),
                        _copy_instruction(size=len(previous)) + b"\x01x",
                    ),
                )
            )
            previous = target
        too_deep, _ = _build_ofs_pack(base, tuple(deltas))
        with self.assertRaisesRegex(VerificationError, "depth"):
            parse_pack(too_deep)

        two_inserts = _program(len(base), 2, b"\x01x\x01y")
        with (
            mock.patch.object(pack_module, "MAX_DELTA_INSTRUCTIONS", 1),
            self.assertRaisesRegex(VerificationError, "instruction"),
        ):
            pack_module._apply_delta(base, two_inserts)
        self.assertEqual(MAX_DELTA_INSTRUCTIONS, 4_096)

        target = base + b"x"
        bounded, _ = _build_ofs_pack(
            base,
            (
                (
                    0,
                    _program(
                        len(base),
                        len(target),
                        _copy_instruction(size=len(base)) + b"\x01x",
                    ),
                ),
            ),
        )
        with (
            mock.patch.object(
                pack_module,
                "MAX_TOTAL_EXPANDED_BYTES",
                len(base) + len(target) - 1,
            ),
            self.assertRaisesRegex(VerificationError, "aggregate"),
        ):
            parse_pack(bounded)
        self.assertEqual(MAX_TOTAL_EXPANDED_BYTES, 16_777_216)

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

        unsupported_tag = bytearray(self.pack_bytes[:-20])
        unsupported_tag[12] = (unsupported_tag[12] & 0x8F) | 0x40

        wrong_size = bytearray(self.pack_bytes[:-20])
        wrong_size[12] = (wrong_size[12] & 0xF0) | ((len(self.payloads[0]) + 1) & 0x0F)

        corrupt_zlib = bytearray(self.pack_bytes[:-20])
        corrupt_zlib[14] ^= 0xFF

        bad_trailer = bytearray(self.pack_bytes)
        bad_trailer[-1] ^= 0x01

        for content in (
            _resign_pack(bytes(delta)),
            _resign_pack(bytes(unsupported_tag)),
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
