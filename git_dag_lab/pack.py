"""Build and independently verify a bounded, deterministic Git pack/index pair.

The baseline fixture uses real ``git pack-objects`` output and validates pack
v2/index v2 bytes with Python's standard library. The parser additionally
supports a bounded OFS_DELTA subset; REF_DELTA remains explicitly rejected.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any
import zlib

from .lab import (
    LabError,
    VerificationError,
    _GitRunner,
    _canonical_json,
    _deep_freeze,
    _find_git,
    _mutable_copy,
    _new_workspace,
    _store_blob,
    _validate_root,
    git_object_oid,
)

PACK_SCHEMA_VERSION = "git-pack-index-lab/v1"
PACK_VERSION = 2
INDEX_VERSION = 2
PACK_MAGIC = b"PACK"
INDEX_MAGIC = b"\xfftOc"
MAX_PACK_BYTES = 1_048_576
MAX_PACK_OBJECTS = 64
MAX_OBJECT_BYTES = 262_144
MAX_DELTA_DEPTH = 4
MAX_DELTA_INSTRUCTIONS = 4_096
MAX_DELTA_SIZE_BYTES = 5
MAX_OFS_OFFSET_BYTES = 8
MAX_TOTAL_EXPANDED_BYTES = 4_194_304

PACK_BLOBS = (
    ("binary-header", bytes(range(32))),
    ("content-addressing", b"content-addressed systems\n"),
    (
        "index-fanout",
        b"fanout tables map object-id prefixes to sorted index ranges\n",
    ),
)
_TYPE_BY_CODE = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_ENTRY_KIND_BY_CODE = {**_TYPE_BY_CODE, 6: "ofs-delta"}


@dataclass(frozen=True, slots=True)
class PackEntry:
    """One independently decoded full or OFS-delta pack entry."""

    crc32: int
    object_type: str
    offset: int
    oid: str
    packed_size: int
    payload_sha256: str
    size: int
    base_offset: int | None = None
    base_oid: str | None = None
    delta_depth: int = 0
    representation: str = "full"
    stored_size: int = 0

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "crc32": f"{self.crc32:08x}",
            "object_type": self.object_type,
            "offset": self.offset,
            "oid": self.oid,
            "packed_size": self.packed_size,
            "payload_sha256": self.payload_sha256,
            "size": self.size,
        }
        if self.representation != "full":
            payload.update(
                {
                    "base_offset": self.base_offset,
                    "base_oid": self.base_oid,
                    "delta_depth": self.delta_depth,
                    "representation": self.representation,
                    "stored_size": self.stored_size,
                }
            )
        return payload


@dataclass(frozen=True, slots=True)
class ParsedPack:
    """Verified pack header, entries, and trailer."""

    entries: tuple[PackEntry, ...]
    trailer_sha1: str
    version: int


@dataclass(frozen=True, slots=True)
class _ResolvedObject:
    """One bounded canonical object available as a delta base."""

    depth: int
    object_type: str
    oid: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class IndexEntry:
    """One verified index v2 row."""

    crc32: int
    offset: int
    oid: str

    def as_dict(self) -> dict[str, object]:
        return {
            "crc32": f"{self.crc32:08x}",
            "offset": self.offset,
            "oid": self.oid,
        }


@dataclass(frozen=True, slots=True)
class ParsedIndex:
    """Verified index v2 fanout, rows, and checksums."""

    entries: tuple[IndexEntry, ...]
    fanout: tuple[int, ...]
    index_sha1: str
    pack_sha1: str
    version: int


@dataclass(frozen=True, slots=True)
class PackReport:
    """Canonical evidence document for one real pack/index build."""

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
        pack = self.payload["pack"]
        index = self.payload["index"]
        return (
            f"PASS {PACK_SCHEMA_VERSION} "
            f"objects={pack['object_count']} "
            f"pack_version={pack['version']} "
            f"index_version={index['version']} "
            "deltas=0 "
            f"pack_sha1={pack['trailer_sha1']} "
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


def _uint32(content: bytes, offset: int, *, label: str) -> int:
    end = offset + 4
    if offset < 0 or end > len(content):
        raise VerificationError(f"{label} is truncated")
    return int.from_bytes(content[offset:end], "big")


def _uint64(content: bytes, offset: int, *, label: str) -> int:
    end = offset + 8
    if offset < 0 or end > len(content):
        raise VerificationError(f"{label} is truncated")
    return int.from_bytes(content[offset:end], "big")


def _read_regular_file(path: Path, *, label: str) -> bytes:
    """Read one bounded, single-link regular file without following a symlink."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise VerificationError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > MAX_PACK_BYTES
    ):
        raise VerificationError(f"{label} is not a bounded single-link file")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(f"{label} could not be opened safely") from exc
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or observed.st_dev != before.st_dev
            or observed.st_ino != before.st_ino
            or observed.st_size != before.st_size
        ):
            raise VerificationError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        remaining = observed.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise VerificationError(f"{label} ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise VerificationError(f"{label} grew while it was read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _decode_entry_header(
    content: bytes,
    offset: int,
    *,
    end: int,
) -> tuple[str, int, int]:
    if offset >= end:
        raise VerificationError("pack entry header is truncated")
    first = content[offset]
    offset += 1
    type_code = (first >> 4) & 0x07
    if type_code == 7:
        raise VerificationError("REF_DELTA pack entries are outside the reviewed subset")
    if type_code not in _ENTRY_KIND_BY_CODE:
        raise VerificationError("pack entry type is invalid")

    size = first & 0x0F
    shift = 4
    current = first
    while current & 0x80:
        if offset >= end or shift > 60:
            raise VerificationError("pack entry size header is malformed")
        current = content[offset]
        offset += 1
        size |= (current & 0x7F) << shift
        shift += 7
    if size > MAX_OBJECT_BYTES:
        raise VerificationError("pack entry data exceeds the reviewed bound")
    return _ENTRY_KIND_BY_CODE[type_code], size, offset


def _inflate_entry(
    content: bytes,
    offset: int,
    *,
    declared_size: int,
    end: int,
) -> tuple[bytes, int]:
    source = content[offset:end]
    inflater = zlib.decompressobj()
    try:
        payload = inflater.decompress(source, declared_size + 1)
    except zlib.error as exc:
        raise VerificationError("pack entry zlib stream is invalid") from exc
    if len(payload) > declared_size:
        raise VerificationError("pack entry expands beyond its declared size")
    if not inflater.eof or inflater.unconsumed_tail:
        raise VerificationError("pack entry zlib stream is incomplete or oversized")
    consumed = len(source) - len(inflater.unused_data)
    if consumed < 1:
        raise VerificationError("pack entry has an empty zlib stream")
    next_offset = offset + consumed
    if next_offset > end or len(payload) != declared_size:
        raise VerificationError("pack entry size does not match its payload")
    return payload, next_offset


def _encode_ofs_distance(distance: int) -> bytes:
    if distance < 1:
        raise ValueError("OFS_DELTA distance must be positive")
    encoded = bytearray((distance & 0x7F,))
    remaining = distance
    while remaining >> 7:
        remaining = (remaining >> 7) - 1
        encoded.append(0x80 | (remaining & 0x7F))
    encoded.reverse()
    return bytes(encoded)


def _decode_ofs_base_offset(
    content: bytes,
    offset: int,
    *,
    end: int,
    entry_offset: int,
) -> tuple[int, int]:
    start = offset
    if offset >= end:
        raise VerificationError("OFS_DELTA base offset is truncated")
    current = content[offset]
    offset += 1
    distance = current & 0x7F
    while current & 0x80:
        if offset >= end or offset - start >= MAX_OFS_OFFSET_BYTES:
            raise VerificationError("OFS_DELTA base offset is malformed")
        current = content[offset]
        offset += 1
        distance = ((distance + 1) << 7) | (current & 0x7F)
        if distance > MAX_PACK_BYTES:
            raise VerificationError("OFS_DELTA base offset exceeds the pack bound")
    encoded = content[start:offset]
    if distance < 1 or encoded != _encode_ofs_distance(distance):
        raise VerificationError("OFS_DELTA base offset is non-canonical")
    base_offset = entry_offset - distance
    if base_offset < 12 or base_offset >= entry_offset:
        raise VerificationError("OFS_DELTA base offset is out of bounds")
    return base_offset, offset


def _encode_delta_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("delta size must be non-negative")
    encoded = bytearray()
    remaining = value
    while True:
        current = remaining & 0x7F
        remaining >>= 7
        if remaining:
            current |= 0x80
        encoded.append(current)
        if not remaining:
            return bytes(encoded)


def _decode_delta_size(
    program: bytes,
    offset: int,
    *,
    label: str,
) -> tuple[int, int]:
    start = offset
    value = 0
    shift = 0
    while True:
        if offset >= len(program) or offset - start >= MAX_DELTA_SIZE_BYTES:
            raise VerificationError(f"{label} is truncated or oversized")
        current = program[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if value > MAX_OBJECT_BYTES:
            raise VerificationError(f"{label} exceeds the reviewed bound")
        if not current & 0x80:
            break
        shift += 7
    if program[start:offset] != _encode_delta_size(value):
        raise VerificationError(f"{label} is non-canonical")
    return value, offset


def _apply_delta(base: bytes, program: bytes) -> bytes:
    if type(base) is not bytes or type(program) is not bytes:
        raise VerificationError("delta inputs must be exact bytes")
    base_size, offset = _decode_delta_size(
        program,
        0,
        label="delta base size",
    )
    result_size, offset = _decode_delta_size(
        program,
        offset,
        label="delta result size",
    )
    if base_size != len(base):
        raise VerificationError("delta base size does not match its object")
    if result_size > MAX_OBJECT_BYTES:
        raise VerificationError("delta result exceeds the reviewed bound")

    output = bytearray()
    instructions = 0
    while offset < len(program):
        instructions += 1
        if instructions > MAX_DELTA_INSTRUCTIONS:
            raise VerificationError("delta instruction count exceeds the reviewed bound")
        opcode = program[offset]
        offset += 1
        if opcode & 0x80:
            copy_offset = 0
            copy_size = 0
            for bit, shift in ((0x01, 0), (0x02, 8), (0x04, 16), (0x08, 24)):
                if opcode & bit:
                    if offset >= len(program):
                        raise VerificationError("delta copy offset is truncated")
                    copy_offset |= program[offset] << shift
                    offset += 1
            for bit, shift in ((0x10, 0), (0x20, 8), (0x40, 16)):
                if opcode & bit:
                    if offset >= len(program):
                        raise VerificationError("delta copy size is truncated")
                    copy_size |= program[offset] << shift
                    offset += 1
            if copy_size == 0:
                copy_size = 0x10000
            if copy_offset > len(base) or copy_size > len(base) - copy_offset:
                raise VerificationError("delta copy range exceeds its base object")
            if copy_size > result_size - len(output):
                raise VerificationError("delta copy exceeds its declared result")
            output.extend(base[copy_offset : copy_offset + copy_size])
        elif opcode:
            literal_size = opcode & 0x7F
            literal_end = offset + literal_size
            if literal_end > len(program):
                raise VerificationError("delta literal is truncated")
            if literal_size > result_size - len(output):
                raise VerificationError("delta literal exceeds its declared result")
            output.extend(program[offset:literal_end])
            offset = literal_end
        else:
            raise VerificationError("delta opcode zero is reserved")
    if len(output) != result_size:
        raise VerificationError("delta result size does not match its instructions")
    return bytes(output)


def parse_pack(content: bytes) -> ParsedPack:
    """Parse and verify one bounded SHA-1 pack v2 without invoking Git."""

    if (
        type(content) is not bytes
        or len(content) < 32
        or len(content) > MAX_PACK_BYTES
    ):
        raise VerificationError("pack bytes are outside the reviewed bound")
    if content[:4] != PACK_MAGIC:
        raise VerificationError("pack signature is invalid")
    version = _uint32(content, 4, label="pack version")
    if version != PACK_VERSION:
        raise VerificationError("pack version is outside the reviewed subset")
    count = _uint32(content, 8, label="pack object count")
    if count < 1 or count > MAX_PACK_OBJECTS:
        raise VerificationError("pack object count is outside the reviewed bound")

    pack_end = len(content) - 20
    trailer = content[pack_end:]
    if hashlib.sha1(content[:pack_end], usedforsecurity=False).digest() != trailer:
        raise VerificationError("pack trailer does not match the preceding bytes")

    entries: list[PackEntry] = []
    offset = 12
    seen: set[str] = set()
    resolved_by_offset: dict[int, _ResolvedObject] = {}
    expanded_bytes = 0
    for _ in range(count):
        entry_start = offset
        entry_kind, declared_size, payload_start = _decode_entry_header(
            content,
            offset,
            end=pack_end,
        )
        base_offset: int | None = None
        base_oid: str | None = None
        depth = 0
        representation = "full"
        if entry_kind == "ofs-delta":
            base_offset, payload_start = _decode_ofs_base_offset(
                content,
                payload_start,
                end=pack_end,
                entry_offset=entry_start,
            )
        stored_payload, offset = _inflate_entry(
            content,
            payload_start,
            declared_size=declared_size,
            end=pack_end,
        )

        if entry_kind == "ofs-delta":
            assert base_offset is not None
            base = resolved_by_offset.get(base_offset)
            if base is None:
                raise VerificationError(
                    "OFS_DELTA base is not an earlier pack-entry boundary"
                )
            depth = base.depth + 1
            if depth > MAX_DELTA_DEPTH:
                raise VerificationError("OFS_DELTA chain exceeds the reviewed depth")
            payload = _apply_delta(base.payload, stored_payload)
            object_type = base.object_type
            base_oid = base.oid
            representation = entry_kind
        else:
            payload = stored_payload
            object_type = entry_kind

        expanded_bytes += len(payload)
        if expanded_bytes > MAX_TOTAL_EXPANDED_BYTES:
            raise VerificationError("pack expands beyond the aggregate reviewed bound")
        oid = git_object_oid(object_type, payload)
        if oid in seen:
            raise VerificationError("pack contains a duplicate logical object")
        seen.add(oid)
        packed = content[entry_start:offset]
        resolved_by_offset[entry_start] = _ResolvedObject(
            depth=depth,
            object_type=object_type,
            oid=oid,
            payload=payload,
        )
        entries.append(
            PackEntry(
                crc32=binascii.crc32(packed) & 0xFFFFFFFF,
                object_type=object_type,
                offset=entry_start,
                oid=oid,
                packed_size=len(packed),
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
                base_offset=base_offset,
                base_oid=base_oid,
                delta_depth=depth,
                representation=representation,
                stored_size=declared_size,
            )
        )
    if offset != pack_end:
        raise VerificationError("pack has trailing bytes outside its declared entries")
    return ParsedPack(
        entries=tuple(entries),
        trailer_sha1=trailer.hex(),
        version=version,
    )

def _expected_fanout(oids: tuple[str, ...]) -> tuple[int, ...]:
    counts = [0] * 256
    for oid in oids:
        counts[int(oid[:2], 16)] += 1
    total = 0
    fanout: list[int] = []
    for count in counts:
        total += count
        fanout.append(total)
    return tuple(fanout)


def parse_index(content: bytes) -> ParsedIndex:
    """Parse and verify one bounded Git index v2 without invoking Git."""

    minimum = 8 + (256 * 4) + 40
    if (
        type(content) is not bytes
        or len(content) < minimum
        or len(content) > MAX_PACK_BYTES
    ):
        raise VerificationError("index bytes are outside the reviewed bound")
    if content[:4] != INDEX_MAGIC:
        raise VerificationError("index signature is invalid")
    version = _uint32(content, 4, label="index version")
    if version != INDEX_VERSION:
        raise VerificationError("index version is outside the reviewed subset")

    fanout = tuple(
        _uint32(content, 8 + (bucket * 4), label="index fanout")
        for bucket in range(256)
    )
    if any(left > right for left, right in zip(fanout, fanout[1:])):
        raise VerificationError("index fanout table is not cumulative")
    count = fanout[-1]
    if count < 1 or count > MAX_PACK_OBJECTS:
        raise VerificationError("index object count is outside the reviewed bound")

    oid_start = 8 + (256 * 4)
    crc_start = oid_start + (count * 20)
    offset_start = crc_start + (count * 4)
    large_start = offset_start + (count * 4)
    fixed_end = large_start + 40
    if fixed_end > len(content):
        raise VerificationError("index tables are truncated")

    oids = tuple(
        content[oid_start + (row * 20) : oid_start + ((row + 1) * 20)].hex()
        for row in range(count)
    )
    if tuple(sorted(oids)) != oids or len(set(oids)) != count:
        raise VerificationError("index object IDs are not unique and sorted")
    if fanout != _expected_fanout(oids):
        raise VerificationError("index fanout does not match its object IDs")

    crc_values = tuple(
        _uint32(content, crc_start + (row * 4), label="index CRC table")
        for row in range(count)
    )
    offset_words = tuple(
        _uint32(content, offset_start + (row * 4), label="index offset table")
        for row in range(count)
    )
    large_indexes = [word & 0x7FFFFFFF for word in offset_words if word & 0x80000000]
    if sorted(large_indexes) != list(range(len(large_indexes))):
        raise VerificationError("index large-offset references are not canonical")
    checksum_start = large_start + (len(large_indexes) * 8)
    if checksum_start + 40 != len(content):
        raise VerificationError("index has an invalid table length")

    large_offsets = tuple(
        _uint64(content, large_start + (row * 8), label="index large-offset table")
        for row in range(len(large_indexes))
    )
    offsets: list[int] = []
    for word in offset_words:
        if word & 0x80000000:
            offsets.append(large_offsets[word & 0x7FFFFFFF])
        else:
            offsets.append(word)

    pack_sha1 = content[checksum_start : checksum_start + 20].hex()
    index_sha1 = content[checksum_start + 20 :].hex()
    expected_index_sha1 = hashlib.sha1(
        content[: checksum_start + 20],
        usedforsecurity=False,
    ).hexdigest()
    if index_sha1 != expected_index_sha1:
        raise VerificationError("index checksum does not match the preceding bytes")

    entries = tuple(
        IndexEntry(crc32=crc_values[row], offset=offsets[row], oid=oids[row])
        for row in range(count)
    )
    return ParsedIndex(
        entries=entries,
        fanout=fanout,
        index_sha1=index_sha1,
        pack_sha1=pack_sha1,
        version=version,
    )


def _cross_check(pack: ParsedPack, index: ParsedIndex) -> None:
    if index.pack_sha1 != pack.trailer_sha1:
        raise VerificationError("index does not bind the verified pack checksum")
    pack_entries = {entry.oid: entry for entry in pack.entries}
    if len(pack_entries) != len(index.entries):
        raise VerificationError("pack and index object counts differ")
    for indexed in index.entries:
        packed = pack_entries.get(indexed.oid)
        if packed is None:
            raise VerificationError("index references an object absent from the pack")
        if indexed.offset != packed.offset or indexed.crc32 != packed.crc32:
            raise VerificationError("index offset or CRC does not match the pack entry")


def _build_and_verify_pack(runner: _GitRunner, private: Path) -> PackReport:
    runner.initialize()
    expected_payloads: dict[str, bytes] = {}
    labels_by_oid: dict[str, str] = {}
    for label, payload in PACK_BLOBS:
        oid = _store_blob(runner, payload)
        expected_payloads[oid] = payload
        labels_by_oid[oid] = label
    if len(expected_payloads) != len(PACK_BLOBS):
        raise VerificationError("fixed pack fixture contains duplicate objects")

    ordered_oids = tuple(sorted(expected_payloads))
    prefix = private / "fixture"
    result = runner.run(
        "pack-objects",
        "--window=0",
        "--depth=0",
        "--compression=0",
        "--no-reuse-delta",
        "--no-reuse-object",
        os.fspath(prefix),
        stdin=("".join(f"{oid}\n" for oid in ordered_oids)).encode("ascii"),
    )
    if result.stderr:
        raise VerificationError("git pack-objects produced unexpected diagnostics")
    try:
        pack_name = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise VerificationError("git pack-objects returned a non-ASCII checksum") from exc
    if (
        len(pack_name) != 40
        or any(character not in "0123456789abcdef" for character in pack_name)
    ):
        raise VerificationError("git pack-objects returned an invalid checksum")

    pack_path = Path(f"{prefix}-{pack_name}.pack")
    index_path = Path(f"{prefix}-{pack_name}.idx")
    pack_bytes = _read_regular_file(pack_path, label="generated pack")
    index_bytes = _read_regular_file(index_path, label="generated index")
    parsed_pack = parse_pack(pack_bytes)
    parsed_index = parse_index(index_bytes)
    _cross_check(parsed_pack, parsed_index)
    if parsed_pack.trailer_sha1 != pack_name:
        raise VerificationError("git pack name does not match the verified trailer")
    if {entry.oid for entry in parsed_pack.entries} != set(expected_payloads):
        raise VerificationError("generated pack object inventory is not exact")
    for entry in parsed_pack.entries:
        payload = expected_payloads[entry.oid]
        if (
            entry.object_type != "blob"
            or entry.size != len(payload)
            or entry.payload_sha256 != hashlib.sha256(payload).hexdigest()
        ):
            raise VerificationError("generated pack object differs from the fixture")

    index_rows = {entry.oid: entry for entry in parsed_index.entries}
    objects = []
    for entry in parsed_pack.entries:
        indexed = index_rows[entry.oid]
        objects.append(
            {
                **entry.as_dict(),
                "index_crc32": f"{indexed.crc32:08x}",
                "index_offset": indexed.offset,
                "label": labels_by_oid[entry.oid],
            }
        )

    nonzero_buckets = [
        {
            "cumulative": parsed_index.fanout[bucket],
            "prefix": f"{bucket:02x}",
            "range_start": 0 if bucket == 0 else parsed_index.fanout[bucket - 1],
        }
        for bucket in range(256)
        if (
            parsed_index.fanout[bucket]
            != (0 if bucket == 0 else parsed_index.fanout[bucket - 1])
        )
    ]
    payload: dict[str, object] = {
        "checks": {
            "all_fixture_objects_present": True,
            "delta_entries_absent": True,
            "index_checksum_verified": True,
            "index_crc32_matches_pack": True,
            "index_fanout_matches_sorted_oids": True,
            "index_offsets_match_pack": True,
            "pack_trailer_verified": True,
        },
        "command_trace": list(runner.trace),
        "fixture": {
            "object_count": len(PACK_BLOBS),
            "objects": [
                {
                    "label": label,
                    "oid": git_object_oid("blob", body),
                    "payload_sha256": hashlib.sha256(body).hexdigest(),
                    "size": len(body),
                }
                for label, body in PACK_BLOBS
            ],
        },
        "index": {
            "bytes": len(index_bytes),
            "index_sha1": parsed_index.index_sha1,
            "nonzero_fanout_buckets": nonzero_buckets,
            "pack_sha1": parsed_index.pack_sha1,
            "sha256": hashlib.sha256(index_bytes).hexdigest(),
            "version": parsed_index.version,
        },
        "object_format": "sha1",
        "objects_in_pack_order": objects,
        "pack": {
            "bytes": len(pack_bytes),
            "delta_count": 0,
            "object_count": len(parsed_pack.entries),
            "sha256": hashlib.sha256(pack_bytes).hexdigest(),
            "trailer_sha1": parsed_pack.trailer_sha1,
            "version": parsed_pack.version,
        },
        "scope": {
            "authentication_claim": False,
            "delta_entries_supported": False,
            "fixture_kind": "three deterministic synthetic blobs",
            "git_pack_objects_executed": True,
            "network_required": False,
        },
        "schema_version": PACK_SCHEMA_VERSION,
    }
    receipt = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return PackReport(payload=_deep_freeze(payload), receipt_sha256=receipt)


def run_pack_lab(root: Path | str = ".") -> PackReport:
    """Build and verify a real pack/index pair below ``root``, then remove it."""

    try:
        validated_root = _validate_root(Path(root))
        git = _find_git()
        with tempfile.TemporaryDirectory(
            prefix=".git-pack-index-lab-",
            dir=validated_root,
        ) as private_name:
            workspace = _new_workspace(validated_root, Path(private_name))
            runner = _GitRunner(git, workspace)
            return _build_and_verify_pack(runner, workspace.private)
    except LabError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise LabError("isolated pack lab setup failed") from exc


__all__ = [
    "INDEX_VERSION",
    "MAX_DELTA_DEPTH",
    "MAX_DELTA_INSTRUCTIONS",
    "MAX_OBJECT_BYTES",
    "MAX_TOTAL_EXPANDED_BYTES",
    "MAX_PACK_BYTES",
    "MAX_PACK_OBJECTS",
    "PACK_SCHEMA_VERSION",
    "PACK_VERSION",
    "IndexEntry",
    "PackEntry",
    "PackReport",
    "ParsedIndex",
    "ParsedPack",
    "parse_index",
    "parse_pack",
    "run_pack_lab",
]
