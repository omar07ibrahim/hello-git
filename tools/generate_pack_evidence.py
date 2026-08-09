#!/usr/bin/env python3
"""Generate and verify source-bound Git pack/index evidence."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import html
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from typing import Any
import zlib

ROOT = Path(__file__).resolve().parents[1]
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))

from tools.generate_evidence import (
    BROWSER_PATH,
    BROWSER_SHA256,
    BROWSER_VERSION,
    CONTAINER_IMAGE,
    EvidenceError,
    MAX_PNG_BYTES,
    _artifact_row,
    _check_artifacts,
    _json_bytes,
    _safe_capture_bytes,
    _sha256,
    _source_row,
    _svg_header as _base_svg_header,
    _write_artifacts,
    _xml_text,
)

EVIDENCE_PATH = Path("evidence/git-pack-index-v1.json")
DEMO_ROOT = Path("docs/demo/git-pack-index-v1")
VERIFY_PATH = DEMO_ROOT / "verify.txt"
INSPECT_PATH = DEMO_ROOT / "inspect.json"
REPORT_PATH = DEMO_ROOT / "report.html"
MANIFEST_PATH = DEMO_ROOT / "manifest.json"
RENDERED_DOM_PATH = DEMO_ROOT / "rendered-dom.html"
ATTESTATION_PATH = DEMO_ROOT / "capture-attestation.json"
LAYOUT_PATH = Path("docs/assets/git-pack-layout.svg")
FANOUT_PATH = Path("docs/assets/git-pack-fanout.svg")
INTEGRITY_PATH = Path("docs/assets/git-pack-integrity.svg")
CLI_PATH = Path("docs/assets/git-pack-cli.svg")
SCREENSHOT_PATH = Path("docs/assets/git-pack-report.png")
PNG_DIMENSIONS = (1440, 1500)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class PackCapture:
    screenshot: bytes
    rendered_dom: bytes
    attestation: bytes
    document: Mapping[str, Any]


def _pack_svg_header(
    title: str,
    description: str,
    *,
    width: int,
    height: int,
    receipt: str,
    metadata_extra: Mapping[str, Any] | None = None,
) -> str:
    """Build an SVG header whose provenance names the pack evidence source."""

    metadata = dict(metadata_extra or {})
    metadata["source"] = EVIDENCE_PATH.as_posix()
    return _base_svg_header(
        title,
        description,
        width=width,
        height=height,
        receipt=receipt,
        metadata_extra=metadata,
    )


def _parse_pack_png(content: bytes) -> tuple[int, int]:
    """Validate the complete pack-report PNG before trusting image metadata."""

    if len(content) > MAX_PNG_BYTES:
        raise EvidenceError("pack browser capture exceeds the PNG size limit")
    if len(content) < 57 or not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise EvidenceError("pack browser capture is not a complete PNG")

    offset = 8
    chunk_index = 0
    width = height = 0
    idat_payloads: list[bytes] = []
    saw_iend = False
    while offset < len(content):
        if len(content) - offset < 12:
            raise EvidenceError("pack PNG chunk header is truncated")
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        chunk_type = content[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(content):
            raise EvidenceError("pack PNG chunk payload is truncated")
        if len(chunk_type) != 4 or not all(
            65 <= byte <= 90 or 97 <= byte <= 122 for byte in chunk_type
        ):
            raise EvidenceError("pack PNG chunk type is malformed")
        payload = content[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", content[offset + 8 + length : chunk_end])[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise EvidenceError("pack PNG chunk CRC does not match")

        if chunk_index == 0:
            if chunk_type != b"IHDR" or length != 13:
                raise EvidenceError("pack PNG does not start with one 13-byte IHDR")
            width, height, bit_depth, color_type, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", payload)
            )
            if (
                (width, height) != PNG_DIMENSIONS
                or bit_depth != 8
                or color_type != 2
                or compression != 0
                or filtering != 0
                or interlace != 0
            ):
                raise EvidenceError(
                    "pack PNG IHDR differs from the pinned Chromium profile"
                )
        elif chunk_type == b"IDAT":
            idat_payloads.append(payload)
        elif chunk_type != b"IEND":
            raise EvidenceError(
                "pack PNG contains a chunk outside the pinned Chromium profile"
            )

        offset = chunk_end
        chunk_index += 1
        if chunk_type == b"IEND":
            if length != 0:
                raise EvidenceError("pack PNG IEND chunk is not empty")
            saw_iend = True
            break

    if not idat_payloads or not saw_iend:
        raise EvidenceError("pack PNG lacks IDAT or terminal IEND")
    if offset != len(content):
        raise EvidenceError("pack PNG has trailing bytes after IEND")

    scanline_size = 1 + width * 3
    expected_decoded_size = height * scanline_size
    decoder = zlib.decompressobj()
    decoded = bytearray()
    try:
        for index, payload in enumerate(idat_payloads):
            if decoder.eof:
                raise EvidenceError(
                    "pack PNG contains IDAT data after the zlib stream ended"
                )
            remaining = expected_decoded_size + 1 - len(decoded)
            if remaining <= 0:
                raise EvidenceError("pack PNG scanline stream exceeds the expected size")
            decoded.extend(decoder.decompress(payload, remaining))
            if decoder.unconsumed_tail or decoder.unused_data:
                raise EvidenceError("pack PNG zlib stream has excess compressed data")
            if decoder.eof and index != len(idat_payloads) - 1:
                raise EvidenceError(
                    "pack PNG zlib stream ended before the final IDAT"
                )
        remaining = expected_decoded_size + 1 - len(decoded)
        if remaining <= 0:
            raise EvidenceError("pack PNG scanline stream exceeds the expected size")
        decoded.extend(decoder.flush(remaining))
    except zlib.error as exc:
        raise EvidenceError("pack PNG IDAT payload is not a valid zlib stream") from exc
    if (
        not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
        or len(decoded) != expected_decoded_size
    ):
        raise EvidenceError("pack PNG scanline stream is incomplete or has the wrong size")
    if any(decoded[row * scanline_size] > 4 for row in range(height)):
        raise EvidenceError("pack PNG contains an invalid scanline filter byte")
    return width, height


def _run_cli(arguments: Sequence[str]) -> bytes:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "git_dag_lab", *arguments],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise EvidenceError(f"CLI {' '.join(arguments)} failed")
    if completed.stderr:
        raise EvidenceError(f"CLI {' '.join(arguments)} wrote to stderr")
    return completed.stdout


def _collect_cli() -> tuple[bytes, bytes, bytes, dict[str, Any]]:
    first = (
        _run_cli(("pack-verify",)),
        _run_cli(("pack-inspect", "--compact")),
        _run_cli(("pack-inspect",)),
    )
    second = (
        _run_cli(("pack-verify",)),
        _run_cli(("pack-inspect", "--compact")),
        _run_cli(("pack-inspect",)),
    )
    if first != second:
        raise EvidenceError("two fresh pack CLI runs produced different evidence")
    verify_output, compact_output, pretty_output = first
    try:
        compact_document = json.loads(compact_output)
        pretty_document = json.loads(pretty_output)
    except json.JSONDecodeError as exc:
        raise EvidenceError("pack inspection output is not JSON") from exc
    if compact_document != pretty_document:
        raise EvidenceError("compact and pretty pack documents differ")
    if compact_output != _json_bytes(compact_document, pretty=False):
        raise EvidenceError("compact pack inspection output is not canonical JSON")
    if pretty_output != _json_bytes(pretty_document, pretty=True):
        raise EvidenceError("pretty pack inspection output is not canonical JSON")
    _validate_document(compact_document, verify_output)
    return verify_output, compact_output, pretty_output, compact_document


def _validate_document(document: Mapping[str, Any], verify_output: bytes) -> None:
    if set(document) != {"receipt", "report"}:
        raise EvidenceError("pack evidence has unexpected top-level fields")
    report = document.get("report")
    receipt = document.get("receipt")
    if not isinstance(report, dict) or not isinstance(receipt, dict):
        raise EvidenceError("pack evidence sections are malformed")
    if report.get("schema_version") != "git-pack-index-lab/v1":
        raise EvidenceError("unexpected pack evidence schema")
    receipt_sha = receipt.get("sha256")
    if not isinstance(receipt_sha, str) or not SHA256_RE.fullmatch(receipt_sha):
        raise EvidenceError("pack receipt is malformed")
    canonical = json.dumps(
        report,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if _sha256(canonical) != receipt_sha:
        raise EvidenceError("pack receipt does not bind the canonical report")
    if f"receipt_sha256={receipt_sha}\n".encode("ascii") not in verify_output:
        raise EvidenceError("pack transcript and receipt differ")

    pack = report.get("pack", {})
    index = report.get("index", {})
    checks = report.get("checks", {})
    scope = report.get("scope", {})
    objects = report.get("objects_in_pack_order", [])
    fixture = report.get("fixture", {})
    if (
        pack.get("version") != 2
        or pack.get("object_count") != 3
        or pack.get("delta_count") != 0
        or not isinstance(pack.get("bytes"), int)
        or pack["bytes"] <= 32
        or not SHA1_RE.fullmatch(pack.get("trailer_sha1", ""))
        or not SHA256_RE.fullmatch(pack.get("sha256", ""))
    ):
        raise EvidenceError("pack summary is outside the reviewed fixture")
    if (
        index.get("version") != 2
        or index.get("pack_sha1") != pack["trailer_sha1"]
        or not isinstance(index.get("bytes"), int)
        or index["bytes"] <= 1_064
        or not SHA1_RE.fullmatch(index.get("index_sha1", ""))
        or not SHA256_RE.fullmatch(index.get("sha256", ""))
    ):
        raise EvidenceError("index summary is outside the reviewed fixture")
    expected_checks = {
        "all_fixture_objects_present",
        "delta_entries_absent",
        "index_checksum_verified",
        "index_crc32_matches_pack",
        "index_fanout_matches_sorted_oids",
        "index_offsets_match_pack",
        "pack_trailer_verified",
    }
    if set(checks) != expected_checks or not all(value is True for value in checks.values()):
        raise EvidenceError("not every pack/index check passed")
    if (
        fixture.get("object_count") != 3
        or len(fixture.get("objects", [])) != 3
        or len(objects) != 3
    ):
        raise EvidenceError("pack fixture inventory is incomplete")
    for row in objects:
        if (
            row.get("object_type") != "blob"
            or not SHA1_RE.fullmatch(row.get("oid", ""))
            or not SHA256_RE.fullmatch(row.get("payload_sha256", ""))
            or row.get("offset") != row.get("index_offset")
            or row.get("crc32") != row.get("index_crc32")
        ):
            raise EvidenceError("pack object row is not cross-bound")
    if (
        scope.get("delta_entries_supported") is not False
        or scope.get("authentication_claim") is not False
        or scope.get("git_pack_objects_executed") is not True
        or scope.get("network_required") is not False
    ):
        raise EvidenceError("pack scope and non-claims are incomplete")
    rendered = json.dumps(document, ensure_ascii=True, sort_keys=True)
    forbidden = ("/home/", "github.com/", "@gmail.com", "AKIA", "ghp_", "github_pat_")
    if any(marker.lower() in rendered.lower() for marker in forbidden):
        raise EvidenceError("pack evidence contains host, remote, or credential material")


def _layout_svg(document: Mapping[str, Any]) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    pack = report["pack"]
    index = report["index"]
    objects = report["objects_in_pack_order"]
    total = pack["bytes"]
    x0 = 55
    width = 1_330
    colors = ("#59e3c2", "#bd7cff", "#55a8ff")
    parts = [
        _pack_svg_header(
            "Actual Git pack v2 and index v2 byte layout",
            "Byte offsets and section sizes are derived from the real production pack receipt.",
            width=1440,
            height=700,
            receipt=receipt,
            metadata_extra={
                "index_sha256": index["sha256"],
                "pack_sha256": pack["sha256"],
            },
        ),
        '  <text class="eyebrow" x="55" y="58">REAL PACK V2 · ACTUAL OFFSETS · THREE NON-DELTA BLOBS</text>',
        f'  <text class="heading" x="55" y="104">{total} pack bytes, independently decoded</text>',
        '  <rect x="55" y="150" width="1330" height="112" rx="18" fill="#081321" stroke="#30476f"/>',
    ]
    header_width = max(58, round(12 / total * width))
    parts.append(
        f'  <rect x="{x0}" y="150" width="{header_width}" height="112" rx="18" fill="#243d62"/>'
    )
    parts.append(
        f'  <text class="small" x="{x0 + 10}" y="210">PACK</text>'
    )
    for number, (row, color) in enumerate(zip(objects, colors, strict=True), 1):
        x = x0 + round(row["offset"] / total * width)
        segment_width = max(105, round(row["packed_size"] / total * width))
        parts.extend(
            (
                f'  <rect x="{x}" y="150" width="{segment_width}" height="112" fill="{color}" fill-opacity=".72" stroke="#07101d"/>',
                f'  <text class="small" style="fill:#06101d;font-weight:800" x="{x + 10}" y="187">0{number} · {row["label"]}</text>',
                f'  <text class="small" style="fill:#06101d" x="{x + 10}" y="214">offset {row["offset"]}</text>',
                f'  <text class="small" style="fill:#06101d" x="{x + 10}" y="239">{row["packed_size"]} bytes</text>',
            )
        )
    trailer_x = x0 + round((total - 20) / total * width)
    trailer_width = max(82, round(20 / total * width))
    parts.extend(
        (
            f'  <rect x="{trailer_x}" y="150" width="{trailer_width}" height="112" rx="0 18 18 0" fill="#ffcf66"/>',
            f'  <text class="small" style="fill:#06101d;font-weight:800" x="{trailer_x + 8}" y="199">SHA-1</text>',
            f'  <text class="small" style="fill:#06101d" x="{trailer_x + 8}" y="225">20 B</text>',
            '  <text class="eyebrow" x="55" y="326">INDEX V2 FIXED TABLES</text>',
        )
    )
    # Widths are legibility-scaled; every label retains the actual byte size.
    sections = (
        ("header", 8, 90, "#243d62"),
        ("fanout[256]", 1_024, 650, "#55a8ff"),
        ("sorted OIDs", 60, 180, "#59e3c2"),
        ("CRC32", 12, 130, "#bd7cff"),
        ("offsets", 12, 130, "#ff8fa3"),
        ("checksums", 40, 150, "#ffcf66"),
    )
    index_x = 55
    for name, size, section_width, color in sections:
        parts.extend(
            (
                f'  <rect x="{index_x}" y="350" width="{section_width}" height="102" fill="{color}" fill-opacity=".74" stroke="#07101d"/>',
                f'  <text class="small" style="fill:#06101d;font-weight:800" x="{index_x + 8}" y="391">{name}</text>',
                f'  <text class="small" style="fill:#06101d" x="{index_x + 8}" y="419">{size} B</text>',
            )
        )
        index_x += section_width
    parts.extend(
        (
            f'  <rect x="55" y="510" width="1330" height="112" rx="16" fill="#102b2c" stroke="#2fd6af"/>',
            f'  <text class="body" x="82" y="550">Pack trailer SHA-1 · {_xml_text(pack["trailer_sha1"])}</text>',
            f'  <text class="body" x="82" y="580">Index SHA-1 · {_xml_text(index["index_sha1"])} · binds the same pack checksum</text>',
            f'  <text class="small" x="82" y="607">Receipt SHA-256 · {receipt}</text>',
            "</svg>\n",
        )
    )
    return "\n".join(parts).encode("utf-8")


def _fanout_svg(document: Mapping[str, Any]) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    objects = sorted(report["objects_in_pack_order"], key=lambda row: row["oid"])
    buckets = {
        row["prefix"]: row for row in report["index"]["nonzero_fanout_buckets"]
    }
    parts = [
        _pack_svg_header(
            "Actual index v2 fanout lookup",
            "The three populated prefix buckets, sorted object IDs, and exact index ranges come from the verified index receipt.",
            width=1440,
            height=690,
            receipt=receipt,
        ),
        '  <text class="eyebrow" x="55" y="58">256-BUCKET CUMULATIVE FANOUT · THREE ACTUAL OBJECT IDS</text>',
        '  <text class="heading" x="55" y="104">Prefix lookup narrows the sorted OID table.</text>',
    ]
    for position, row in enumerate(objects):
        y = 160 + (position * 145)
        bucket = buckets[row["oid"][:2]]
        parts.extend(
            (
                f'  <rect class="node" filter="url(#shadow)" x="55" y="{y}" width="180" height="105" rx="16"/>',
                f'  <text class="eyebrow" x="82" y="{y + 38}">PREFIX {row["oid"][:2]}</text>',
                f'  <text class="heading" style="font-size:25px" x="82" y="{y + 74}">[{bucket["range_start"]}, {bucket["cumulative"]})</text>',
                f'  <path class="edge" d="M 245 {y + 52} L 320 {y + 52}"/>',
                f'  <rect x="335" y="{y}" width="1050" height="105" rx="16" fill="#0c182b" stroke="#30476f"/>',
                f'  <text class="body" x="365" y="{y + 37}">{_xml_text(row["label"])} · blob · {row["size"]} bytes</text>',
                f'  <text class="mono" x="365" y="{y + 72}">{row["oid"]}</text>',
            )
        )
    parts.extend(
        (
            '  <rect x="55" y="610" width="1330" height="42" rx="12" fill="#102b2c" stroke="#2fd6af"/>',
            f'  <text class="small" x="75" y="636">Every displayed bucket and range is decoded from index bytes · receipt {receipt}</text>',
            "</svg>\n",
        )
    )
    return "\n".join(parts).encode("utf-8")


def _integrity_svg(document: Mapping[str, Any]) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    pack = report["pack"]
    index = report["index"]
    stages = (
        ("PACK HEADER", f"v{pack['version']} · {pack['object_count']} objects"),
        ("ENTRY STREAMS", "bounded zlib · logical OIDs"),
        ("INDEX ROWS", "CRC32 · exact offsets"),
        ("PACK BINDING", index["pack_sha1"]),
        ("INDEX CHECKSUM", index["index_sha1"]),
    )
    parts = [
        _pack_svg_header(
            "Independent pack/index integrity chain",
            "The production verifier reconstructs each logical object, checks entry CRCs and offsets, then binds both file checksums.",
            width=1440,
            height=580,
            receipt=receipt,
        ),
        '  <text class="eyebrow" x="55" y="58">GIT WRITES · PYTHON INDEPENDENTLY READS · NO MODELLED SUCCESS</text>',
        '  <text class="heading" x="55" y="104">Five checks connect raw bytes to one receipt.</text>',
    ]
    x_values = (35, 315, 595, 875, 1155)
    for number, ((title, detail), x) in enumerate(zip(stages, x_values, strict=True), 1):
        visible = detail if len(detail) <= 24 else detail[:20] + "…"
        parts.extend(
            (
                f'  <rect class="node" filter="url(#shadow)" x="{x}" y="170" width="245" height="205" rx="18"/>',
                f'  <text class="eyebrow" x="{x + 24}" y="210">0{number}</text>',
                f'  <text class="heading" style="font-size:20px" x="{x + 24}" y="252">{title}</text>',
                f'  <text class="small" x="{x + 24}" y="292">{_xml_text(visible)}</text>',
                f'  <text class="small" x="{x + 24}" y="329">PASS</text>',
            )
        )
        if number < len(stages):
            parts.append(f'  <path class="edge" d="M {x + 250} 270 L {x + 275} 270"/>')
    parts.extend(
        (
            '  <rect x="35" y="430" width="1365" height="88" rx="16" fill="#102b2c" stroke="#2fd6af"/>',
            f'  <text class="body" x="62" y="467">3/3 CRC32 and offsets cross-match · 0 deltas accepted · pack SHA-1 {pack["trailer_sha1"]}</text>',
            f'  <text class="small" x="62" y="496">SHA-1 models Git object storage; authentication claim = false · receipt {receipt}</text>',
            "</svg>\n",
        )
    )
    return "\n".join(parts).encode("utf-8")


def _cli_svg(document: Mapping[str, Any], verify_output: bytes) -> bytes:
    receipt = document["receipt"]["sha256"]
    transcript = verify_output.decode("utf-8").rstrip("\n")
    before_receipt, receipt_digest = transcript.rsplit(" receipt_sha256=", 1)
    before_pack, pack_digest = before_receipt.rsplit("pack_sha1=", 1)
    parts = [
        _pack_svg_header(
            "Real Git pack/index CLI receipt",
            "Exact stdout from pack-verify; the command executed real git pack-objects and independently checked both files.",
            width=1440,
            height=500,
            receipt=receipt,
        ),
        '  <text class="eyebrow" x="55" y="58">REAL CLI STDOUT · STDERR 0 BYTES · EXIT 0</text>',
        '  <rect x="55" y="92" width="1330" height="300" rx="18" fill="#050a13" stroke="#30476f"/>',
        '  <circle cx="88" cy="124" r="6" fill="#ff6b6b"/><circle cx="110" cy="124" r="6" fill="#ffd166"/><circle cx="132" cy="124" r="6" fill="#59e3c2"/>',
        '  <text class="mono" x="88" y="176"><tspan fill="#59e3c2">$</tspan> python3 -B -m git_dag_lab pack-verify</text>',
        f'  <text class="mono" x="88" y="225">{_xml_text(before_pack)}</text>',
        f'  <text class="mono" x="88" y="265">pack_sha1={pack_digest}</text>',
        f'  <text class="mono" x="88" y="305">receipt_sha256={receipt_digest}</text>',
        f'  <text class="small" x="88" y="353">verify.txt SHA-256 · {_sha256(verify_output)}</text>',
        f'  <text class="small" x="55" y="445">Report receipt SHA-256 · {receipt}</text>',
        "</svg>\n",
    ]
    return "\n".join(parts).encode("utf-8")


def _report_html(document: Mapping[str, Any], verify_output: bytes) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    pack = report["pack"]
    index = report["index"]
    checks = report["checks"]
    objects = report["objects_in_pack_order"]
    transcript = html.escape(verify_output.decode("utf-8").rstrip("\n"))
    object_rows = "".join(
        f'''<tr><td>{html.escape(row["label"])}</td><td><code>{row["oid"]}</code></td><td>{row["size"]}</td><td>{row["offset"]}</td><td><code>{row["crc32"]}</code></td></tr>'''
        for row in objects
    )
    check_rows = "".join(
        f"<li><span>✓</span>{html.escape(name.replace('_', ' '))}</li>"
        for name, passed in checks.items()
        if passed
    )
    text = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Git pack/index evidence — verified offline report</title>
  <style>
    *{{box-sizing:border-box}}:root{{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#06101d;color:#f8fafc}}body{{margin:0;background:radial-gradient(circle at 82% 0,#183555 0,transparent 36%),linear-gradient(145deg,#06101d,#0d1729 65%,#101b31)}}main{{width:100%;min-height:1500px;padding:58px 70px}}.eyebrow{{color:#59e3c2;font:700 14px ui-monospace,monospace;letter-spacing:.16em;text-transform:uppercase}}h1{{margin:18px 0;font-size:62px;line-height:1.04;letter-spacing:-.04em}}.lede{{max-width:980px;color:#b9c8e3;font-size:21px;line-height:1.5}}.receipt,pre,.panel{{border:1px solid #294366;background:#091526}}.receipt{{display:inline-block;padding:13px 16px;border-radius:10px;color:#b8c8e4;font:13px ui-monospace,monospace}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:38px 0}}.metric,.panel{{border-radius:17px;padding:23px;box-shadow:0 18px 50px rgba(0,0,0,.2)}}.metric{{background:#0c182b;border:1px solid #294366}}.metric strong{{display:block;font-size:35px}}.metric span{{color:#93a8ca}}.grid{{display:grid;grid-template-columns:1.25fr .75fr;gap:20px}}h2{{margin:0 0 16px;font-size:25px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:13px 10px;border-bottom:1px solid #213655;text-align:left;font-size:13px}}th{{color:#93a8ca;text-transform:uppercase;letter-spacing:.08em}}code{{font-family:ui-monospace,monospace;color:#dce7fb;overflow-wrap:anywhere}}.checks{{list-style:none;margin:0;padding:0;display:grid;gap:9px}}.checks li{{display:flex;gap:11px;align-items:center;padding:11px;background:#07111f;border-radius:10px;text-transform:capitalize}}.checks span{{display:grid;place-items:center;width:25px;height:25px;border-radius:50%;background:#123b35;color:#59e3c2;font-weight:900}}pre{{margin:20px 0 0;padding:22px;border-radius:14px;white-space:pre-wrap;overflow-wrap:anywhere;color:#dce7fb;font:14px/1.65 ui-monospace,monospace}}.binding{{margin-top:20px;padding:19px;border:1px solid #2fd6af;border-radius:14px;background:#0d2a29}}footer{{display:flex;justify-content:space-between;margin-top:28px;padding-top:22px;border-top:1px solid #263957;color:#8fa4c5;font-size:13px}}
  </style>
</head>
<body>
<main data-pack-receipt="{receipt}" data-object-count="3" data-check-count="7">
  <p class="eyebrow">Git pack/index lab · actual offline report</p>
  <h1>Pack v2.<br>Index v2.</h1>
  <p class="lede">Real <code>git pack-objects</code> output is decoded independently: bounded zlib entries, logical object IDs, fanout ranges, CRC32 rows, offsets, and both file checksums.</p>
  <div class="receipt">PASS · report receipt {receipt}</div>
  <section class="metrics">
    <div class="metric"><strong>3</strong><span>packed objects</span></div>
    <div class="metric"><strong>{pack["bytes"]}</strong><span>actual pack bytes</span></div>
    <div class="metric"><strong>{index["bytes"]}</strong><span>actual index bytes</span></div>
    <div class="metric"><strong>7/7</strong><span>checks passed</span></div>
  </section>
  <div class="grid">
    <section class="panel"><h2>Objects in physical pack order</h2><table><thead><tr><th>fixture</th><th>OID</th><th>size</th><th>offset</th><th>CRC32</th></tr></thead><tbody>{object_rows}</tbody></table></section>
    <section class="panel"><h2>Independent gate</h2><ul class="checks">{check_rows}</ul></section>
  </div>
  <section class="panel" style="margin-top:20px"><h2>Real CLI receipt</h2><pre>$ python3 -B -m git_dag_lab pack-verify\n{transcript}</pre><div class="binding"><strong>Pack trailer</strong><br><code>{pack["trailer_sha1"]}</code><br><br><strong>Index checksum</strong><br><code>{index["index_sha1"]}</code><p>Delta support: false · authentication claim: false · network required: false</p></div></section>
  <footer><span>Generated offline · no JavaScript · no external assets</span><code>evidence/git-pack-index-v1.json</code></footer>
</main>
</body>
</html>
'''
    return text.encode("utf-8")


def _capture_path_is_safe_if_present(path: Path) -> None:
    target = ROOT / path
    if target.exists() and (not target.is_file() or target.is_symlink()):
        raise EvidenceError(f"unsafe pack capture path: {path.as_posix()}")


def _load_capture(
    report_content: bytes,
    receipt: str,
    *,
    allow_missing: bool,
) -> PackCapture | None:
    for path in (SCREENSHOT_PATH, RENDERED_DOM_PATH, ATTESTATION_PATH):
        _capture_path_is_safe_if_present(path)
    if allow_missing:
        return None
    present = [
        (ROOT / path).is_file()
        for path in (SCREENSHOT_PATH, RENDERED_DOM_PATH, ATTESTATION_PATH)
    ]
    if not all(present):
        raise EvidenceError("pack browser capture is missing")

    screenshot = _safe_capture_bytes(SCREENSHOT_PATH, "pack screenshot")
    rendered_dom = _safe_capture_bytes(RENDERED_DOM_PATH, "pack rendered DOM")
    attestation = _safe_capture_bytes(ATTESTATION_PATH, "pack capture attestation")
    if _parse_pack_png(screenshot) != PNG_DIMENSIONS:
        raise EvidenceError("pack screenshot dimensions differ from the contract")
    try:
        dom_text = rendered_dom.decode("utf-8")
        document = json.loads(attestation)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("pack browser capture metadata is malformed") from exc
    required = (
        f'data-pack-receipt="{receipt}"',
        'data-object-count="3"',
        'data-check-count="7"',
        "Pack v2.",
        "Index v2.",
        "packed objects",
    )
    if not all(marker in dom_text for marker in required):
        raise EvidenceError("pack rendered DOM sentinels are incomplete")
    if any(marker in dom_text for marker in ("/home/", "ERR_FILE", "github.com/")):
        raise EvidenceError("pack rendered DOM contains a forbidden marker")
    if set(document) != {"attestation", "receipt"}:
        raise EvidenceError("pack capture attestation shape is invalid")
    payload = document["attestation"]
    attestation_receipt = document["receipt"].get("sha256")
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if attestation_receipt != _sha256(canonical):
        raise EvidenceError("pack capture attestation receipt is invalid")
    try:
        report_row = payload["input"]["report"]
        dom_row = payload["outputs"]["rendered_dom"]
        screenshot_row = payload["outputs"]["screenshot"]
        script_row = payload["script"]
    except (KeyError, TypeError) as exc:
        raise EvidenceError("pack capture attestation rows are incomplete") from exc
    script_path = Path("tools/capture_pack_report.sh")
    script_content = _safe_capture_bytes(script_path, "pack capture script")
    if (
        payload.get("schema_version") != "git-pack-browser-capture-attestation/v1"
        or payload.get("browser", {}).get("binary_path") != BROWSER_PATH
        or payload.get("browser", {}).get("sha256") != BROWSER_SHA256
        or payload.get("browser", {}).get("version") != BROWSER_VERSION
        or payload.get("container", {}).get("image") != CONTAINER_IMAGE
        or payload.get("container", {}).get("architecture") != "amd64"
        or payload.get("isolation", {}).get("network") != "none"
        or payload.get("isolation", {}).get("root_filesystem") != "read-only"
        or payload.get("isolation", {}).get("demo_mount") != "read-only"
        or payload.get("isolation", {}).get("capabilities") != "all-dropped"
        or payload.get("isolation", {}).get("no_new_privileges") is not True
        or payload.get("viewport") != {
            "device_scale_factor": 1,
            "height": PNG_DIMENSIONS[1],
            "width": PNG_DIMENSIONS[0],
        }
        or report_row.get("path") != REPORT_PATH.as_posix()
        or report_row.get("sha256") != _sha256(report_content)
        or report_row.get("size") != len(report_content)
        or report_row.get("report_receipt_sha256") != receipt
        or dom_row.get("path") != RENDERED_DOM_PATH.as_posix()
        or dom_row.get("sha256") != _sha256(rendered_dom)
        or dom_row.get("size") != len(rendered_dom)
        or screenshot_row.get("path") != SCREENSHOT_PATH.as_posix()
        or screenshot_row.get("sha256") != _sha256(screenshot)
        or screenshot_row.get("size") != len(screenshot)
        or screenshot_row.get("width") != PNG_DIMENSIONS[0]
        or screenshot_row.get("height") != PNG_DIMENSIONS[1]
        or script_row.get("path") != script_path.as_posix()
        or script_row.get("sha256") != _sha256(script_content)
        or script_row.get("size") != len(script_content)
    ):
        raise EvidenceError("pack capture attestation does not bind current inputs")
    return PackCapture(
        screenshot=screenshot,
        rendered_dom=rendered_dom,
        attestation=attestation,
        document=document,
    )


def build_artifacts(*, allow_missing_screenshot: bool) -> dict[Path, bytes]:
    verify_output, compact_output, pretty_output, document = _collect_cli()
    report_content = _report_html(document, verify_output)
    receipt = document["receipt"]["sha256"]
    capture = _load_capture(
        report_content,
        receipt,
        allow_missing=allow_missing_screenshot,
    )
    generated = {
        EVIDENCE_PATH: compact_output,
        VERIFY_PATH: verify_output,
        INSPECT_PATH: pretty_output,
        REPORT_PATH: report_content,
        LAYOUT_PATH: _layout_svg(document),
        FANOUT_PATH: _fanout_svg(document),
        INTEGRITY_PATH: _integrity_svg(document),
        CLI_PATH: _cli_svg(document, verify_output),
    }
    roles = {
        EVIDENCE_PATH: "canonical compact pack/index CLI evidence",
        VERIFY_PATH: "exact pack-verify stdout",
        INSPECT_PATH: "exact pretty pack-inspect stdout",
        REPORT_PATH: "dependency-free pack/index offline report",
        LAYOUT_PATH: "actual pack and index byte layout",
        FANOUT_PATH: "actual index fanout ranges and sorted object IDs",
        INTEGRITY_PATH: "pack/index integrity chain derived from the receipt",
        CLI_PATH: "visualized exact pack-verify transcript",
    }
    artifact_rows = [
        _artifact_row(path, generated[path], roles[path]) for path in sorted(generated)
    ]
    capture_manifest: dict[str, Any] = {
        "attestation": ATTESTATION_PATH.as_posix(),
        "browser_binary": BROWSER_PATH,
        "browser_sha256": BROWSER_SHA256,
        "browser_version": BROWSER_VERSION,
        "container_image": CONTAINER_IMAGE,
        "network": "none",
        "status": "not-attested",
        "viewport": {"height": PNG_DIMENSIONS[1], "width": PNG_DIMENSIONS[0]},
    }
    if capture is not None:
        artifact_rows.extend(
            (
                _artifact_row(
                    SCREENSHOT_PATH,
                    capture.screenshot,
                    "attested pack/index offline report browser capture",
                ),
                _artifact_row(
                    RENDERED_DOM_PATH,
                    capture.rendered_dom,
                    "actual DOM emitted during the pack report capture",
                ),
                _artifact_row(
                    ATTESTATION_PATH,
                    capture.attestation,
                    "pack capture provenance and isolation attestation",
                ),
            )
        )
        capture_manifest.update(
            {
                "attestation_receipt_sha256": capture.document["receipt"]["sha256"],
                "rendered_dom_sha256": _sha256(capture.rendered_dom),
                "screenshot_sha256": _sha256(capture.screenshot),
                "status": "attested",
            }
        )
    artifact_rows.sort(key=lambda row: row["path"])
    manifest = {
        "artifacts": artifact_rows,
        "capture": capture_manifest,
        "commands": [
            {
                "argv": ["python3", "-B", "-m", "git_dag_lab", "pack-verify"],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": VERIFY_PATH.as_posix(),
            },
            {
                "argv": [
                    "python3",
                    "-B",
                    "-m",
                    "git_dag_lab",
                    "pack-inspect",
                    "--compact",
                ],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": EVIDENCE_PATH.as_posix(),
            },
            {
                "argv": ["python3", "-B", "-m", "git_dag_lab", "pack-inspect"],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": INSPECT_PATH.as_posix(),
            },
        ],
        "report_receipt_sha256": receipt,
        "schema_version": "git-pack-index-evidence-manifest/v1",
        "sources": [
            _source_row(Path("git_dag_lab/pack.py")),
            _source_row(Path("git_dag_lab/cli.py")),
            _source_row(Path("tools/generate_evidence.py")),
            _source_row(Path("tools/generate_pack_evidence.py")),
            _source_row(Path("tools/capture_pack_report.sh")),
        ],
    }
    generated[MANIFEST_PATH] = _json_bytes(manifest, pretty=True)
    _validate_generated(generated, capture, allow_missing_screenshot)
    return generated


def _validate_generated(
    generated: Mapping[Path, bytes],
    capture: PackCapture | None,
    allow_missing_screenshot: bool,
) -> None:
    manifest = json.loads(generated[MANIFEST_PATH])
    rows = {row["path"]: row for row in manifest["artifacts"]}
    for path, content in generated.items():
        if path == MANIFEST_PATH:
            continue
        row = rows.get(path.as_posix())
        if row is None or row["sha256"] != _sha256(content) or row["size"] != len(content):
            raise EvidenceError(f"pack manifest does not bind {path.as_posix()}")
    if capture is not None:
        external = {
            SCREENSHOT_PATH: capture.screenshot,
            RENDERED_DOM_PATH: capture.rendered_dom,
            ATTESTATION_PATH: capture.attestation,
        }
        for path, content in external.items():
            row = rows.get(path.as_posix())
            if row is None or row["sha256"] != _sha256(content) or row["size"] != len(content):
                raise EvidenceError(f"pack manifest does not bind {path.as_posix()}")
        if manifest["capture"].get("status") != "attested":
            raise EvidenceError("pack manifest omits its attested capture")
    elif not allow_missing_screenshot:
        raise EvidenceError("pack manifest has no required browser capture")

    receipt = manifest["report_receipt_sha256"]
    for path in (LAYOUT_PATH, FANOUT_PATH, INTEGRITY_PATH, CLI_PATH, REPORT_PATH):
        text = generated[path].decode("utf-8")
        if receipt not in text:
            raise EvidenceError(f"{path.as_posix()} is not receipt-bound")
        without_namespace = text.replace("http://www.w3.org/2000/svg", "")
        if (
            "https://" in without_namespace
            or "http://" in without_namespace
            or "/home/" in without_namespace
        ):
            raise EvidenceError(f"{path.as_posix()} contains an external reference")
    for path in (LAYOUT_PATH, FANOUT_PATH, INTEGRITY_PATH, CLI_PATH):
        text = generated[path].decode("utf-8")
        if "<title" not in text or "<desc" not in text or 'role="img"' not in text:
            raise EvidenceError(f"{path.as_posix()} lacks accessible SVG metadata")
    report_text = generated[REPORT_PATH].decode("utf-8")
    if "<script" in report_text.lower() or "Pack v2." not in report_text:
        raise EvidenceError("pack offline report is executable or incomplete")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="write generated evidence")
    action.add_argument("--check", action="store_true", help="verify checked-in evidence")
    parser.add_argument(
        "--allow-missing-screenshot",
        action="store_true",
        help="permit the pre-capture package used by capture_pack_report.sh",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        generated = build_artifacts(
            allow_missing_screenshot=args.allow_missing_screenshot
        )
        if args.write:
            _write_artifacts(generated)
        else:
            _check_artifacts(generated)
    except EvidenceError as exc:
        print(f"pack evidence error: {exc}", file=sys.stderr)
        return 1
    action = "wrote" if args.write else "verified"
    screenshot = "optional" if args.allow_missing_screenshot else "required"
    print(
        f"PASS pack-evidence {action} artifacts={len(generated)} "
        f"screenshot={screenshot}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
