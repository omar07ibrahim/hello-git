#!/usr/bin/env python3
"""Generate and verify source-bound evidence for the real OFS_DELTA fixture."""

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
import shutil
import stat
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))

from tools.generate_evidence import (
    BROWSER_PATH,
    BROWSER_SHA256,
    BROWSER_VERSION,
    CONTAINER_IMAGE,
    EvidenceError,
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
from tools.generate_pack_evidence import _parse_pack_png


EVIDENCE_PATH = Path("evidence/git-pack-ofs-delta-v1.json")
DEMO_ROOT = Path("docs/demo/git-pack-ofs-delta-v1")
VERIFY_PATH = DEMO_ROOT / "verify.txt"
INSPECT_PATH = DEMO_ROOT / "inspect.json"
REPORT_PATH = DEMO_ROOT / "report.html"
MANIFEST_PATH = DEMO_ROOT / "manifest.json"
RENDERED_DOM_PATH = DEMO_ROOT / "rendered-dom.html"
ATTESTATION_PATH = DEMO_ROOT / "capture-attestation.json"
RECONSTRUCTION_PATH = Path("docs/assets/git-pack-ofs-reconstruction.svg")
WORKFLOW_PATH = Path("docs/assets/git-pack-ofs-workflow.svg")
CLI_PATH = Path("docs/assets/git-pack-ofs-cli.svg")
SCREENSHOT_PATH = Path("docs/assets/git-pack-ofs-report.png")
PNG_DIMENSIONS = (1440, 1500)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_BYTES_RE = re.compile(r"^(?:[0-9a-f]{2}){1,3}$")
EXPECTED_ARGV = [
    "git",
    "pack-objects",
    "--delta-base-offset",
    "--window=2",
    "--depth=1",
    "--threads=1",
    "--compression=0",
    "--no-reuse-delta",
    "--no-reuse-object",
    "--index-version=2",
    "<private>/fixture",
]
EXPECTED_CHECKS = {
    "all_fixture_objects_present",
    "exactly_one_full_entry",
    "exactly_one_ofs_delta_entry",
    "index_checksum_verified",
    "index_crc32_matches_pack",
    "index_fanout_matches_sorted_oids",
    "index_offsets_match_pack",
    "ofs_base_entry_bound",
    "ofs_distance_reencoded",
    "pack_trailer_verified",
    "reconstructed_objects_match_fixture",
    "ref_delta_entries_absent",
}


@dataclass(frozen=True, slots=True)
class OfsCapture:
    screenshot: bytes
    rendered_dom: bytes
    attestation: bytes
    document: Mapping[str, Any]


def _ofs_svg_header(
    title: str,
    description: str,
    *,
    width: int,
    height: int,
    receipt: str,
    metadata_extra: Mapping[str, Any] | None = None,
) -> str:
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


def _cli_environment() -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }


def _run_cli(arguments: Sequence[str]) -> bytes:
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "git_dag_lab", *arguments],
        cwd=ROOT,
        env=_cli_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise EvidenceError(f"OFS CLI {' '.join(arguments)} failed")
    if completed.stderr:
        raise EvidenceError(f"OFS CLI {' '.join(arguments)} wrote to stderr")
    return completed.stdout


def _collect_cli() -> tuple[bytes, bytes, bytes, dict[str, Any]]:
    first = (
        _run_cli(("pack-ofs-verify",)),
        _run_cli(("pack-ofs-inspect", "--compact")),
        _run_cli(("pack-ofs-inspect",)),
    )
    second = (
        _run_cli(("pack-ofs-verify",)),
        _run_cli(("pack-ofs-inspect", "--compact")),
        _run_cli(("pack-ofs-inspect",)),
    )
    if first != second:
        raise EvidenceError("two fresh OFS CLI runs produced different evidence")
    verify_output, compact_output, pretty_output = first
    try:
        compact_document = json.loads(compact_output)
        pretty_document = json.loads(pretty_output)
    except json.JSONDecodeError as exc:
        raise EvidenceError("OFS inspection output is not JSON") from exc
    if compact_document != pretty_document:
        raise EvidenceError("compact and pretty OFS documents differ")
    if compact_output != _json_bytes(compact_document, pretty=False):
        raise EvidenceError("compact OFS inspection output is not canonical JSON")
    if pretty_output != _json_bytes(pretty_document, pretty=True):
        raise EvidenceError("pretty OFS inspection output is not canonical JSON")
    _validate_document(compact_document, verify_output)
    return verify_output, compact_output, pretty_output, compact_document


def _validate_document(document: Mapping[str, Any], verify_output: bytes) -> None:
    if set(document) != {"receipt", "report"}:
        raise EvidenceError("OFS evidence has unexpected top-level fields")
    report = document.get("report")
    receipt = document.get("receipt")
    if not isinstance(report, dict) or not isinstance(receipt, dict):
        raise EvidenceError("OFS evidence sections are malformed")
    if report.get("schema_version") != "git-pack-ofs-delta-lab/v1":
        raise EvidenceError("unexpected OFS evidence schema")

    receipt_sha = receipt.get("sha256")
    if not isinstance(receipt_sha, str) or not SHA256_RE.fullmatch(receipt_sha):
        raise EvidenceError("OFS receipt is malformed")
    canonical = json.dumps(
        report,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if _sha256(canonical) != receipt_sha:
        raise EvidenceError("OFS receipt does not bind the canonical report")

    pack = report.get("pack", {})
    index = report.get("index", {})
    checks = report.get("checks", {})
    scope = report.get("scope", {})
    fixture = report.get("fixture", {})
    objects = report.get("objects_in_pack_order", [])
    pack_objects = report.get("pack_objects", {})
    if (
        pack.get("version") != 2
        or pack.get("object_count") != 2
        or pack.get("full_count") != 1
        or pack.get("delta_count") != 1
        or pack.get("ofs_delta_count") != 1
        or pack.get("ref_delta_count") != 0
        or pack.get("max_delta_depth") != 1
        or not isinstance(pack.get("bytes"), int)
        or not 32 < pack["bytes"] <= 1_048_576
        or not SHA1_RE.fullmatch(pack.get("trailer_sha1", ""))
        or not SHA256_RE.fullmatch(pack.get("sha256", ""))
    ):
        raise EvidenceError("OFS pack summary is outside the reviewed fixture")
    if (
        index.get("version") != 2
        or index.get("pack_sha1") != pack["trailer_sha1"]
        or not isinstance(index.get("bytes"), int)
        or not 1_064 < index["bytes"] <= 1_048_576
        or not SHA1_RE.fullmatch(index.get("index_sha1", ""))
        or not SHA256_RE.fullmatch(index.get("sha256", ""))
    ):
        raise EvidenceError("OFS index summary is outside the reviewed fixture")
    if set(checks) != EXPECTED_CHECKS or not all(
        value is True for value in checks.values()
    ):
        raise EvidenceError("not every OFS pack/index check passed")

    mutation = fixture.get("changed_record", {})
    fixture_rows = fixture.get("objects", [])
    if (
        fixture.get("object_count") != 2
        or len(fixture_rows) != 2
        or len(objects) != 2
        or mutation
        != {
            "after": "1024:fedcba9876543210fedcba9876543210",
            "before": "1024:0123456789abcdef0123456789abcdef",
            "line_number": 1024,
        }
    ):
        raise EvidenceError("OFS fixture inventory or mutation is not exact")
    fixture_by_oid: dict[str, Mapping[str, Any]] = {}
    for row in fixture_rows:
        oid = row.get("oid", "")
        if (
            not SHA1_RE.fullmatch(oid)
            or not SHA256_RE.fullmatch(row.get("payload_sha256", ""))
            or row.get("size") != 77_824
            or row.get("label") not in {"baseline", "line-1024-changed"}
        ):
            raise EvidenceError("OFS fixture row is malformed")
        fixture_by_oid[oid] = row
    if len(fixture_by_oid) != 2:
        raise EvidenceError("OFS fixture object IDs are not unique")

    full, delta = objects
    for row in objects:
        fixture_row = fixture_by_oid.get(row.get("oid", ""))
        if (
            fixture_row is None
            or row.get("object_type") != "blob"
            or row.get("size") != 77_824
            or row.get("size") != fixture_row.get("size")
            or row.get("payload_sha256") != fixture_row.get("payload_sha256")
            or row.get("label") != fixture_row.get("label")
            or row.get("offset") != row.get("index_offset")
            or row.get("crc32") != row.get("index_crc32")
            or not isinstance(row.get("packed_size"), int)
            or row["packed_size"] < 1
        ):
            raise EvidenceError("OFS object row is not fixture- and index-bound")
    if (
        full.get("representation") != "full"
        or delta.get("representation") != "ofs-delta"
        or delta.get("base_offset") != full.get("offset")
        or delta.get("base_oid") != full.get("oid")
        or delta.get("delta_depth") != 1
        or not isinstance(delta.get("stored_size"), int)
        or not 4 <= delta["stored_size"] <= 262_144
        or not isinstance(delta.get("ofs_distance"), int)
        or delta["ofs_distance"] != delta["offset"] - full["offset"]
        or delta["ofs_distance"] < 1
        or not HEX_BYTES_RE.fullmatch(delta.get("ofs_offset_bytes_hex", ""))
    ):
        raise EvidenceError("OFS physical base/delta relationship is incomplete")

    oid_order = pack_objects.get("stdin_oid_order", [])
    if (
        pack_objects.get("normalized_argv") != EXPECTED_ARGV
        or pack_objects.get("stdin_bytes") != 82
        or oid_order != sorted(fixture_by_oid)
        or not SHA256_RE.fullmatch(pack_objects.get("stdin_sha256", ""))
        or report.get("command_trace")
        != ["init", "hash-object", "hash-object", "pack-objects"]
    ):
        raise EvidenceError("OFS command provenance is incomplete")
    if (
        scope.get("arbitrary_repository_supported") is not False
        or scope.get("authentication_claim") is not False
        or scope.get("byte_identity_requires_same_git_build") is not True
        or scope.get("git_pack_objects_executed") is not True
        or scope.get("network_required") is not False
        or scope.get("ofs_delta_supported") is not True
        or scope.get("ref_delta_supported") is not False
        or scope.get("thin_pack_supported") is not False
    ):
        raise EvidenceError("OFS scope and non-claims are incomplete")

    expected_verify = (
        f"PASS git-pack-ofs-delta-lab/v1 objects=2 pack_version=2 "
        f"index_version=2 deltas=1 pack_sha1={pack['trailer_sha1']} "
        f"receipt_sha256={receipt_sha}\n"
    ).encode("ascii")
    if verify_output != expected_verify:
        raise EvidenceError("OFS verification transcript is not exact")
    rendered = json.dumps(document, ensure_ascii=True, sort_keys=True)
    forbidden = ("/home/", "github.com/", "@gmail.com", "AKIA", "ghp_", "github_pat_")
    if any(marker.lower() in rendered.lower() for marker in forbidden):
        raise EvidenceError("OFS evidence contains host, remote, or credential material")


def _bounded_binary_hash(path: Path, *, label: str) -> str:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise EvidenceError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > 100 * 1024 * 1024
    ):
        raise EvidenceError(f"{label} is outside the evidence bound")
    try:
        return _sha256(resolved.read_bytes())
    except OSError as exc:
        raise EvidenceError(f"{label} could not be read") from exc


def _git_environment_proof() -> dict[str, object]:
    candidate = shutil.which("git", path=_cli_environment()["PATH"])
    if candidate is None:
        raise EvidenceError("Git executable is unavailable for OFS provenance")
    git = Path(candidate).resolve(strict=True)
    version = subprocess.run(
        [os.fspath(git), "version"],
        cwd=ROOT,
        env=_cli_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        timeout=10,
    )
    exec_path = subprocess.run(
        [os.fspath(git), "--exec-path"],
        cwd=ROOT,
        env=_cli_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        timeout=10,
    )
    if (
        version.returncode != 0
        or version.stderr
        or exec_path.returncode != 0
        or exec_path.stderr
    ):
        raise EvidenceError("Git build provenance commands failed")
    try:
        version_text = version.stdout.decode("ascii").strip()
        exec_path_text = exec_path.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise EvidenceError("Git build provenance output is malformed") from exc
    if not re.fullmatch(r"git version [0-9]+(?:\.[0-9]+){1,3}", version_text):
        raise EvidenceError("Git version string is outside the reviewed form")
    pack_objects = Path(exec_path_text) / "git-pack-objects"
    return {
        "byte_identity_scope": "same recorded Git build",
        "frontend_sha256": _bounded_binary_hash(git, label="Git frontend"),
        "pack_objects_sha256": _bounded_binary_hash(
            pack_objects,
            label="Git pack-objects executable",
        ),
        "version": version_text,
    }


def _reconstruction_svg(document: Mapping[str, Any]) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    pack = report["pack"]
    full, delta = report["objects_in_pack_order"]
    parts = [
        _ofs_svg_header(
            "Real OFS_DELTA reconstruction",
            "Physical offsets, the biased backward distance, logical object sizes, and reconstructed object IDs come from the verified Git-generated pack.",
            width=1440,
            height=760,
            receipt=receipt,
            metadata_extra={
                "base_oid": full["oid"],
                "delta_oid": delta["oid"],
                "pack_sha256": pack["sha256"],
            },
        ),
        '  <text class="eyebrow" x="55" y="58">REAL GIT PACK · ONE FULL BLOB · ONE OFS_DELTA · ZERO REF_DELTA</text>',
        '  <text class="heading" x="55" y="104">A physical backward edge reconstructs a new logical blob.</text>',
        '  <rect class="node" filter="url(#shadow)" x="55" y="170" width="390" height="250" rx="18"/>',
        '  <text class="eyebrow" x="85" y="211">BASE ENTRY · FULL</text>',
        f'  <text class="heading" style="font-size:27px" x="85" y="254">offset {full["offset"]}</text>',
        f'  <text class="body" x="85" y="296">{full["packed_size"]} packed bytes · {full["size"]} logical bytes</text>',
        f'  <text class="small" x="85" y="340">{_xml_text(full["label"])}</text>',
        f'  <text class="mono" x="85" y="382">{full["oid"]}</text>',
        '  <rect class="node" filter="url(#shadow)" x="790" y="170" width="595" height="250" rx="18"/>',
        '  <text class="eyebrow" x="820" y="211">DELTA ENTRY · TYPE 6</text>',
        f'  <text class="heading" style="font-size:27px" x="820" y="254">offset {delta["offset"]} − distance {delta["ofs_distance"]}</text>',
        f'  <text class="body" x="820" y="296">biased bytes 0x{delta["ofs_offset_bytes_hex"]} · program {delta["stored_size"]} bytes</text>',
        f'  <text class="small" x="820" y="340">{_xml_text(delta["label"])} · depth {delta["delta_depth"]}</text>',
        f'  <text class="mono" x="820" y="382">{delta["oid"]}</text>',
        '  <path class="edge" d="M 790 282 C 665 282 575 282 445 282"/>',
        f'  <text class="small" x="515" y="259">base_offset = {delta["base_offset"]}</text>',
        '  <rect x="55" y="485" width="1330" height="170" rx="18" fill="#102b2c" stroke="#2fd6af"/>',
        f'  <text class="eyebrow" x="85" y="528">INDEPENDENT REPLAY · {len(report["checks"])}/{len(report["checks"])} CHECKS</text>',
        f'  <text class="body" x="85" y="572">Base OID {full["oid"]} → apply bounded copy/insert program → target OID {delta["oid"]}</text>',
        f'  <text class="body" x="85" y="610">Index v2 binds physical offsets {full["index_offset"]} and {delta["index_offset"]}, plus CRC32 {full["crc32"]} and {delta["crc32"]}.</text>',
        f'  <text class="small" x="85" y="640">receipt {receipt}</text>',
        "</svg>\n",
    ]
    return "\n".join(parts).encode("utf-8")


def _workflow_svg(
    document: Mapping[str, Any],
    git_environment: Mapping[str, object],
) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    command = report["pack_objects"]["normalized_argv"]
    stages = (
        ("FIXTURE", "2 × 77,824 B"),
        ("REAL GIT", git_environment["version"]),
        ("PACK PARSER", "OFS replay"),
        ("INDEX V2", "offset + CRC"),
        ("RECEIPT", receipt[:16] + "…"),
    )
    parts = [
        _ofs_svg_header(
            "Reproducible OFS evidence workflow",
            "The exact fixed inputs, normalized Git arguments, independent parser, index cross-check, and receipt shown here are bound into the evidence manifest.",
            width=1440,
            height=690,
            receipt=receipt,
            metadata_extra={
                "git_frontend_sha256": git_environment["frontend_sha256"],
                "stdin_sha256": report["pack_objects"]["stdin_sha256"],
            },
        ),
        '  <text class="eyebrow" x="55" y="58">FIXED INPUTS · SINGLE THREAD · SAME RECORDED GIT BUILD · FRESH RUNS ×2</text>',
        '  <text class="heading" x="55" y="104">From two synthetic blobs to one source-bound receipt.</text>',
    ]
    x_values = (35, 315, 595, 875, 1155)
    for number, ((title, detail), x) in enumerate(zip(stages, x_values, strict=True), 1):
        visible = str(detail) if len(str(detail)) <= 24 else str(detail)[:20] + "…"
        parts.extend(
            (
                f'  <rect class="node" filter="url(#shadow)" x="{x}" y="165" width="245" height="200" rx="18"/>',
                f'  <text class="eyebrow" x="{x + 24}" y="205">0{number}</text>',
                f'  <text class="heading" style="font-size:21px" x="{x + 24}" y="248">{title}</text>',
                f'  <text class="small" x="{x + 24}" y="290">{_xml_text(visible)}</text>',
                f'  <text class="small" x="{x + 24}" y="326">PASS</text>',
            )
        )
        if number < len(stages):
            parts.append(f'  <path class="edge" d="M {x + 250} 265 L {x + 275} 265"/>')
    first_line = " ".join(command[:6])
    second_line = " ".join(command[6:])
    parts.extend(
        (
            '  <rect x="35" y="425" width="1365" height="190" rx="16" fill="#07111f" stroke="#30476f"/>',
            f'  <text class="mono" x="62" y="469">$ {_xml_text(first_line)}</text>',
            f'  <text class="mono" x="62" y="505">  {_xml_text(second_line)}</text>',
            f'  <text class="small" x="62" y="552">stdin SHA-256 {report["pack_objects"]["stdin_sha256"]}</text>',
            f'  <text class="small" x="62" y="582">Git frontend SHA-256 {git_environment["frontend_sha256"]} · byte identity scope: same recorded build</text>',
            "</svg>\n",
        )
    )
    return "\n".join(parts).encode("utf-8")


def _cli_svg(document: Mapping[str, Any], verify_output: bytes) -> bytes:
    receipt = document["receipt"]["sha256"]
    tokens = verify_output.decode("ascii").strip().split()
    lines = (
        " ".join(tokens[:5]),
        " ".join(tokens[5:7]),
        tokens[7],
    )
    parts = [
        _ofs_svg_header(
            "Real OFS_DELTA CLI receipt",
            "Exact stdout from pack-ofs-verify after real git pack-objects output was reconstructed and cross-checked against index v2.",
            width=1440,
            height=560,
            receipt=receipt,
        ),
        '  <text class="eyebrow" x="55" y="58">REAL CLI STDOUT · STDERR 0 BYTES · EXIT 0</text>',
        '  <rect x="55" y="92" width="1330" height="370" rx="18" fill="#050a13" stroke="#30476f"/>',
        '  <circle cx="88" cy="124" r="6" fill="#ff6b6b"/><circle cx="110" cy="124" r="6" fill="#ffd166"/><circle cx="132" cy="124" r="6" fill="#59e3c2"/>',
        '  <text class="mono" x="88" y="176"><tspan fill="#59e3c2">$</tspan> python3 -B -m git_dag_lab pack-ofs-verify</text>',
        f'  <text class="mono" x="88" y="230">{_xml_text(lines[0])}</text>',
        f'  <text class="mono" x="88" y="278">{_xml_text(lines[1])}</text>',
        f'  <text class="mono" x="88" y="326">{_xml_text(lines[2])}</text>',
        f'  <text class="small" x="88" y="390">receipt-bound source · {EVIDENCE_PATH.as_posix()}</text>',
        f'  <text class="small" x="88" y="425">receipt {receipt}</text>',
        "</svg>\n",
    ]
    return "\n".join(parts).encode("utf-8")


def _report_html(
    document: Mapping[str, Any],
    verify_output: bytes,
    git_environment: Mapping[str, object],
) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    pack = report["pack"]
    index = report["index"]
    checks = report["checks"]
    full, delta = report["objects_in_pack_order"]
    transcript = html.escape(verify_output.decode("ascii").rstrip("\n"))
    object_rows = "".join(
        f'''<tr><td>{html.escape(row["representation"])}</td><td>{html.escape(row["label"])}</td><td><code>{row["oid"]}</code></td><td>{row["offset"]}</td><td>{row["stored_size"] if row["representation"] == "ofs-delta" else row["size"]}</td><td><code>{row["crc32"]}</code></td></tr>'''
        for row in report["objects_in_pack_order"]
    )
    check_rows = "".join(
        f"<li><span>✓</span>{html.escape(name.replace('_', ' '))}</li>"
        for name, passed in checks.items()
        if passed
    )
    command = html.escape(" ".join(report["pack_objects"]["normalized_argv"]))
    text = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Git OFS_DELTA evidence — verified offline report</title>
  <style>
    *{{box-sizing:border-box}}:root{{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#06101d;color:#f8fafc}}body{{margin:0;background:radial-gradient(circle at 82% 0,#183555 0,transparent 36%),linear-gradient(145deg,#06101d,#0d1729 65%,#101b31)}}main{{width:100%;min-height:1500px;padding:52px 64px}}.eyebrow{{color:#59e3c2;font:700 14px ui-monospace,monospace;letter-spacing:.16em;text-transform:uppercase}}h1{{margin:16px 0;font-size:58px;line-height:1.04;letter-spacing:-.04em}}.lede{{max-width:1050px;color:#b9c8e3;font-size:20px;line-height:1.48}}.receipt,pre,.panel{{border:1px solid #294366;background:#091526}}.receipt{{display:inline-block;padding:12px 15px;border-radius:10px;color:#b8c8e4;font:13px ui-monospace,monospace}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:28px 0}}.metric,.panel{{border-radius:16px;padding:20px;box-shadow:0 18px 50px rgba(0,0,0,.2)}}.metric{{background:#0c182b;border:1px solid #294366}}.metric strong{{display:block;font-size:32px}}.metric span{{color:#93a8ca}}.grid{{display:grid;grid-template-columns:1.15fr .85fr;gap:18px}}h2{{margin:0 0 14px;font-size:23px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px 8px;border-bottom:1px solid #213655;text-align:left;font-size:12px}}th{{color:#93a8ca;text-transform:uppercase;letter-spacing:.07em}}code{{font-family:ui-monospace,monospace;color:#dce7fb;overflow-wrap:anywhere}}.checks{{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:7px}}.checks li{{display:flex;gap:8px;align-items:center;padding:8px;background:#07111f;border-radius:9px;text-transform:capitalize;font-size:12px}}.checks span{{display:grid;place-items:center;width:22px;height:22px;border-radius:50%;background:#123b35;color:#59e3c2;font-weight:900}}pre{{margin:14px 0 0;padding:17px;border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere;color:#dce7fb;font:12px/1.55 ui-monospace,monospace}}.binding{{margin-top:15px;padding:16px;border:1px solid #2fd6af;border-radius:13px;background:#0d2a29;font-size:13px;line-height:1.45}}footer{{display:flex;justify-content:space-between;margin-top:20px;padding-top:17px;border-top:1px solid #263957;color:#8fa4c5;font-size:12px}}
  </style>
</head>
<body>
<main data-ofs-receipt="{receipt}" data-object-count="2" data-check-count="12">
  <p class="eyebrow">Git pack lab · actual OFS_DELTA offline report</p>
  <h1>One backward edge.<br>Two verified blobs.</h1>
  <p class="lede">Real <code>git pack-objects --delta-base-offset</code> output is decoded without asking Git to replay it: the bounded delta program reconstructs the target, then index v2 independently binds both physical offsets and CRC32 rows.</p>
  <div class="receipt">PASS · report receipt {receipt}</div>
  <section class="metrics">
    <div class="metric"><strong>2</strong><span>logical blobs</span></div>
    <div class="metric"><strong>1</strong><span>physical OFS_DELTA</span></div>
    <div class="metric"><strong>{pack["bytes"]}</strong><span>actual pack bytes</span></div>
    <div class="metric"><strong>12/12</strong><span>checks passed</span></div>
  </section>
  <div class="grid">
    <section class="panel"><h2>Objects in physical pack order</h2><table><thead><tr><th>form</th><th>fixture</th><th>OID</th><th>offset</th><th>stored</th><th>CRC32</th></tr></thead><tbody>{object_rows}</tbody></table><div class="binding"><strong>Base → target</strong><br>offset {full["offset"]} → {delta["offset"]}; biased distance {delta["ofs_distance"]} encoded as <code>{delta["ofs_offset_bytes_hex"]}</code><br><code>{full["oid"]}</code><br>↓ independent copy/insert replay<br><code>{delta["oid"]}</code></div></section>
    <section class="panel"><h2>Independent fail-closed gate</h2><ul class="checks">{check_rows}</ul></section>
  </div>
  <section class="panel" style="margin-top:18px"><h2>Exact command provenance</h2><pre>$ {command}
stdin sha256={report["pack_objects"]["stdin_sha256"]}
Git={html.escape(str(git_environment["version"]))}
frontend sha256={git_environment["frontend_sha256"]}</pre><h2 style="margin-top:16px">Real CLI receipt</h2><pre>$ python3 -B -m git_dag_lab pack-ofs-verify
{transcript}</pre><div class="binding">Index checksum <code>{index["index_sha1"]}</code> · REF_DELTA false · thin pack false · arbitrary repository false · authentication claim false · network required false · exact byte identity scoped to the recorded Git build.</div></section>
  <footer><span>Generated offline · no JavaScript · no external assets</span><code>{EVIDENCE_PATH.as_posix()}</code></footer>
</main>
</body>
</html>
'''
    return text.encode("utf-8")


def _capture_path_is_safe_if_present(path: Path) -> None:
    target = ROOT / path
    if target.exists() and (not target.is_file() or target.is_symlink()):
        raise EvidenceError(f"unsafe OFS capture path: {path.as_posix()}")


def _load_capture(
    report_content: bytes,
    receipt: str,
    *,
    allow_missing: bool,
) -> OfsCapture | None:
    for path in (SCREENSHOT_PATH, RENDERED_DOM_PATH, ATTESTATION_PATH):
        _capture_path_is_safe_if_present(path)
    if allow_missing:
        return None
    present = [
        (ROOT / path).is_file()
        for path in (SCREENSHOT_PATH, RENDERED_DOM_PATH, ATTESTATION_PATH)
    ]
    if not all(present):
        raise EvidenceError("OFS browser capture is missing")

    screenshot = _safe_capture_bytes(SCREENSHOT_PATH, "OFS screenshot")
    rendered_dom = _safe_capture_bytes(RENDERED_DOM_PATH, "OFS rendered DOM")
    attestation = _safe_capture_bytes(ATTESTATION_PATH, "OFS capture attestation")
    if _parse_pack_png(screenshot) != PNG_DIMENSIONS:
        raise EvidenceError("OFS screenshot dimensions differ from the contract")
    try:
        dom_text = rendered_dom.decode("utf-8")
        document = json.loads(attestation)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("OFS browser capture metadata is malformed") from exc
    required = (
        f'data-ofs-receipt="{receipt}"',
        'data-object-count="2"',
        'data-check-count="12"',
        "actual OFS_DELTA",
        "Base → target",
        "Two verified blobs",
    )
    if not all(marker in dom_text for marker in required):
        raise EvidenceError("OFS rendered DOM sentinels are incomplete")
    if any(marker in dom_text for marker in ("/home/", "ERR_FILE", "github.com/")):
        raise EvidenceError("OFS rendered DOM contains a forbidden marker")
    if set(document) != {"attestation", "receipt"}:
        raise EvidenceError("OFS capture attestation shape is invalid")
    payload = document["attestation"]
    attestation_receipt = document["receipt"].get("sha256")
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if attestation_receipt != _sha256(canonical):
        raise EvidenceError("OFS capture attestation receipt is invalid")
    try:
        report_row = payload["input"]["report"]
        dom_row = payload["outputs"]["rendered_dom"]
        screenshot_row = payload["outputs"]["screenshot"]
        script_row = payload["script"]
    except (KeyError, TypeError) as exc:
        raise EvidenceError("OFS capture attestation rows are incomplete") from exc
    script_path = Path("tools/capture_ofs_report.sh")
    script_content = _safe_capture_bytes(script_path, "OFS capture script")
    if (
        payload.get("schema_version")
        != "git-pack-ofs-browser-capture-attestation/v1"
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
        or payload.get("viewport")
        != {
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
        raise EvidenceError("OFS capture attestation does not bind current inputs")
    return OfsCapture(
        screenshot=screenshot,
        rendered_dom=rendered_dom,
        attestation=attestation,
        document=document,
    )


def build_artifacts(*, allow_missing_screenshot: bool) -> dict[Path, bytes]:
    verify_output, compact_output, pretty_output, document = _collect_cli()
    git_environment = _git_environment_proof()
    report_content = _report_html(document, verify_output, git_environment)
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
        RECONSTRUCTION_PATH: _reconstruction_svg(document),
        WORKFLOW_PATH: _workflow_svg(document, git_environment),
        CLI_PATH: _cli_svg(document, verify_output),
    }
    roles = {
        EVIDENCE_PATH: "canonical compact real OFS_DELTA CLI evidence",
        VERIFY_PATH: "exact pack-ofs-verify stdout",
        INSPECT_PATH: "exact pretty pack-ofs-inspect stdout",
        REPORT_PATH: "dependency-free OFS_DELTA offline report",
        RECONSTRUCTION_PATH: "actual OFS base distance and reconstructed object flow",
        WORKFLOW_PATH: "source-bound Git OFS evidence workflow",
        CLI_PATH: "visualized exact pack-ofs-verify transcript",
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
                    "attested OFS_DELTA offline report browser capture",
                ),
                _artifact_row(
                    RENDERED_DOM_PATH,
                    capture.rendered_dom,
                    "actual DOM emitted during the OFS report capture",
                ),
                _artifact_row(
                    ATTESTATION_PATH,
                    capture.attestation,
                    "OFS capture provenance and isolation attestation",
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
                "argv": ["python3", "-B", "-m", "git_dag_lab", "pack-ofs-verify"],
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
                    "pack-ofs-inspect",
                    "--compact",
                ],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": EVIDENCE_PATH.as_posix(),
            },
            {
                "argv": [
                    "python3",
                    "-B",
                    "-m",
                    "git_dag_lab",
                    "pack-ofs-inspect",
                ],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": INSPECT_PATH.as_posix(),
            },
        ],
        "git_build": git_environment,
        "report_receipt_sha256": receipt,
        "schema_version": "git-pack-ofs-evidence-manifest/v1",
        "sources": [
            _source_row(Path("git_dag_lab/__init__.py")),
            _source_row(Path("git_dag_lab/__main__.py")),
            _source_row(Path("git_dag_lab/cli.py")),
            _source_row(Path("git_dag_lab/lab.py")),
            _source_row(Path("git_dag_lab/pack.py")),
            _source_row(Path("tools/generate_evidence.py")),
            _source_row(Path("tools/generate_pack_evidence.py")),
            _source_row(Path("tools/generate_ofs_evidence.py")),
            _source_row(Path("tools/capture_ofs_report.sh")),
        ],
    }
    generated[MANIFEST_PATH] = _json_bytes(manifest, pretty=True)
    _validate_generated(generated, capture, allow_missing_screenshot)
    return generated


def _validate_generated(
    generated: Mapping[Path, bytes],
    capture: OfsCapture | None,
    allow_missing_screenshot: bool,
) -> None:
    manifest = json.loads(generated[MANIFEST_PATH])
    rows = {row["path"]: row for row in manifest["artifacts"]}
    for path, content in generated.items():
        if path == MANIFEST_PATH:
            continue
        row = rows.get(path.as_posix())
        if (
            row is None
            or row["sha256"] != _sha256(content)
            or row["size"] != len(content)
        ):
            raise EvidenceError(f"OFS manifest does not bind {path.as_posix()}")
    if capture is not None:
        external = {
            SCREENSHOT_PATH: capture.screenshot,
            RENDERED_DOM_PATH: capture.rendered_dom,
            ATTESTATION_PATH: capture.attestation,
        }
        for path, content in external.items():
            row = rows.get(path.as_posix())
            if (
                row is None
                or row["sha256"] != _sha256(content)
                or row["size"] != len(content)
            ):
                raise EvidenceError(f"OFS manifest does not bind {path.as_posix()}")
        if manifest["capture"].get("status") != "attested":
            raise EvidenceError("OFS manifest omits its attested capture")
    elif not allow_missing_screenshot:
        raise EvidenceError("OFS manifest has no required browser capture")

    receipt = manifest["report_receipt_sha256"]
    for path in (RECONSTRUCTION_PATH, WORKFLOW_PATH, CLI_PATH, REPORT_PATH):
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
    for path in (RECONSTRUCTION_PATH, WORKFLOW_PATH, CLI_PATH):
        text = generated[path].decode("utf-8")
        if "<title" not in text or "<desc" not in text or 'role="img"' not in text:
            raise EvidenceError(f"{path.as_posix()} lacks accessible SVG metadata")
    report_text = generated[REPORT_PATH].decode("utf-8")
    if "<script" in report_text.lower() or "actual OFS_DELTA" not in report_text:
        raise EvidenceError("OFS offline report is executable or incomplete")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="write generated evidence")
    action.add_argument("--check", action="store_true", help="verify checked-in evidence")
    parser.add_argument(
        "--allow-missing-screenshot",
        action="store_true",
        help="permit the pre-capture package used by capture_ofs_report.sh",
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
        print(f"OFS evidence error: {exc}", file=sys.stderr)
        return 1
    action = "wrote" if args.write else "verified"
    screenshot = "optional" if args.allow_missing_screenshot else "required"
    print(
        f"PASS ofs-evidence {action} artifacts={len(generated)} "
        f"screenshot={screenshot}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
