#!/usr/bin/env python3
"""Generate and verify the checked-in Git DAG evidence package.

Every visible claim is derived from the real CLI document.  The browser image
is intentionally handled by ``capture_report.sh`` and then bound into the
non-self-referential manifest by this generator.
"""

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
import tempfile
from typing import Any
import zlib


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = Path("evidence/git-dag-v1.json")
DEMO_ROOT = Path("docs/demo/git-dag-v1")
VERIFY_PATH = DEMO_ROOT / "verify.txt"
INSPECT_PATH = DEMO_ROOT / "inspect.json"
REPORT_PATH = DEMO_ROOT / "report.html"
MANIFEST_PATH = DEMO_ROOT / "manifest.json"
RENDERED_DOM_PATH = DEMO_ROOT / "rendered-dom.html"
ATTESTATION_PATH = DEMO_ROOT / "capture-attestation.json"
TOPOLOGY_PATH = Path("docs/assets/git-dag-topology.svg")
ENVELOPE_PATH = Path("docs/assets/git-object-envelope.svg")
CLI_PATH = Path("docs/assets/git-dag-cli.svg")
PIPELINE_PATH = Path("docs/assets/evidence-pipeline.svg")
SCREENSHOT_PATH = Path("docs/assets/git-dag-report.png")

CONTAINER_IMAGE = (
    "mcr.microsoft.com/playwright@sha256:"
    "2f29369043d81d6d69a815ceb80760f55e85f5020371ad06a4d996f18503ad1c"
)
BROWSER_PATH = "/ms-playwright/chromium_headless_shell-1193/chrome-linux/headless_shell"
BROWSER_VERSION = "Chromium 140.0.7339.186"
BROWSER_SHA256 = "003728e0b77eb9d52e4d258594bd55ce22ecd245eb6d3b6858fbd844c901ad7d"
PNG_DIMENSIONS = (1440, 1800)
OID_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PNG_BYTES = 20_000_000


class EvidenceError(RuntimeError):
    """Raised when generated evidence is incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class CaptureEvidence:
    """Externally produced browser evidence validated against current sources."""

    screenshot: bytes
    rendered_dom: bytes
    attestation: bytes
    document: Mapping[str, Any]


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _json_bytes(value: Any, *, pretty: bool = True) -> bytes:
    options: dict[str, Any] = {
        "ensure_ascii": True,
        "sort_keys": True,
    }
    if pretty:
        options["indent"] = 2
    else:
        options["separators"] = (",", ":")
    return (json.dumps(value, **options) + "\n").encode("utf-8")


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
    first_verify = _run_cli(("verify",))
    first_compact = _run_cli(("inspect", "--compact"))
    first_pretty = _run_cli(("inspect",))
    second_verify = _run_cli(("verify",))
    second_compact = _run_cli(("inspect", "--compact"))
    second_pretty = _run_cli(("inspect",))
    if (first_verify, first_compact, first_pretty) != (
        second_verify,
        second_compact,
        second_pretty,
    ):
        raise EvidenceError("two fresh CLI runs produced different evidence")
    try:
        compact_document = json.loads(first_compact)
        pretty_document = json.loads(first_pretty)
    except json.JSONDecodeError as exc:
        raise EvidenceError("CLI inspection output is not JSON") from exc
    if compact_document != pretty_document:
        raise EvidenceError("compact and pretty CLI documents differ")
    if first_compact != _json_bytes(compact_document, pretty=False):
        raise EvidenceError("compact inspection output is not canonical JSON")
    if first_pretty != _json_bytes(pretty_document, pretty=True):
        raise EvidenceError("pretty inspection output is not canonical JSON")
    _validate_document(compact_document, first_verify)
    return first_verify, first_compact, first_pretty, compact_document


def _validate_document(document: Mapping[str, Any], verify_output: bytes) -> None:
    if set(document) != {"receipt", "report"}:
        raise EvidenceError("evidence document has unexpected top-level fields")
    report = document["report"]
    receipt = document["receipt"]
    if report.get("schema_version") != "git-dag-lab/v1":
        raise EvidenceError("unexpected report schema")
    receipt_sha = receipt.get("sha256")
    if not isinstance(receipt_sha, str) or not SHA256_RE.fullmatch(receipt_sha):
        raise EvidenceError("report receipt is malformed")
    canonical_report = json.dumps(
        report,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if _sha256(canonical_report) != receipt_sha:
        raise EvidenceError("report receipt does not match canonical report bytes")
    if f"receipt_sha256={receipt_sha}\n".encode("ascii") not in verify_output:
        raise EvidenceError("verify transcript and report receipt differ")
    inventory = report.get("inventory", {})
    if inventory.get("total") != 14 or inventory.get("by_type") != {
        "blob": 3,
        "commit": 5,
        "tree": 6,
    }:
        raise EvidenceError("object inventory differs from the fixed scenario")
    checks = report.get("checks", [])
    if len(checks) != 9 or not all(check.get("passed") is True for check in checks):
        raise EvidenceError("not every documented check passed")
    nodes = report.get("graph", {}).get("nodes", [])
    if {node.get("id") for node in nodes} != {
        "root",
        "feature",
        "docs",
        "merge",
        "replay",
    }:
        raise EvidenceError("commit graph is incomplete")
    for node in nodes:
        if not OID_RE.fullmatch(node.get("oid", "")) or not OID_RE.fullmatch(
            node.get("tree", "")
        ):
            raise EvidenceError("commit graph contains a malformed object ID")
    proof = report.get("proofs", {}).get("object_envelope", {})
    payload_text = proof.get("payload_utf8")
    if not isinstance(payload_text, str):
        raise EvidenceError("object envelope proof has no payload")
    payload = payload_text.encode("utf-8")
    header = f"commit {len(payload)}\0".encode("ascii")
    envelope_oid = hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()
    if (
        proof.get("header_utf8", "").encode("utf-8") != header
        or proof.get("payload_size") != len(payload)
        or proof.get("payload_sha256") != _sha256(payload)
        or proof.get("envelope_sha1") != envelope_oid
        or proof.get("oid") != envelope_oid
        or proof.get("verified") is not True
    ):
        raise EvidenceError("object envelope proof does not reconstruct its object ID")
    rendered = json.dumps(document, ensure_ascii=True, sort_keys=True)
    forbidden = ("/home/", "github.com/", "@gmail.com", "AKIA", "ghp_", "github_pat_")
    if any(marker.lower() in rendered.lower() for marker in forbidden):
        raise EvidenceError("evidence document contains host, remote, or credential material")


def _xml_text(value: Any) -> str:
    return html.escape(str(value), quote=False)


def _svg_header(
    title: str,
    description: str,
    *,
    width: int,
    height: int,
    receipt: str,
    metadata_extra: Mapping[str, Any] | None = None,
) -> str:
    metadata_payload: dict[str, Any] = {
        "report_receipt_sha256": receipt,
        "source": EVIDENCE_PATH.as_posix(),
    }
    if metadata_extra:
        metadata_payload.update(metadata_extra)
    metadata = json.dumps(
        metadata_payload,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc" data-report-receipt="{receipt}">
  <title id="title">{_xml_text(title)}</title>
  <desc id="desc">{_xml_text(description)}</desc>
  <metadata>{_xml_text(metadata)}</metadata>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#07111f"/><stop offset="1" stop-color="#111b31"/></linearGradient>
    <filter id="shadow"><feDropShadow dx="0" dy="8" stdDeviation="10" flood-color="#020617" flood-opacity="0.55"/></filter>
    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#8ea2c8"/></marker>
  </defs>
  <rect width="{width}" height="{height}" rx="24" fill="url(#bg)"/>
  <style>
    .eyebrow {{ font: 700 14px ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 2px; fill: #59e3c2; }}
    .heading {{ font: 700 30px Inter, ui-sans-serif, system-ui, sans-serif; fill: #f8fafc; }}
    .body {{ font: 500 16px Inter, ui-sans-serif, system-ui, sans-serif; fill: #bac8e4; }}
    .mono {{ font: 500 15px ui-monospace, SFMono-Regular, Menlo, monospace; fill: #dce7fb; }}
    .small {{ font: 500 13px Inter, ui-sans-serif, system-ui, sans-serif; fill: #8ea2c8; }}
    .node {{ fill: #14223d; stroke: #38517b; stroke-width: 2; }}
    .edge {{ fill: none; stroke: #8ea2c8; stroke-width: 2.5; marker-end: url(#arrow); }}
  </style>'''


def _topology_svg(document: Mapping[str, Any]) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    nodes = {node["id"]: node for node in report["graph"]["nodes"]}
    positions = {
        "root": (145, 350),
        "feature": (405, 205),
        "docs": (405, 495),
        "merge": (735, 205),
        "replay": (735, 495),
    }
    edges = (
        ("feature", "root"),
        ("docs", "root"),
        ("merge", "feature"),
        ("merge", "docs"),
        ("replay", "docs"),
    )
    parts = [
        _svg_header(
            "Actual Git commit topology",
            "Five verified commits. Arrows point from each commit to the parent object IDs stored in its raw bytes.",
            width=1200,
            height=760,
            receipt=receipt,
        ),
        '  <text class="eyebrow" x="56" y="58">REAL GIT OBJECT GRAPH · SHA-1 OIDS FROM EVIDENCE</text>',
        '  <text class="heading" x="56" y="101">Same tree. Different history.</text>',
        '  <text class="body" x="56" y="132">Arrows point backward to ordered parents, matching the commit payload—not a presentation-only flow.</text>',
    ]
    for child, parent in edges:
        child_x, child_y = positions[child]
        parent_x, parent_y = positions[parent]
        parts.append(
            f'  <path class="edge" d="M {child_x - 90} {child_y} C {child_x - 150} {child_y}, {parent_x + 150} {parent_y}, {parent_x + 90} {parent_y}"/>'
        )
    for name in ("root", "feature", "docs", "merge", "replay"):
        node = nodes[name]
        x, y = positions[name]
        parent_count = len(node["parents"])
        parts.extend(
            (
                f'  <g><title>{name} commit {node["oid"]}; tree {node["tree"]}; ordered parents {", ".join(node["parents"]) or "none"}</title>',
                f'    <rect class="node" filter="url(#shadow)" x="{x - 90}" y="{y - 61}" width="180" height="122" rx="16"/>',
                f'    <text class="heading" style="font-size:21px" text-anchor="middle" x="{x}" y="{y - 20}">{name}</text>',
                f'    <text class="mono" text-anchor="middle" x="{x}" y="{y + 9}">{node["oid"][:12]}</text>',
                f'    <text class="small" text-anchor="middle" x="{x}" y="{y + 38}">{parent_count} parent{"s" if parent_count != 1 else ""}</text>',
                "  </g>",
            )
        )
    same_tree = report["graph"]["same_tree_different_history"]["same_tree"]
    parts.extend(
        (
            '  <rect x="948" y="242" width="205" height="216" rx="18" fill="#102b2c" stroke="#2fd6af" stroke-width="2"/>',
            '  <text class="eyebrow" x="972" y="278">PROVEN INVARIANT</text>',
            '  <text class="heading" style="font-size:22px" x="972" y="318">Same tree</text>',
            f'  <text class="mono" x="972" y="349">{same_tree[:16]}</text>',
            '  <text class="body" x="972" y="386">merge: 2 parents</text>',
            '  <text class="body" x="972" y="414">replay: 1 parent</text>',
            '  <text class="small" x="972" y="442">Distinct commit OIDs</text>',
            '  <line x1="56" y1="665" x2="1144" y2="665" stroke="#263a5d"/>',
            '  <text class="small" x="56" y="700">Ref tips: main → merge · feature → feature · docs → docs · results/rebased-feature → replay</text>',
            f'  <text class="small" x="56" y="726">Report receipt SHA-256 · {receipt}</text>',
            "</svg>\n",
        )
    )
    return "\n".join(parts).encode("utf-8")


def _envelope_svg(document: Mapping[str, Any]) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    proof = report["proofs"]["object_envelope"]
    visible_header = _xml_text(proof["header_utf8"].replace(chr(0), r"\0"))
    visible_header = visible_header.replace(chr(92) * 2 + "0", chr(92) + "0")
    payload_lines = proof["payload_utf8"].rstrip("\n").split("\n")
    parts = [
        _svg_header(
            "Independent Git object envelope verification",
            "The actual merge commit payload, its byte-counted Git header, and independently recomputed SHA-1 object ID.",
            width=1300,
            height=900,
            receipt=receipt,
        ),
        '  <text class="eyebrow" x="58" y="58">ACTUAL COMMIT BYTES · INDEPENDENT ENVELOPE CHECK</text>',
        '  <text class="heading" x="58" y="102">Git hashes the envelope, not the payload alone.</text>',
        '  <rect x="58" y="145" width="1184" height="490" rx="18" fill="#0b1528" stroke="#30476f"/>',
        f'  <text class="eyebrow" x="88" y="186">HEADER · {visible_header}</text>',
        '  <line x1="88" y1="206" x2="1210" y2="206" stroke="#263a5d"/>',
    ]
    y = 242
    for line in payload_lines:
        visible = line if line else "⟨blank line⟩"
        parts.append(f'  <text class="mono" x="88" y="{y}">{_xml_text(visible)}</text>')
        y += 39
    parts.extend(
        (
            '  <path d="M 650 650 L 650 704" stroke="#59e3c2" stroke-width="3" marker-end="url(#arrow)"/>',
            '  <rect x="170" y="718" width="960" height="116" rx="18" fill="#102b2c" stroke="#2fd6af" stroke-width="2"/>',
            '  <text class="eyebrow" text-anchor="middle" x="650" y="755">SHA-1(TYPE + SPACE + SIZE + NUL + PAYLOAD)</text>',
            f'  <text class="mono" text-anchor="middle" x="650" y="792">{proof["envelope_sha1"]}</text>',
            f'  <text class="small" text-anchor="middle" x="650" y="820">payload {proof["payload_size"]} bytes · payload SHA-256 {proof["payload_sha256"][:20]}… · verified true</text>',
            f'  <text class="small" x="58" y="872">Report receipt SHA-256 · {receipt}</text>',
            "</svg>\n",
        )
    )
    return "\n".join(parts).encode("utf-8")


def _cli_svg(document: Mapping[str, Any], verify_output: bytes) -> bytes:
    receipt = document["receipt"]["sha256"]
    transcript = verify_output.decode("utf-8").rstrip("\n")
    prefix, digest = transcript.rsplit("receipt_sha256=", 1)
    parts = [
        _svg_header(
            "Verified Git DAG Lab CLI transcript",
            "Exact checked-in stdout from the real verify command, with its transcript hash and report receipt.",
            width=1300,
            height=420,
            receipt=receipt,
        ),
        '  <text class="eyebrow" x="58" y="58">REAL CLI STDOUT · STDERR 0 BYTES · EXIT 0</text>',
        '  <rect x="58" y="92" width="1184" height="228" rx="18" fill="#050a13" stroke="#30476f"/>',
        '  <circle cx="88" cy="122" r="6" fill="#ff6b6b"/><circle cx="110" cy="122" r="6" fill="#ffd166"/><circle cx="132" cy="122" r="6" fill="#59e3c2"/>',
        '  <text class="mono" x="88" y="171"><tspan fill="#59e3c2">$</tspan> python3 -B -m git_dag_lab verify</text>',
        f'  <text class="mono" x="88" y="218">{_xml_text(prefix)}</text>',
        f'  <text class="mono" x="88" y="255">receipt_sha256={_xml_text(digest)}</text>',
        f'  <text class="small" x="58" y="359">verify.txt SHA-256 · {_sha256(verify_output)}</text>',
        f'  <text class="small" x="58" y="386">Report receipt SHA-256 · {receipt}</text>',
        "</svg>\n",
    ]
    return "\n".join(parts).encode("utf-8")


def _pipeline_svg(
    document: Mapping[str, Any], capture: CaptureEvidence | None
) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    invocation_count = report["execution"]["git_invocations"]
    stages = (
        ("Fixed scenario", "3 blobs · 6 trees · 5 commits"),
        ("Git plumbing", f"{invocation_count} isolated invocations"),
        ("Bare object DB", "private HOME · config ignored"),
        ("Independent verifier", "14 envelopes · refs · DAG"),
        ("Canonical evidence", "JSON · SVG · HTML · PNG"),
    )
    if capture is None:
        capture_line = "capture pending · pinned Chromium configured · network=none"
        capture_metadata: dict[str, Any] = {
            "capture_attestation": ATTESTATION_PATH.as_posix(),
            "capture_status": "not-attested",
        }
    else:
        attestation = capture.document
        screenshot = attestation["attestation"]["outputs"]["screenshot"]
        capture_line = (
            f"attested PNG {screenshot['sha256'][:12]}… · pinned Chromium · network=none"
        )
        capture_metadata = {
            "capture_attestation": ATTESTATION_PATH.as_posix(),
            "capture_attestation_receipt_sha256": attestation["receipt"]["sha256"],
            "capture_status": "attested",
            "container_image": CONTAINER_IMAGE,
            "network": "none",
            "screenshot_sha256": screenshot["sha256"],
        }
    parts = [
        _svg_header(
            "Reproducible evidence pipeline",
            "The actual path from fixed fixture bytes through isolated Git plumbing and independent checks into the checked-in evidence artifacts.",
            width=1400,
            height=520,
            receipt=receipt,
            metadata_extra=capture_metadata,
        ),
        '  <text class="eyebrow" x="58" y="58">REPRODUCIBLE EVIDENCE PIPELINE · NO NETWORK</text>',
        '  <text class="heading" x="58" y="102">Every visual starts from the same verified report receipt.</text>',
    ]
    x_values = (40, 315, 590, 865, 1140)
    for index, ((title, detail), x) in enumerate(zip(stages, x_values, strict=True), 1):
        parts.extend(
            (
                f'  <rect class="node" filter="url(#shadow)" x="{x}" y="178" width="220" height="172" rx="18"/>',
                f'  <text class="eyebrow" x="{x + 24}" y="214">0{index}</text>',
                f'  <text class="heading" style="font-size:20px" x="{x + 24}" y="258">{_xml_text(title)}</text>',
                f'  <text class="body" style="font-size:14px" x="{x + 24}" y="296">{_xml_text(detail)}</text>',
            )
        )
        if index < len(stages):
            parts.append(
                f'  <path class="edge" d="M {x + 229} 264 L {x + 265} 264"/>'
            )
    parts.extend(
        (
            '  <rect x="40" y="390" width="1320" height="70" rx="16" fill="#102b2c" stroke="#2fd6af"/>',
            f'  <text class="body" x="68" y="424">Gate: two fresh CLI runs byte-match · 9/9 checks pass · {_xml_text(capture_line)}</text>',
            f'  <text class="small" x="68" y="449">Report receipt SHA-256 · {receipt}</text>',
            "</svg>\n",
        )
    )
    return "\n".join(parts).encode("utf-8")


def _report_html(document: Mapping[str, Any], verify_output: bytes) -> bytes:
    report = document["report"]
    receipt = document["receipt"]["sha256"]
    nodes = {node["id"]: node for node in report["graph"]["nodes"]}
    proof = report["graph"]["same_tree_different_history"]
    checks = report["checks"]
    check_cards = "".join(
        f'<li><span aria-hidden="true">✓</span><div><strong>{html.escape(check["id"].replace("-", " ").title())}</strong><small>passed</small></div></li>'
        for check in checks
    )
    node_cards = "".join(
        f'''<article class="commit {name}">
          <span class="role">{name}</span>
          <strong>{node["oid"][:12]}</strong>
          <small>{len(node["parents"])} parent{"s" if len(node["parents"]) != 1 else ""}</small>
        </article>'''
        for name, node in nodes.items()
    )
    transcript = html.escape(verify_output.decode("utf-8").rstrip("\n"))
    payload = report["proofs"]["object_envelope"]
    visible_header = html.escape(payload["header_utf8"].replace(chr(0), r"\0"))
    visible_header = visible_header.replace(chr(92) * 2 + "0", chr(92) + "0")
    document_text = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
  <title>Git DAG Evidence Lab — verified offline report</title>
  <style>
    * {{ box-sizing: border-box; }}
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif; background:#06101d; color:#f8fafc; }}
    body {{ margin:0; min-width:320px; background:radial-gradient(circle at 82% 0,#183555 0,transparent 36%),linear-gradient(145deg,#06101d,#0d1729 65%,#101b31); }}
    main {{ width:100%; min-height:1800px; padding:62px 74px 54px; }}
    .eyebrow {{ margin:0 0 16px; color:#59e3c2; font:700 14px ui-monospace,monospace; letter-spacing:.18em; text-transform:uppercase; }}
    h1 {{ max-width:880px; margin:0; font-size:68px; line-height:1.02; letter-spacing:-.045em; }}
    .lede {{ max-width:880px; color:#b9c8e3; font-size:22px; line-height:1.55; margin:25px 0 33px; }}
    .receipt {{ display:inline-flex; gap:12px; align-items:center; padding:12px 16px; border:1px solid #2e4e70; border-radius:10px; background:#0a1425; color:#b8c8e4; font:500 13px ui-monospace,monospace; }}
    .receipt b {{ color:#59e3c2; }}
    .metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:42px 0; }}
    .metric,.panel {{ border:1px solid #273c5f; background:rgba(12,24,43,.88); box-shadow:0 18px 50px rgba(0,0,0,.2); }}
    .metric {{ border-radius:16px; padding:23px; }}
    .metric strong {{ display:block; font-size:34px; }} .metric span {{ color:#93a8ca; font-size:14px; }}
    .grid {{ display:grid; grid-template-columns:1.35fr .65fr; gap:20px; }}
    .panel {{ border-radius:20px; padding:28px; }}
    .panel h2 {{ margin:0 0 8px; font-size:25px; }} .sub {{ margin:0 0 22px; color:#93a8ca; line-height:1.5; }}
    .dag {{ position:relative; height:410px; border-radius:16px; overflow:hidden; background:linear-gradient(160deg,#081220,#101c33); border:1px solid #213655; }}
    .dag svg {{ position:absolute; inset:0; width:100%; height:100%; }}
    .dag svg>path {{ fill:none; stroke:#8097bc; stroke-width:2.2; marker-end:url(#parent-tip); }}
    .commit {{ position:absolute; width:148px; height:91px; padding:14px; border:2px solid #34517c; border-radius:14px; background:#142440; }}
    .commit .role {{ display:block; color:#59e3c2; font-weight:700; text-transform:uppercase; font-size:11px; letter-spacing:.12em; }}
    .commit strong {{ display:block; margin:8px 0 3px; font:600 14px ui-monospace,monospace; }} .commit small {{ color:#9dafcc; }}
    .root {{left:5%;top:39%}} .feature {{left:31%;top:11%}} .docs {{left:31%;top:67%}} .merge {{left:65%;top:11%;border-color:#bd7cff}} .replay {{left:65%;top:67%;border-color:#59e3c2}}
    .proof {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:18px; }} .proof div {{ padding:16px; background:#091526; border-radius:12px; }}
    .proof span {{ display:block;color:#93a8ca;font-size:12px;text-transform:uppercase;letter-spacing:.1em}} .proof code {{ display:block;margin-top:8px;color:#e4ecfa;font-size:14px;overflow-wrap:anywhere}}
    .checks {{ list-style:none; padding:0; margin:0; display:grid; gap:9px; }} .checks li {{ display:flex; gap:12px; align-items:center; padding:11px 13px; background:#091526; border-radius:11px; }}
    .checks li>span {{ display:grid;place-items:center;width:27px;height:27px;border-radius:50%;background:#123b35;color:#59e3c2;font-weight:900}} .checks strong,.checks small {{ display:block; }} .checks strong {{ font-size:13px; }} .checks small {{ color:#59e3c2;font-size:11px; }}
    .lower {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-top:20px; }}
    pre {{ margin:0; padding:22px; white-space:pre-wrap; overflow-wrap:anywhere; border-radius:14px; background:#040a12; color:#dce7fb; font:500 14px/1.65 ui-monospace,monospace; border:1px solid #263957; }}
    .envelope {{ display:grid; gap:12px; }} .envelope code {{ padding:13px 15px;border-radius:10px;background:#081321;color:#dce7fb;font:500 13px ui-monospace,monospace;overflow-wrap:anywhere}}
    .result {{ padding:18px;border:1px solid #2fd6af;border-radius:14px;background:#0d2a29; }} .result strong {{ display:block;font-size:19px}} .result small {{ color:#a8c9c2}}
    footer {{ display:flex;justify-content:space-between;gap:20px;margin-top:30px;padding-top:25px;border-top:1px solid #263957;color:#8fa4c5;font-size:13px}} footer code {{color:#bfcee5}}
  </style>
</head>
<body>
<main data-report-receipt="{receipt}" data-object-count="14" data-commit-count="5" data-check-count="9">
  <p class="eyebrow">Git DAG Evidence Lab · reproducible offline report</p>
  <h1>Same tree.<br>Different history.</h1>
  <p class="lede">A real isolated Git object database proves that one merge and one rebase-shaped replay resolve to identical content while preserving different parent topology.</p>
  <div class="receipt"><b>PASS</b><span>report receipt · {receipt}</span></div>
  <section class="metrics" aria-label="Verified metrics">
    <div class="metric"><strong>14</strong><span>verified Git objects</span></div>
    <div class="metric"><strong>5</strong><span>deterministic commits</span></div>
    <div class="metric"><strong>9/9</strong><span>invariants passed</span></div>
    <div class="metric"><strong>{report["execution"]["git_invocations"]}</strong><span>isolated Git calls</span></div>
  </section>
  <div class="grid">
    <section class="panel">
      <h2>Actual commit topology</h2><p class="sub">Edges point from commits to the ordered parents stored in their raw payloads.</p>
      <div class="dag" aria-label="Five commit Git DAG">
        <svg viewBox="0 0 900 410" aria-hidden="true"><defs><marker id="parent-tip" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10Z" fill="#8097bc"/></marker></defs><path d="M278 90 C240 90 230 178 205 204"/><path d="M278 320 C240 320 230 230 205 204"/><path d="M585 90 C520 90 485 90 438 90"/><path d="M585 90 C530 120 500 300 438 320"/><path d="M585 320 C530 320 500 320 438 320"/></svg>
        {node_cards}
      </div>
      <div class="proof"><div><span>shared tree</span><code>{proof["same_tree"]}</code></div><div><span>different commits</span><code>{proof["merge_commit"][:12]} ≠ {proof["rebase_shaped_commit"][:12]}</code></div></div>
    </section>
    <section class="panel"><h2>Verification gate</h2><p class="sub">All claims below come directly from the canonical report.</p><ul class="checks">{check_cards}</ul></section>
  </div>
  <div class="lower">
    <section class="panel"><h2>Real CLI receipt</h2><p class="sub">Exact stdout; exit 0; stderr empty.</p><pre>$ python3 -B -m git_dag_lab verify\n{transcript}</pre></section>
    <section class="panel"><h2>Object envelope</h2><p class="sub">The selected merge commit is independently reconstructed from raw bytes.</p><div class="envelope"><code>{visible_header}</code><code>payload · {payload["payload_size"]} bytes · SHA-256 {payload["payload_sha256"]}</code><div class="result"><strong>SHA-1 → {payload["envelope_sha1"]}</strong><small>Deterministic content address—not authentication or a signature.</small></div></div></section>
  </div>
  <footer><span>Generated offline · no JavaScript · no external assets · no network</span><code>evidence/git-dag-v1.json</code></footer>
</main>
</body>
</html>
'''
    return document_text.encode("utf-8")


def _parse_png(content: bytes) -> tuple[int, int]:
    """Validate the complete PNG chunk stream before trusting image metadata."""

    if len(content) > MAX_PNG_BYTES:
        raise EvidenceError("browser capture exceeds the PNG size limit")
    if len(content) < 57 or not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise EvidenceError("browser capture is not a complete PNG")

    offset = 8
    chunk_index = 0
    width = height = 0
    idat_payloads: list[bytes] = []
    saw_iend = False
    while offset < len(content):
        if len(content) - offset < 12:
            raise EvidenceError("PNG chunk header is truncated")
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        chunk_type = content[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(content):
            raise EvidenceError("PNG chunk payload is truncated")
        if len(chunk_type) != 4 or not all(
            65 <= byte <= 90 or 97 <= byte <= 122 for byte in chunk_type
        ):
            raise EvidenceError("PNG chunk type is malformed")
        payload = content[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", content[offset + 8 + length : chunk_end])[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise EvidenceError("PNG chunk CRC does not match")

        if chunk_index == 0:
            if chunk_type != b"IHDR" or length != 13:
                raise EvidenceError("PNG does not start with one 13-byte IHDR")
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
                raise EvidenceError("PNG IHDR differs from the pinned Chromium profile")
        elif chunk_type == b"IDAT":
            idat_payloads.append(payload)
        elif chunk_type != b"IEND":
            raise EvidenceError("PNG contains a chunk outside the pinned Chromium profile")

        offset = chunk_end
        chunk_index += 1
        if chunk_type == b"IEND":
            if length != 0:
                raise EvidenceError("PNG IEND chunk is not empty")
            saw_iend = True
            break

    if not idat_payloads or not saw_iend:
        raise EvidenceError("PNG lacks IDAT or terminal IEND")
    if offset != len(content):
        raise EvidenceError("PNG has trailing bytes after IEND")

    scanline_size = 1 + width * 3
    expected_decoded_size = height * scanline_size
    decoder = zlib.decompressobj()
    decoded = bytearray()
    try:
        for index, payload in enumerate(idat_payloads):
            if decoder.eof:
                raise EvidenceError("PNG contains IDAT data after the zlib stream ended")
            remaining = expected_decoded_size + 1 - len(decoded)
            if remaining <= 0:
                raise EvidenceError("PNG scanline stream exceeds the expected size")
            decoded.extend(decoder.decompress(payload, remaining))
            if decoder.unconsumed_tail or decoder.unused_data:
                raise EvidenceError("PNG zlib stream has excess compressed data")
            if decoder.eof and index != len(idat_payloads) - 1:
                raise EvidenceError("PNG zlib stream ended before the final IDAT")
        remaining = expected_decoded_size + 1 - len(decoded)
        if remaining <= 0:
            raise EvidenceError("PNG scanline stream exceeds the expected size")
        decoded.extend(decoder.flush(remaining))
    except zlib.error as exc:
        raise EvidenceError("PNG IDAT payload is not a valid zlib stream") from exc
    if (
        not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
        or len(decoded) != expected_decoded_size
    ):
        raise EvidenceError("PNG scanline stream is incomplete or has the wrong size")
    if any(decoded[row * scanline_size] > 4 for row in range(height)):
        raise EvidenceError("PNG contains an invalid scanline filter byte")
    return width, height


def _validate_png(content: bytes) -> None:
    width, height = _parse_png(content)
    if (width, height) != PNG_DIMENSIONS:
        raise EvidenceError(
            f"browser capture dimensions are {width}x{height}, expected 1440x1800"
        )


def _safe_capture_bytes(path: Path, label: str) -> bytes:
    absolute = ROOT / path
    if not absolute.exists():
        raise EvidenceError(f"{label} is missing; run tools/capture_report.sh")
    if absolute.is_symlink() or not absolute.is_file() or absolute.stat().st_nlink != 1:
        raise EvidenceError(f"{label} path is unsafe")
    return absolute.read_bytes()


def _capture_path_is_safe_if_present(path: Path) -> None:
    absolute = ROOT / path
    if absolute.exists() and (
        absolute.is_symlink()
        or not absolute.is_file()
        or absolute.stat().st_nlink != 1
    ):
        raise EvidenceError(f"capture path is unsafe: {path.as_posix()}")


def _load_capture_evidence(
    report_content: bytes,
    report_receipt: str,
    *,
    allow_missing: bool,
) -> CaptureEvidence | None:
    for path in (SCREENSHOT_PATH, RENDERED_DOM_PATH, ATTESTATION_PATH):
        _capture_path_is_safe_if_present(path)
    if allow_missing:
        return None

    screenshot = _safe_capture_bytes(SCREENSHOT_PATH, "browser capture")
    rendered_dom = _safe_capture_bytes(RENDERED_DOM_PATH, "rendered DOM")
    attestation = _safe_capture_bytes(ATTESTATION_PATH, "capture attestation")
    _validate_png(screenshot)
    try:
        dom_text = rendered_dom.decode("utf-8")
        attestation_document = json.loads(attestation)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("capture DOM or attestation is not canonical UTF-8 data") from exc
    if attestation != _json_bytes(attestation_document, pretty=True):
        raise EvidenceError("capture attestation is not canonical pretty JSON")
    if set(attestation_document) != {"attestation", "receipt"}:
        raise EvidenceError("capture attestation has unexpected top-level fields")

    payload = attestation_document["attestation"]
    receipt = attestation_document["receipt"]
    canonical_payload = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    expected_attestation_sha = _sha256(canonical_payload)
    if receipt != {
        "algorithm": "sha256",
        "canonicalization": "UTF-8 JSON; sorted keys; compact separators",
        "sha256": expected_attestation_sha,
    }:
        raise EvidenceError("capture attestation receipt does not match its payload")

    capture_script = (ROOT / "tools/capture_report.sh").read_bytes()
    expected_payload = {
        "browser": {
            "binary_path": BROWSER_PATH,
            "sha256": BROWSER_SHA256,
            "version": BROWSER_VERSION,
        },
        "container": {
            "architecture": "amd64",
            "image": CONTAINER_IMAGE,
        },
        "input": {
            "report": {
                "path": REPORT_PATH.as_posix(),
                "report_receipt_sha256": report_receipt,
                "sha256": _sha256(report_content),
                "size": len(report_content),
            }
        },
        "isolation": {
            "capabilities": "all-dropped",
            "demo_mount": "read-only",
            "network": "none",
            "no_new_privileges": True,
            "pull": "never",
            "root_filesystem": "read-only",
            "user": "caller-nonroot",
        },
        "outputs": {
            "rendered_dom": {
                "path": RENDERED_DOM_PATH.as_posix(),
                "sha256": _sha256(rendered_dom),
                "size": len(rendered_dom),
            },
            "screenshot": {
                "height": PNG_DIMENSIONS[1],
                "path": SCREENSHOT_PATH.as_posix(),
                "sha256": _sha256(screenshot),
                "size": len(screenshot),
                "width": PNG_DIMENSIONS[0],
            },
        },
        "schema_version": "git-dag-browser-capture-attestation/v1",
        "script": {
            "path": "tools/capture_report.sh",
            "sha256": _sha256(capture_script),
            "size": len(capture_script),
        },
        "viewport": {
            "device_scale_factor": 1,
            "height": PNG_DIMENSIONS[1],
            "width": PNG_DIMENSIONS[0],
        },
    }
    if payload != expected_payload:
        raise EvidenceError("capture attestation does not match current sources and outputs")

    required_dom = (
        '<main ',
        f'data-report-receipt="{report_receipt}"',
        'data-object-count="14"',
        'data-commit-count="5"',
        'data-check-count="9"',
        "Same tree.",
        "Different history.",
        "verified Git objects",
    )
    if not all(marker in dom_text for marker in required_dom):
        raise EvidenceError("attested rendered DOM lacks required evidence sentinels")
    forbidden = ("/home/", "ERR_FILE", "github.com/", "@gmail.com", "github_pat_", "ghp_")
    if any(marker.lower() in dom_text.lower() for marker in forbidden):
        raise EvidenceError("attested rendered DOM exposes host, remote, or credential state")
    return CaptureEvidence(
        screenshot=screenshot,
        rendered_dom=rendered_dom,
        attestation=attestation,
        document=attestation_document,
    )


def _artifact_row(path: Path, content: bytes, role: str) -> dict[str, Any]:
    return {
        "path": path.as_posix(),
        "role": role,
        "sha256": _sha256(content),
        "size": len(content),
    }


def _source_row(path: Path) -> dict[str, Any]:
    content = (ROOT / path).read_bytes()
    return {
        "path": path.as_posix(),
        "sha256": _sha256(content),
        "size": len(content),
    }


def build_artifacts(*, allow_missing_screenshot: bool) -> dict[Path, bytes]:
    verify_output, compact_output, pretty_output, document = _collect_cli()
    report_content = _report_html(document, verify_output)
    capture_evidence = _load_capture_evidence(
        report_content,
        document["receipt"]["sha256"],
        allow_missing=allow_missing_screenshot,
    )
    generated: dict[Path, bytes] = {
        EVIDENCE_PATH: compact_output,
        VERIFY_PATH: verify_output,
        INSPECT_PATH: pretty_output,
        REPORT_PATH: report_content,
        TOPOLOGY_PATH: _topology_svg(document),
        ENVELOPE_PATH: _envelope_svg(document),
        CLI_PATH: _cli_svg(document, verify_output),
        PIPELINE_PATH: _pipeline_svg(document, capture_evidence),
    }

    roles = {
        EVIDENCE_PATH: "canonical compact CLI evidence",
        VERIFY_PATH: "exact verify stdout",
        INSPECT_PATH: "exact pretty inspection stdout",
        REPORT_PATH: "dependency-free offline report",
        TOPOLOGY_PATH: "Git DAG topology derived from evidence",
        ENVELOPE_PATH: "raw object envelope proof derived from evidence",
        CLI_PATH: "visualized exact CLI transcript",
        PIPELINE_PATH: "evidence pipeline derived from execution summary",
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
    if capture_evidence is not None:
        artifact_rows.extend(
            (
                _artifact_row(
                    SCREENSHOT_PATH,
                    capture_evidence.screenshot,
                    "attested offline report browser capture",
                ),
                _artifact_row(
                    RENDERED_DOM_PATH,
                    capture_evidence.rendered_dom,
                    "actual DOM emitted during the browser capture",
                ),
                _artifact_row(
                    ATTESTATION_PATH,
                    capture_evidence.attestation,
                    "capture provenance binding browser, isolation, input, and outputs",
                ),
            )
        )
        attestation = capture_evidence.document
        capture_manifest.update(
            {
                "attestation_receipt_sha256": attestation["receipt"]["sha256"],
                "rendered_dom_sha256": _sha256(capture_evidence.rendered_dom),
                "screenshot_sha256": _sha256(capture_evidence.screenshot),
                "status": "attested",
            }
        )
    artifact_rows.sort(key=lambda row: row["path"])

    manifest = {
        "artifacts": artifact_rows,
        "capture": capture_manifest,
        "commands": [
            {
                "argv": ["python3", "-B", "-m", "git_dag_lab", "verify"],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": VERIFY_PATH.as_posix(),
            },
            {
                "argv": ["python3", "-B", "-m", "git_dag_lab", "inspect", "--compact"],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": EVIDENCE_PATH.as_posix(),
            },
            {
                "argv": ["python3", "-B", "-m", "git_dag_lab", "inspect"],
                "exit_code": 0,
                "fresh_runs": 2,
                "stderr_bytes": 0,
                "stdout": INSPECT_PATH.as_posix(),
            },
        ],
        "report_receipt_sha256": document["receipt"]["sha256"],
        "schema_version": "git-dag-evidence-manifest/v1",
        "sources": [
            _source_row(Path("git_dag_lab/lab.py")),
            _source_row(Path("git_dag_lab/cli.py")),
            _source_row(Path("tools/generate_evidence.py")),
            _source_row(Path("tools/capture_report.sh")),
        ],
    }
    generated[MANIFEST_PATH] = _json_bytes(manifest, pretty=True)
    _validate_generated(generated, capture_evidence, allow_missing_screenshot)
    return generated


def _validate_generated(
    generated: Mapping[Path, bytes],
    capture: CaptureEvidence | None,
    allow_missing_screenshot: bool,
) -> None:
    manifest = json.loads(generated[MANIFEST_PATH])
    rows = {row["path"]: row for row in manifest["artifacts"]}
    for path, content in generated.items():
        if path == MANIFEST_PATH:
            continue
        row = rows.get(path.as_posix())
        if row is None or row["sha256"] != _sha256(content) or row["size"] != len(content):
            raise EvidenceError(f"manifest does not bind {path.as_posix()}")
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
                raise EvidenceError(f"manifest does not bind {path.as_posix()}")
        if manifest["capture"].get("status") != "attested":
            raise EvidenceError("manifest does not identify the attested capture")
    elif not allow_missing_screenshot:
        raise EvidenceError("manifest has no required capture attestation")
    receipt = manifest["report_receipt_sha256"]
    for path in (TOPOLOGY_PATH, ENVELOPE_PATH, CLI_PATH, PIPELINE_PATH, REPORT_PATH):
        text = generated[path].decode("utf-8")
        if receipt not in text:
            raise EvidenceError(f"{path.as_posix()} is not bound to the report receipt")
        without_svg_namespace = text.replace("http://www.w3.org/2000/svg", "")
        if (
            "https://" in without_svg_namespace
            or "http://" in without_svg_namespace
            or "/home/" in without_svg_namespace
        ):
            raise EvidenceError(f"{path.as_posix()} contains an external or host reference")
    for path in (TOPOLOGY_PATH, ENVELOPE_PATH, CLI_PATH, PIPELINE_PATH):
        text = generated[path].decode("utf-8")
        if "<title" not in text or "<desc" not in text or 'role="img"' not in text:
            raise EvidenceError(f"{path.as_posix()} lacks accessible SVG metadata")
    html_text = generated[REPORT_PATH].decode("utf-8")
    if "<script" in html_text.lower() or "Same tree." not in html_text:
        raise EvidenceError("offline report contains executable code or lacks its primary result")


def _ensure_safe_target(path: Path) -> None:
    if path.is_absolute() or ".." in path.parts:
        raise EvidenceError("managed evidence paths must stay below the repository root")
    absolute = ROOT / path
    current = ROOT
    for part in path.parts[:-1]:
        current /= part
        if current.exists() and (current.is_symlink() or not current.is_dir()):
            raise EvidenceError(f"managed parent is unsafe: {path.as_posix()}")
        if not current.exists():
            current.mkdir(mode=0o755)
    if absolute.exists():
        if absolute.is_symlink() or not absolute.is_file():
            raise EvidenceError(f"managed target is unsafe: {path.as_posix()}")
        if absolute.stat().st_nlink != 1:
            raise EvidenceError(f"managed target has multiple hard links: {path.as_posix()}")


def _write_artifacts(generated: Mapping[Path, bytes]) -> None:
    for path in sorted(generated):
        _ensure_safe_target(path)
        target = ROOT / path
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".git-dag-evidence-", dir=target.parent, delete=False
            ) as temporary:
                temporary.write(generated[path])
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, target)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def _check_artifacts(generated: Mapping[Path, bytes]) -> None:
    mismatches: list[str] = []
    for path, expected in sorted(generated.items()):
        target = ROOT / path
        if not target.is_file() or target.is_symlink():
            mismatches.append(f"missing or unsafe: {path.as_posix()}")
        elif target.read_bytes() != expected:
            mismatches.append(f"stale: {path.as_posix()}")
    if mismatches:
        raise EvidenceError("evidence check failed: " + "; ".join(mismatches))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="write generated evidence")
    action.add_argument("--check", action="store_true", help="verify checked-in evidence")
    parser.add_argument(
        "--allow-missing-screenshot",
        action="store_true",
        help="permit the pre-capture package used by capture_report.sh",
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
        print(f"evidence error: {exc}", file=sys.stderr)
        return 1
    action = "wrote" if args.write else "verified"
    screenshot = "optional" if args.allow_missing_screenshot else "required"
    print(f"PASS evidence {action} artifacts={len(generated)} screenshot={screenshot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
