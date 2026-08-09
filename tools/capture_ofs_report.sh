#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 0 ]]; then
    echo "usage: $0" >&2
    exit 2
fi

readonly image='mcr.microsoft.com/playwright@sha256:2f29369043d81d6d69a815ceb80760f55e85f5020371ad06a4d996f18503ad1c'
readonly browser='/ms-playwright/chromium_headless_shell-1193/chrome-linux/headless_shell'
readonly browser_version='Chromium 140.0.7339.186'
readonly browser_sha256='003728e0b77eb9d52e4d258594bd55ce22ecd245eb6d3b6858fbd844c901ad7d'

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
demo_root="$repo_root/docs/demo/git-pack-ofs-delta-v1"
report_path="$demo_root/report.html"
output_path="$repo_root/docs/assets/git-pack-ofs-report.png"
rendered_dom_path="$demo_root/rendered-dom.html"
attestation_path="$demo_root/capture-attestation.json"

if ! command -v docker >/dev/null 2>&1; then
    echo "capture error: Docker is required" >&2
    exit 1
fi
if [[ $(id -u) -eq 0 || $(id -g) -eq 0 ]]; then
    echo "capture error: refusing to run Chromium as root" >&2
    exit 1
fi

python3 -B "$repo_root/tools/generate_ofs_evidence.py" --write --allow-missing-screenshot >/dev/null
python3 -B "$repo_root/tools/generate_ofs_evidence.py" --check --allow-missing-screenshot >/dev/null

for managed_path in \
    "$repo_root/docs" \
    "$repo_root/docs/demo" \
    "$demo_root" \
    "$report_path" \
    "$repo_root/docs/assets"; do
    if [[ ! -e "$managed_path" || $(realpath -e -- "$managed_path") != "$managed_path" ]]; then
        echo "capture error: managed evidence path is missing or contains a symlink" >&2
        exit 1
    fi
done
if [[ ! -f "$report_path" || -L "$report_path" ]]; then
    echo "capture error: offline report is unsafe" >&2
    exit 1
fi
for destination in "$output_path" "$rendered_dom_path" "$attestation_path"; do
    if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
        echo "capture error: managed capture destination is unsafe" >&2
        exit 1
    fi
    if [[ -e "$destination" && $(stat -c '%h' -- "$destination") -ne 1 ]]; then
        echo "capture error: managed capture destination has multiple hard links" >&2
        exit 1
    fi
done

report_sha_before=$(sha256sum "$report_path" | awk '{print $1}')
script_sha_before=$(sha256sum "$repo_root/tools/capture_ofs_report.sh" | awk '{print $1}')

observed_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$image")
if [[ "$observed_digest" != "$image" ]]; then
    echo "capture error: cached container digest is not exact" >&2
    exit 1
fi
observed_architecture=$(docker image inspect --format '{{.Architecture}}' "$image")
if [[ "$observed_architecture" != "amd64" ]]; then
    echo "capture error: cached container architecture is not amd64" >&2
    exit 1
fi

uid=$(id -u)
gid=$(id -g)
readonly uid
readonly gid
common=(
    --rm
    --pull=never
    --platform linux/amd64
    --network none
    --user "$uid:$gid"
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
    --pids-limit 256
    --memory 768m
    --memory-swap 768m
    --cpus 1
    --ulimit nofile=1024:1024
    --ulimit core=0:0
    --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777'
    --tmpfs '/dev/shm:rw,nosuid,nodev,noexec,size=256m,mode=1777'
    --env HOME=/tmp
    --env XDG_CACHE_HOME=/tmp/cache
    --env XDG_CONFIG_HOME=/tmp/config
    --env LANG=C.UTF-8
    --env LC_ALL=C.UTF-8
    --env TZ=UTC
)

observed_hash=$(docker run "${common[@]}" --entrypoint /usr/bin/sha256sum \
    "$image" "$browser" | awk '{print $1}')
if [[ "$observed_hash" != "$browser_sha256" ]]; then
    echo "capture error: Chromium binary hash is not exact" >&2
    exit 1
fi
observed_version=$(docker run "${common[@]}" --entrypoint "$browser" \
    "$image" --version)
if [[ "$observed_version" != "$browser_version" ]]; then
    echo "capture error: Chromium version is not exact" >&2
    exit 1
fi

temporary_root=$(mktemp -d "$repo_root/.git-pack-ofs-report-capture.XXXXXX")
cidfile="$temporary_root/container.cid"
cleanup() {
    if [[ -f "$cidfile" && ! -L "$cidfile" ]]; then
        container_id=$(<"$cidfile")
        if [[ "$container_id" =~ ^[0-9a-f]{64}$ ]]; then
            docker rm -f "$container_id" >/dev/null 2>&1 || true
        fi
    fi
    if [[ -d "$temporary_root" ]]; then
        find "$temporary_root" -depth -delete
    fi
}
trap cleanup EXIT INT TERM
mkdir "$temporary_root/output"
dom_path="$temporary_root/rendered-dom.html"
capture_log="$temporary_root/capture.stderr"

capture=(
    docker run
    "${common[@]}"
    --cidfile "$cidfile"
    --mount "type=bind,src=$demo_root,dst=/demo,readonly"
    --mount "type=bind,src=$temporary_root/output,dst=/output"
    --workdir /demo
    --entrypoint "$browser"
    "$image"
    --headless
    --no-sandbox
    --disable-background-networking
    --disable-breakpad
    --disable-component-update
    --disable-default-apps
    --disable-extensions
    '--disable-features=OptimizationHints,Translate'
    --disable-sync
    --force-color-profile=srgb
    --force-device-scale-factor=1
    --hide-scrollbars
    '--host-resolver-rules=MAP * ~NOTFOUND'
    --lang=en-US
    --metrics-recording-only
    --no-first-run
    --no-pings
    --password-store=basic
    --run-all-compositor-stages-before-draw
    --safebrowsing-disable-auto-update
    --virtual-time-budget=1000
    '--window-size=1440,1500'
    --dump-dom
    --screenshot=/output/git-pack-ofs-report.png
    file:///demo/report.html
)

if ! timeout --signal=TERM --kill-after=5s 45s \
    "${capture[@]}" >"$dom_path" 2>"$capture_log"; then
    echo "capture error: isolated Chromium capture failed" >&2
    sed -n '1,12p' "$capture_log" >&2
    exit 1
fi

python3 - "$repo_root" "$repo_root/evidence/git-pack-ofs-delta-v1.json" "$dom_path" "$temporary_root/output" <<'PY'
from pathlib import Path
import json
import sys

repo_root = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
dom_path = Path(sys.argv[3])
output = Path(sys.argv[4])
sys.path.insert(0, str(repo_root))
from tools.generate_pack_evidence import _parse_pack_png

document = json.loads(evidence_path.read_text(encoding="utf-8"))
receipt = document["receipt"]["sha256"]
dom = dom_path.read_text(encoding="utf-8")
required = (
    '<main ',
    f'data-ofs-receipt="{receipt}"',
    'data-object-count="2"',
    'data-check-count="12"',
    'actual OFS_DELTA',
    'Base → target',
    'Two verified blobs',
)
if not all(marker in dom for marker in required):
    raise SystemExit("capture error: rendered DOM sentinels are incomplete")
if "/home/" in dom or "ERR_FILE" in dom or "github.com/" in dom:
    raise SystemExit("capture error: rendered DOM exposes host, remote, or error state")
entries = list(output.iterdir())
expected = output / "git-pack-ofs-report.png"
if entries != [expected] or not expected.is_file() or expected.is_symlink():
    raise SystemExit("capture error: browser output inventory is invalid")
content = expected.read_bytes()
if _parse_pack_png(content) != (1440, 1500):
    raise SystemExit("capture error: pack screenshot dimensions are invalid")
PY

python3 -B "$repo_root/tools/generate_ofs_evidence.py" --check --allow-missing-screenshot >/dev/null
if [[ $(sha256sum "$report_path" | awk '{print $1}') != "$report_sha_before" ]]; then
    echo "capture error: offline report changed during capture" >&2
    exit 1
fi
if [[ $(sha256sum "$repo_root/tools/capture_ofs_report.sh" | awk '{print $1}') != "$script_sha_before" ]]; then
    echo "capture error: capture script changed during execution" >&2
    exit 1
fi

chmod 0600 "$temporary_root/output/git-pack-ofs-report.png"
chmod 0600 "$dom_path"
mv -f -- "$temporary_root/output/git-pack-ofs-report.png" "$output_path"
mv -f -- "$dom_path" "$rendered_dom_path"

python3 - "$repo_root" "$report_path" "$rendered_dom_path" "$output_path" "$attestation_path" <<'PY'
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile

root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
dom_path = Path(sys.argv[3])
screenshot_path = Path(sys.argv[4])
attestation_path = Path(sys.argv[5])

def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def row(path: Path, relative: str) -> dict[str, object]:
    content = path.read_bytes()
    return {"path": relative, "sha256": sha256(content), "size": len(content)}

report = report_path.read_bytes()
dom = dom_path.read_bytes()
screenshot = screenshot_path.read_bytes()
script_path = root / "tools/capture_ofs_report.sh"
script = script_path.read_bytes()
evidence = json.loads((root / "evidence/git-pack-ofs-delta-v1.json").read_text(encoding="utf-8"))

payload = {
    "browser": {
        "binary_path": "/ms-playwright/chromium_headless_shell-1193/chrome-linux/headless_shell",
        "sha256": "003728e0b77eb9d52e4d258594bd55ce22ecd245eb6d3b6858fbd844c901ad7d",
        "version": "Chromium 140.0.7339.186",
    },
    "container": {
        "architecture": "amd64",
        "image": "mcr.microsoft.com/playwright@sha256:2f29369043d81d6d69a815ceb80760f55e85f5020371ad06a4d996f18503ad1c",
    },
    "input": {
        "report": {
            **row(report_path, "docs/demo/git-pack-ofs-delta-v1/report.html"),
            "report_receipt_sha256": evidence["receipt"]["sha256"],
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
        "rendered_dom": row(dom_path, "docs/demo/git-pack-ofs-delta-v1/rendered-dom.html"),
        "screenshot": {
            **row(screenshot_path, "docs/assets/git-pack-ofs-report.png"),
            "height": 1500,
            "width": 1440,
        },
    },
    "schema_version": "git-pack-ofs-browser-capture-attestation/v1",
    "script": row(script_path, "tools/capture_ofs_report.sh"),
    "viewport": {"device_scale_factor": 1, "height": 1500, "width": 1440},
}
canonical = json.dumps(
    payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
).encode("utf-8")
document = {
    "attestation": payload,
    "receipt": {
        "algorithm": "sha256",
        "canonicalization": "UTF-8 JSON; sorted keys; compact separators",
        "sha256": sha256(canonical),
    },
}
content = (json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
temporary_path: Path | None = None
try:
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix=".capture-attestation-", dir=attestation_path.parent, delete=False
    ) as temporary:
        temporary.write(content)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, attestation_path)
    temporary_path = None
finally:
    if temporary_path is not None:
        temporary_path.unlink(missing_ok=True)
PY

python3 -B "$repo_root/tools/generate_ofs_evidence.py" --write >/dev/null
python3 -B "$repo_root/tools/generate_ofs_evidence.py" --check >/dev/null
sha256sum "$output_path"
