#!/usr/bin/env bash
# run.sh - reproduce the multi-platform acceptance checks.
#
# It builds gosec from this repository and runs it against two fixture
# modules under reports/fixtures/:
#
#   three-platform  - three mutually exclusive implementations (linux, darwin,
#                     windows) plus one shared file. Checks that every platform
#                     is analyzed, that findings are merged and annotated, and
#                     that the accounting identity holds.
#   broken-platform - the windows implementation does not compile. Checks that
#                     the other platforms still produce conclusions, that the
#                     failed platform is marked, and that the exit code shows
#                     the result is incomplete.
#
# Real outputs are written to reports/output/ so results can be inspected and
# compared. The script is deterministic: it never reads the machine's GOOS.
#
# Usage: reports/scripts/run.sh [path-to-go-binary]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${REPORT_DIR}/.." && pwd)"
OUT_DIR="${REPORT_DIR}/output"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

GO_BIN="${1:-go}"
if ! command -v "${GO_BIN}" >/dev/null 2>&1; then
  if [ -x "/home/wll/go-sdk/bin/go" ]; then
    GO_BIN="/home/wll/go-sdk/bin/go"
  else
    echo "error: go toolchain not found (pass its path as the first argument)" >&2
    exit 1
  fi
fi

mkdir -p "${OUT_DIR}"
BIN="${BUILD_DIR}/gosec"
echo "== building gosec"
(cd "${REPO_ROOT}" && GO111MODULE=on "${GO_BIN}" build -o "${BIN}" ./cmd/gosec/)

PLATFORMS="linux/amd64,darwin/arm64,windows/amd64"

echo
echo "== acceptance 1: three mutually exclusive implementations"
set +e
"${BIN}" -quiet -fmt=json -out="${OUT_DIR}/three-platform.json" \
  -platforms="${PLATFORMS}" \
  "${REPORT_DIR}/fixtures/three-platform/app"
THREE_EXIT=$?
set -e
echo "exit code: ${THREE_EXIT} (expected 1: findings were reported)"

echo
echo "== acceptance 2: one platform fails to compile"
set +e
"${BIN}" -quiet -fmt=json -out="${OUT_DIR}/broken-platform.json" \
  -platforms="${PLATFORMS}" \
  "${REPORT_DIR}/fixtures/broken-platform/app"
BROKEN_EXIT=$?
set -e
echo "exit code: ${BROKEN_EXIT} (expected 2: incomplete platform coverage)"

echo
echo "== acceptance 3: single-platform project is unchanged"
set +e
"${BIN}" -quiet -fmt=json -out="${OUT_DIR}/single-platform.json" \
  -platforms="$( "${GO_BIN}" env GOOS)/$( "${GO_BIN}" env GOARCH)" \
  "${REPORT_DIR}/fixtures/three-platform/app"
SINGLE_EXIT=$?
set -e
echo "exit code: ${SINGLE_EXIT}"

echo
echo "== reconciling outputs"
python3 - "${OUT_DIR}" "${THREE_EXIT}" "${BROKEN_EXIT}" <<'PY'
import json
import os
import sys

out_dir, three_exit, broken_exit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
failures = []

def load(name):
    with open(os.path.join(out_dir, name), encoding="utf-8") as fh:
        return json.load(fh)

def check(cond, message):
    if not cond:
        failures.append(message)
    print(("OK   " if cond else "FAIL ") + message)

three = load("three-platform.json")
platforms = three["platforms"]
check(sorted(platforms["platforms"]) ==
      ["darwin/arm64", "linux/amd64", "windows/amd64"],
      "three platforms were analyzed")
check(platforms["coverage"]["complete"], "three-platform coverage is complete")

files = {os.path.basename(i["file"]) for i in three["Issues"]}
for name in ("common.go", "linux_only.go", "darwin_only.go", "windows_only.go"):
    check(name in files, "finding for %s is present" % name)

shared = [i for i in three["Issues"] if i["file"].endswith("common.go")]
check(len(shared) == 1 and sorted(shared[0]["platforms"]) ==
      ["darwin/arm64", "linux/amd64", "windows/amd64"],
      "the shared finding is merged and lists every platform")

linux_only = [i for i in three["Issues"] if i["file"].endswith("linux_only.go")]
check(len(linux_only) == 1 and linux_only[0]["platforms"] == ["linux/amd64"],
      "the linux-only finding lists only linux")

recon = platforms["reconciliation"]
check(recon["per_platform_total"] == recon["merged"] + recon["duplicates"],
      "per-platform total (%d) = merged (%d) + duplicates (%d)" %
      (recon["per_platform_total"], recon["merged"], recon["duplicates"]))
check(recon["balanced"], "reconciliation is balanced")
check(three_exit == 1, "three-platform run exits 1 on findings")

per_platform = sum(s["issues"] for s in platforms["stats"])
check(per_platform == recon["per_platform_total"],
      "sum of per-platform hits (%d) equals the recorded total" % per_platform)

broken = load("broken-platform.json")
broken_platforms = broken["platforms"]
check(not broken_platforms["coverage"]["complete"],
      "broken-platform coverage is incomplete")
check(broken_platforms["coverage"]["missing"] == ["windows/amd64"],
      "only windows/amd64 is reported missing")
failed = [f["platform"] for f in broken_platforms.get("failed", [])]
check(failed == ["windows/amd64"], "only windows/amd64 is reported failed")

healthy = {os.path.basename(i["file"]) for i in broken["Issues"]}
check("linux_only.go" in healthy and "darwin_only.go" in healthy,
      "healthy platforms still produce their conclusions")
check(broken_exit == 2, "broken platform run exits 2 for incomplete coverage")

single = load("single-platform.json")
check("platforms" not in single,
      "single-platform scan carries no platform block")
for item in single["Issues"]:
    if "platforms" in item:
        failures.append("single-platform issue %s is annotated" % item["file"])
        break
else:
    print("OK   single-platform issues carry no platform annotation")

print()
if failures:
    print("%d check(s) failed:" % len(failures))
    for failure in failures:
        print("  - " + failure)
    sys.exit(1)
print("all acceptance checks passed")
PY

echo
echo "reports written to ${OUT_DIR}"

# ---------------------------------------------------------------------------
# Default-run inference: when no platform is configured, the project's build
# constraints are used, so the same command finds cross-platform code.
# ---------------------------------------------------------------------------
echo
echo "== acceptance 4: inference without an explicit platform list"
set +e
"${BIN}" -quiet -fmt=json -out="${OUT_DIR}/inferred.json" \
  "${REPORT_DIR}/fixtures/three-platform/app"
INFER_EXIT=$?
set -e
echo "exit code: ${INFER_EXIT}"

python3 - "${OUT_DIR}" "${INFER_EXIT}" <<'PY'
import json
import os
import sys

out_dir, infer_exit = sys.argv[1], int(sys.argv[2])
failures = []
def check(cond, message):
    if not cond:
        failures.append(message)
    print(("OK   " if cond else "FAIL ") + message)

data = json.load(open(os.path.join(out_dir, "inferred.json"), encoding="utf-8"))
report = data["platforms"]
check(report["source"] == "inferred", "platform set was inferred (source=%s)" % report["source"])
check(report["coverage"]["complete"], "inferred coverage is complete")
names = {os.path.basename(i["file"]) for i in data["Issues"]}
check("windows_only.go" in names and "darwin_only.go" in names,
      "inference reaches the other platforms' files")
check(infer_exit == 1, "inferred run exits 1 on findings")

print()
if failures:
    for failure in failures:
        print("  - " + failure)
    sys.exit(1)
print("inference checks passed")
PY
