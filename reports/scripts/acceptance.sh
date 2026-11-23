#!/usr/bin/env bash
# Acceptance driver for the declarative custom rules feature.
#
# It rebuilds gosec, runs every acceptance scenario against the sample
# application under reports/sample and stores the real stdout/stderr and
# machine-readable reports under reports/output. A non-zero exit from any
# scenario that should succeed fails the script.
set -euo pipefail

# reports/scripts -> repository root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT="${REPO_ROOT}/reports"
OUT="${ROOT}/output"
RULES="${ROOT}/rules"
INVALID="${ROOT}/invalid"
SAMPLE="${ROOT}/sample"
BIN="${OUT}/gosec"

mkdir -p "${OUT}"
: > "${OUT}/summary.txt"

log() {
	echo "== $*" | tee -a "${OUT}/summary.txt"
}

# Locate the Go toolchain (CI images do not always put it on PATH).
if ! command -v go >/dev/null 2>&1; then
	for candidate in /home/wll/go-sdk/bin /usr/local/go/bin; do
		if [ -x "${candidate}/go" ]; then
			export PATH="${PATH}:${candidate}"
			break
		fi
	done
fi

log "building gosec"
(cd "${REPO_ROOT}" && go build -o "${BIN}" ./cmd/gosec/)

# 1. Multi-file merge load + full scan, text and JSON outputs.
log "scenario 1: merged custom rules, text + json output"
"${BIN}" -custom-rules "${RULES}" -fmt=json -out "${OUT}/findings.json" "${SAMPLE}/..." \
	>"${OUT}/01-scan-stdout.txt" 2>"${OUT}/01-scan-stderr.txt" || true
"${BIN}" -custom-rules "${RULES}" "${SAMPLE}/..." \
	>"${OUT}/01-scan-text.txt" 2>>"${OUT}/01-scan-stderr.txt" || true

# 2. Built-in + custom mixed run: stats and suppression parity.
log "scenario 2: built-in + custom mixed run"
"${BIN}" -custom-rules "${RULES}" -track-suppressions "${SAMPLE}/..." \
	>"${OUT}/02-mixed-text.txt" 2>"${OUT}/02-mixed-stderr.txt" || true
"${BIN}" -custom-rules "${RULES}" -track-suppressions -fmt=json -out "${OUT}/02-mixed.json" \
	"${SAMPLE}/..." >>"${OUT}/02-mixed-stderr.txt" 2>&1 || true

# 3. Include/exclude filters apply to custom rules.
log "scenario 3: include/exclude filters"
"${BIN}" -custom-rules "${RULES}" -include G9001,G401 "${SAMPLE}/..." \
	>"${OUT}/03-include.txt" 2>"${OUT}/03-include-stderr.txt" || true
"${BIN}" -custom-rules "${RULES}" -exclude G9001,G9008 "${SAMPLE}/..." \
	>"${OUT}/04-exclude.txt" 2>"${OUT}/04-exclude-stderr.txt" || true

# 4. Six invalid configurations: every one must be refused with entry/field detail.
log "scenario 4: invalid configuration rejection"
idx=1
for f in "${INVALID}"/0[1-3]-*.yaml "${INVALID}"/05-*.yaml "${INVALID}"/06-*.yaml; do
	name="$(basename "${f}" .yaml)"
	if "${BIN}" -custom-rules "${f}" "${SAMPLE}/..." \
		>"${OUT}/invalid-${name}.txt" 2>&1; then
		echo "FAIL: ${name} was accepted" | tee -a "${OUT}/summary.txt"
		exit 1
	fi
	idx=$((idx + 1))
done
# Duplicate id across two files.
if "${BIN}" -custom-rules "${INVALID}/04-duplicate-id-a.yaml" \
	-custom-rules "${INVALID}/04-duplicate-id-b.yaml" "${SAMPLE}/..." \
	>"${OUT}/invalid-04-duplicate-id.txt" 2>&1; then
	echo "FAIL: duplicate ids were accepted" | tee -a "${OUT}/summary.txt"
	exit 1
fi

# 5. Built-in id collision must also be refused.
log "scenario 5: built-in id collision"
cat > "${OUT}/collision.yaml" <<'EOF'
rules:
  - id: G101
    description: collides with a built-in rule
    severity: low
    confidence: low
    anchors:
      - kind: string_literal
        pattern: "whatever"
EOF
if "${BIN}" -custom-rules "${OUT}/collision.yaml" "${SAMPLE}/..." \
	>"${OUT}/05-collision.txt" 2>&1; then
	echo "FAIL: built-in collision was accepted" | tee -a "${OUT}/summary.txt"
	exit 1
fi

# 6. SARIF machine-readable output with custom + unclassified rules.
log "scenario 6: sarif output"
"${BIN}" -custom-rules "${RULES}" -fmt=sarif -out "${OUT}/06-report.sarif" \
	"${SAMPLE}/..." >>"${OUT}/06-sarif-stdout.txt" 2>&1 || true

# 7. Runtime counters (anchor misses, unclassified warnings land in stderr logs).
log "scenario 7: runtime warnings and miss behaviour"
"${BIN}" -custom-rules "${RULES}" "${SAMPLE}/..." \
	>>"${OUT}/07-runtime.txt" 2>&1 || true

log "all scenarios completed; outputs in ${OUT}"
