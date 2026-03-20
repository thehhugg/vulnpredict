#!/usr/bin/env bash
# VulnPredict GitHub Action entrypoint script
# Exit codes: 0 = no findings above threshold, 1 = findings found, 2 = error
set -euo pipefail

SCAN_PATH="${1:-.}"
FORMAT="${2:-sarif}"
OUTPUT_FILE="${3:-vulnpredict-results.sarif}"
MIN_SEVERITY="${4:-low}"
FAIL_ON_FINDINGS="${5:-false}"
CONFIG_FILE="${6:-}"

echo "::group::VulnPredict Configuration"
echo "  Scan path:        ${SCAN_PATH}"
echo "  Output format:    ${FORMAT}"
echo "  Output file:      ${OUTPUT_FILE}"
echo "  Min severity:     ${MIN_SEVERITY}"
echo "  Fail on findings: ${FAIL_ON_FINDINGS}"
echo "  Config file:      ${CONFIG_FILE:-none}"
echo "::endgroup::"

# Validate inputs
if [ ! -d "${SCAN_PATH}" ] && [ ! -f "${SCAN_PATH}" ]; then
  echo "::error::Scan path does not exist: ${SCAN_PATH}"
  echo "exit_code=2" >> "${GITHUB_OUTPUT}"
  exit 2
fi

case "${FORMAT}" in
  text|json|sarif) ;;
  *)
    echo "::error::Invalid format: ${FORMAT}. Must be text, json, or sarif."
    echo "exit_code=2" >> "${GITHUB_OUTPUT}"
    exit 2
    ;;
esac

case "${MIN_SEVERITY}" in
  low|medium|high) ;;
  *)
    echo "::error::Invalid min-severity: ${MIN_SEVERITY}. Must be low, medium, or high."
    echo "exit_code=2" >> "${GITHUB_OUTPUT}"
    exit 2
    ;;
esac

# Ensure output directory exists
OUTPUT_DIR=$(dirname "${OUTPUT_FILE}")
if [ -n "${OUTPUT_DIR}" ] && [ "${OUTPUT_DIR}" != "." ]; then
  mkdir -p "${OUTPUT_DIR}"
fi

# Run VulnPredict scan
echo "::group::Running VulnPredict scan"
SCAN_EXIT_CODE=0
SCAN_CMD="vulnpredict scan ${SCAN_PATH} --format ${FORMAT} --output ${OUTPUT_FILE}"
if [ -n "${CONFIG_FILE}" ] && [ -f "${CONFIG_FILE}" ]; then
  SCAN_CMD="${SCAN_CMD} --config ${CONFIG_FILE}"
elif [ -n "${CONFIG_FILE}" ] && [ ! -f "${CONFIG_FILE}" ]; then
  echo "::warning::Config file not found: ${CONFIG_FILE}. Proceeding without it."
fi
${SCAN_CMD} || SCAN_EXIT_CODE=$?
echo "::endgroup::"

# Handle scan errors (exit code > 2 means crash)
if [ "${SCAN_EXIT_CODE}" -gt 2 ]; then
  echo "::error::VulnPredict crashed with exit code ${SCAN_EXIT_CODE}"
  echo "exit_code=2" >> "${GITHUB_OUTPUT}"
  echo "results_file=${OUTPUT_FILE}" >> "${GITHUB_OUTPUT}"
  echo "finding_count=0" >> "${GITHUB_OUTPUT}"
  echo "high_count=0" >> "${GITHUB_OUTPUT}"
  echo "medium_count=0" >> "${GITHUB_OUTPUT}"
  echo "low_count=0" >> "${GITHUB_OUTPUT}"
  exit 2
fi

echo "results_file=${OUTPUT_FILE}" >> "${GITHUB_OUTPUT}"

# Parse results to count findings by severity
if [ "${FORMAT}" = "json" ] && [ -f "${OUTPUT_FILE}" ]; then
  TOTAL=$(python3 -c "
import json, sys
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
summary = data.get('summary', {})
print(summary.get('total_findings', 0))
" 2>/dev/null || echo "0")

  HIGH=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
print(data.get('summary', {}).get('by_severity', {}).get('high', 0))
" 2>/dev/null || echo "0")

  MEDIUM=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
print(data.get('summary', {}).get('by_severity', {}).get('medium', 0))
" 2>/dev/null || echo "0")

  LOW=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
print(data.get('summary', {}).get('by_severity', {}).get('low', 0))
" 2>/dev/null || echo "0")

elif [ "${FORMAT}" = "sarif" ] && [ -f "${OUTPUT_FILE}" ]; then
  TOTAL=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
results = data.get('runs', [{}])[0].get('results', [])
print(len(results))
" 2>/dev/null || echo "0")

  HIGH=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
results = data.get('runs', [{}])[0].get('results', [])
print(sum(1 for r in results if r.get('level') == 'error'))
" 2>/dev/null || echo "0")

  MEDIUM=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
results = data.get('runs', [{}])[0].get('results', [])
print(sum(1 for r in results if r.get('level') == 'warning'))
" 2>/dev/null || echo "0")

  LOW=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
results = data.get('runs', [{}])[0].get('results', [])
print(sum(1 for r in results if r.get('level') == 'note'))
" 2>/dev/null || echo "0")

else
  TOTAL=0
  HIGH=0
  MEDIUM=0
  LOW=0
fi

echo "finding_count=${TOTAL}" >> "${GITHUB_OUTPUT}"
echo "high_count=${HIGH}" >> "${GITHUB_OUTPUT}"
echo "medium_count=${MEDIUM}" >> "${GITHUB_OUTPUT}"
echo "low_count=${LOW}" >> "${GITHUB_OUTPUT}"

# Display summary
echo ""
echo "╔══════════════════════════════════════╗"
echo "║     VulnPredict Scan Summary         ║"
echo "╠══════════════════════════════════════╣"
printf "║  High severity:   %-17s ║\n" "${HIGH}"
printf "║  Medium severity: %-17s ║\n" "${MEDIUM}"
printf "║  Low severity:    %-17s ║\n" "${LOW}"
printf "║  Total findings:  %-17s ║\n" "${TOTAL}"
echo "╚══════════════════════════════════════╝"
echo ""

# Determine if we should fail based on min-severity threshold
FINDINGS_ABOVE_THRESHOLD=0
case "${MIN_SEVERITY}" in
  low)
    FINDINGS_ABOVE_THRESHOLD=$((HIGH + MEDIUM + LOW))
    ;;
  medium)
    FINDINGS_ABOVE_THRESHOLD=$((HIGH + MEDIUM))
    ;;
  high)
    FINDINGS_ABOVE_THRESHOLD=${HIGH}
    ;;
esac

if [ "${FINDINGS_ABOVE_THRESHOLD}" -gt 0 ]; then
  echo "::warning::Found ${FINDINGS_ABOVE_THRESHOLD} findings at or above '${MIN_SEVERITY}' severity."

  if [ "${FAIL_ON_FINDINGS}" = "true" ]; then
    echo "::error::Failing because fail-on-findings is enabled and ${FINDINGS_ABOVE_THRESHOLD} findings were detected."
    echo "exit_code=1" >> "${GITHUB_OUTPUT}"
    exit 1
  fi
fi

echo "exit_code=0" >> "${GITHUB_OUTPUT}"
exit 0
