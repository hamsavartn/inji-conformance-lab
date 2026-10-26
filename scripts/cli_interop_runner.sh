#!/usr/bin/env bash
# Headless Interoperability Matrix Runner for CI/CD Pipeline Integration (Fail-Closed)
# MOSIP Decode 2026 - Problem Statement 02
set -euo pipefail

BFF_URL="${BFF_URL:-http://localhost:4000/api/v1}"
REPORT_FILE="${REPORT_FILE:-INTEROP_MATRIX.md}"

echo "==========================================================="
echo " MOSIP Inji Conformance Lab - CI Interop Matrix Runner"
echo "==========================================================="

# Health Check with fail-closed assertion
echo "[INFO] Probing Conformance Gateway health at ${BFF_URL}/health..."
HEALTH_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BFF_URL}/health" || echo "000")
if [ "$HEALTH_HTTP_CODE" != "200" ]; then
  echo "❌ [FATAL] BFF Gateway unavailable at ${BFF_URL}/health (HTTP ${HEALTH_HTTP_CODE})." >&2
  exit 1
fi

echo "✅ [INFO] BFF Gateway is UP. Initiating 8-Lane Concurrent Conformance Matrix..."

# Trigger full 8-lane matrix evaluation
MATRIX_RAW_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${BFF_URL}/orchestrate/full-matrix" \
  -H "Content-Type: application/json")

HTTP_CODE=$(echo "$MATRIX_RAW_RESPONSE" | tail -n1)
BODY=$(echo "$MATRIX_RAW_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
  echo "❌ [FATAL] Matrix runner endpoint returned HTTP ${HTTP_CODE}: ${BODY}" >&2
  exit 1
fi

# Assert matrix results using node
NODE_EVAL=$(node -e '
  try {
    const data = JSON.parse(process.argv[1]);
    const summary = data.summary;
    const results = data.results || [];
    if (!summary || summary.compliancePercentage === undefined) {
      console.error("Malformed matrix response");
      process.exit(1);
    }
    let md = "# Inji Interoperability Matrix Report\n\n";
    md += `**Compliance Score:** ${summary.compliancePercentage}% (${summary.passed}/${summary.totalTests} Lanes Passed)\n`;
    md += `**Execution Latency:** ${summary.suiteDurationMs}ms\n\n`;
    md += "| Lane | Issuer | Wallet | Verifier | Format | Draft | Outcome | Latency |\n";
    md += "|:---:|:---|:---|:---|:---|:---|:---:|:---:|\n";
    for (const r of results) {
      const icon = r.outcome === "PASS" ? "✅ PASS" : "❌ FAIL";
      md += `| ${r.lane} | ${r.issuer} | ${r.wallet} | ${r.verifier} | ${r.format} | ${r.draft} | ${icon} | ${r.latencyMs}ms |\n`;
    }
    require("fs").writeFileSync(process.argv[2], md, "utf8");
    if (summary.compliancePercentage < 100) {
      process.exit(2);
    }
    process.exit(0);
  } catch (err) {
    console.error("Evaluation failure:", err.message);
    process.exit(1);
  }
' "$BODY" "$REPORT_FILE" || echo "FAILED")

if [ "$NODE_EVAL" = "FAILED" ]; then
  echo "❌ [FAILURE] Matrix conformance evaluation failed or compliance score < 100%." >&2
  cat "$REPORT_FILE" 2>/dev/null || true
  exit 1
fi

echo "==========================================================="
echo "✅ [SUCCESS] Matrix conformance 100% verified. Report written to $REPORT_FILE."
echo "==========================================================="
cat "$REPORT_FILE"
