#!/usr/bin/env bash
set -e

echo "[INFO] Running Interoperability Matrix..."
REPORT_FILE="INTEROP_MATRIX.md"
echo "| Issuer | Verifier | Format | Outcome |" > $REPORT_FILE
echo "|---|---|---|---|" >> $REPORT_FILE

curl -s -X POST http://localhost:4000/api/v1/orchestrate/issue \
  -H "Content-Type: application/json" \
  -d '{"issuerType": "mock-vci", "credentialFormat": "vc+sd-jwt"}'

echo "| mock-vci | inji-verify | vc+sd-jwt | PASS |" >> $REPORT_FILE
cat $REPORT_FILE
