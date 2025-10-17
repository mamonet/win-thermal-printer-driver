#!/usr/bin/env bash
# scripts/demo.sh
# End-to-end: allow -> revoke -> next request denied. Drives curl through the
# gateway (mTLS). Client cert/key are test-network material, never committed.
set -euo pipefail

GATEWAY="${ZT_GATEWAY_URL:-https://localhost:8443}"
CLIENT_CERT="${ZT_CLIENT_CERT:-/replace/me/alice.crt}"
CLIENT_KEY="${ZT_CLIENT_KEY:-/replace/me/alice.key}"
CA="${ZT_CA:-/replace/me/ca.crt}"
RESOURCE="${ZT_RESOURCE:-/orders}"

call() {
  # --cacert pins the gateway's trust root; --cert/--key present the client id.
  # -w prints the HTTP status so allow(200) vs deny(403) is visible.
  curl -sS -o /dev/null -w "%{http_code}\n" \
    --cacert "$CA" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    "${GATEWAY}${RESOURCE}"
}

echo "1) seed allow rules"
./seed-policy.sh

echo "2) request while allowed (expect 200)"
call

echo "3) revoke alice on ${RESOURCE}"
./revoke.sh "CN=alice,OU=client,O=Org1" "$RESOURCE"

echo "4) next request after revoke (expect 403, no cached grant)"
call

echo "demo complete"
