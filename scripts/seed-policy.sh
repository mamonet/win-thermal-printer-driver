#!/usr/bin/env bash
# scripts/seed-policy.sh
# Seed a couple of allow rules into the policy chaincode via PutRule.
# Placeholders only; identities come from the enrolled test-network certs.
set -euo pipefail

CHANNEL="${ZT_POLICY_CHANNEL:-policy-channel}"
CC="${ZT_POLICY_CC:-policy}"
ORDERER="${ZT_ORDERER:-localhost:7050}"
ORDERER_CA="${ORDERER_CA:-/replace/me/orderer-ca.crt}"

# identity+resource -> allow (action optional; "" means any action).
put_rule() {
  local identity="$1" resource="$2" action="$3"
  echo "PutRule identity=${identity} resource=${resource} action=${action}"
  peer chaincode invoke \
    -o "$ORDERER" --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CC" \
    -c "{\"function\":\"PutRule\",\"Args\":[\"${identity}\",\"${resource}\",\"${action}\"]}" \
    --waitForEvent
}

# Example subjects match the SPKI/subject the gateway extracts from client certs.
put_rule "CN=alice,OU=client,O=Org1" "/orders" "GET"
put_rule "CN=alice,OU=client,O=Org1" "/orders" "POST"
put_rule "CN=svc-report,OU=client,O=Org2" "/reports" ""

echo "seed complete"
