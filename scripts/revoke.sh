#!/usr/bin/env bash
# scripts/revoke.sh
# Revoke an identity's grant on a resource. Effective on the NEXT Evaluate:
# the gateway reads the ledger per request, so there is no grant to cache.
set -euo pipefail

CHANNEL="${ZT_POLICY_CHANNEL:-policy-channel}"
CC="${ZT_POLICY_CC:-policy}"
ORDERER="${ZT_ORDERER:-localhost:7050}"
ORDERER_CA="${ORDERER_CA:-/replace/me/orderer-ca.crt}"

IDENTITY="${1:-CN=alice,OU=client,O=Org1}"
RESOURCE="${2:-/orders}"

echo "Revoke identity=${IDENTITY} resource=${RESOURCE}"
peer chaincode invoke \
  -o "$ORDERER" --tls --cafile "$ORDERER_CA" \
  -C "$CHANNEL" -n "$CC" \
  -c "{\"function\":\"Revoke\",\"Args\":[\"${IDENTITY}\",\"${RESOURCE}\"]}" \
  --waitForEvent

echo "revoke committed; next Evaluate will deny"
