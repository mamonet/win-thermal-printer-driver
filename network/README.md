<!-- network/README.md -->
# Fabric test network for zt-policy-gateway

Commands only. No output is reproduced here; run them against your own machine.
All MSP IDs, channel names, and CA URLs are placeholders matching the compose
file and configtx. Crypto material is generated locally and never committed.

## Prerequisites
- Docker + docker-compose
- Fabric binaries + `fabric-ca-client` on PATH (peer, orderer, configtxgen)
- `FABRIC_CFG_PATH` pointing at `./network`

## 1. Generate crypto via Fabric CA
```sh
# Start the CA
docker-compose up -d ca.org1.example.com

# Enroll the CA admin (bootstrap id is REPLACE_ME_ADMIN in the CA config)
fabric-ca-client enroll -u https://REPLACE_ME_ADMIN:REPLACE_ME_ADMINPW@localhost:7054 \
  --caname ca-org1 --tls.certfiles organizations/fabric-ca/org1/ca-cert.pem

# Register + enroll peer and orderer identities (repeat per node/org)
fabric-ca-client register --caname ca-org1 --id.name peer0-org1 --id.secret REPLACE_ME \
  --id.type peer --tls.certfiles organizations/fabric-ca/org1/ca-cert.pem
```

## 2. Channel artifacts
```sh
configtxgen -profile PolicyChannel -outputBlock ./channel-artifacts/policy-channel.block \
  -channelID policy-channel
configtxgen -profile AuditChannel -outputBlock ./channel-artifacts/audit-channel.block \
  -channelID audit-channel
```

## 3. Bring up orderer + peers
```sh
docker-compose up -d orderer.example.com peer0.org1.example.com peer0.org2.example.com
```

## 4. Create + join channels
```sh
# policy-channel
osnadmin channel join --channelID policy-channel \
  --config-block ./channel-artifacts/policy-channel.block -o localhost:7053 \
  --ca-file "$ORDERER_CA" --client-cert "$ORDERER_ADMIN_TLS_SIGN_CERT" \
  --client-key "$ORDERER_ADMIN_TLS_PRIVATE_KEY"
peer channel join -b ./channel-artifacts/policy-channel.block   # as Org1, then Org2

# audit-channel (same steps, different channel id)
osnadmin channel join --channelID audit-channel \
  --config-block ./channel-artifacts/audit-channel.block -o localhost:7053 \
  --ca-file "$ORDERER_CA" --client-cert "$ORDERER_ADMIN_TLS_SIGN_CERT" \
  --client-key "$ORDERER_ADMIN_TLS_PRIVATE_KEY"
peer channel join -b ./channel-artifacts/audit-channel.block
```

## 5. Deploy both chaincodes
```sh
# policy -> policy-channel
peer lifecycle chaincode package policy.tar.gz --path ../chaincode/policy \
  --lang golang --label policy_1
peer lifecycle chaincode install policy.tar.gz
peer lifecycle chaincode approveformyorg -C policy-channel -n policy -v 1 \
  --package-id "$POLICY_PKG_ID" --sequence 1 -o localhost:7050 --tls --cafile "$ORDERER_CA"
peer lifecycle chaincode commit -C policy-channel -n policy -v 1 --sequence 1 \
  -o localhost:7050 --tls --cafile "$ORDERER_CA"

# audit -> audit-channel
peer lifecycle chaincode package audit.tar.gz --path ../chaincode/audit \
  --lang golang --label audit_1
peer lifecycle chaincode install audit.tar.gz
peer lifecycle chaincode approveformyorg -C audit-channel -n audit -v 1 \
  --package-id "$AUDIT_PKG_ID" --sequence 1 -o localhost:7050 --tls --cafile "$ORDERER_CA"
peer lifecycle chaincode commit -C audit-channel -n audit -v 1 --sequence 1 \
  -o localhost:7050 --tls --cafile "$ORDERER_CA"
```

## 6. Register a client identity for the gateway
```sh
fabric-ca-client register --caname ca-org1 --id.name gateway-client --id.secret REPLACE_ME \
  --id.type client --tls.certfiles organizations/fabric-ca/org1/ca-cert.pem
fabric-ca-client enroll -u https://gateway-client:REPLACE_ME@localhost:7054 \
  --caname ca-org1 -M organizations/peerOrganizations/org1.example.com/users/gateway-client/msp \
  --tls.certfiles organizations/fabric-ca/org1/ca-cert.pem
```

## 7. Seed + demo
```sh
../scripts/seed-policy.sh
../scripts/demo.sh
```

## Evidence
| step | tx id | block | result |
|------|-------|-------|--------|
| PutRule | _(fill: tx id)_ | _(fill: block)_ | _(fill: result)_ |
| Evaluate allow | _(fill: tx id)_ | _(fill: block)_ | _(fill: result)_ |
| Revoke | _(fill: tx id)_ | _(fill: block)_ | _(fill: result)_ |
| Evaluate deny | _(fill: tx id)_ | _(fill: block)_ | _(fill: result)_ |
