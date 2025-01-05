# zt-policy-gateway

A zero-trust enforcement gateway in Rust. Early scaffold.

Verifies who is calling with a client certificate, asks a permissioned Hyperledger Fabric ledger
whether the call is allowed, and records the decision immutably before the action is ever forwarded.

Nothing is trusted by default. The policy that governs a request lives on the ledger rather than in
the gateway's own config, and the gateway holds no authority of its own; it enforces what the ledger
says.

```bash
docker compose up
scripts/seed-policy.sh
curl --cert client.pem --key client.key https://localhost:8443/action/read
```

Rust (tokio, tower, rustls, hyper), Hyperledger Fabric with Go chaincode. Fail closed, always.
