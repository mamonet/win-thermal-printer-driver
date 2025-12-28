# zt-policy-gateway

A zero-trust enforcement gateway in Rust that verifies who is calling, asks a permissioned ledger
whether the call is allowed, and records the decision immutably before the action is ever forwarded.

The idea is the one that matters for a runtime trust layer: nothing is trusted by default. Every
request has to prove its identity with a certificate, the policy that governs it lives on a
Hyperledger Fabric ledger rather than in the gateway's own config, and the fact that a decision was
made is written to that same ledger so it cannot be quietly edited later. The gateway itself holds no
authority of its own; it enforces what the ledger says.

## Shape

```
   client (mTLS cert)
        |
        v
  +--------------+   identity ok?   +---------------------------+
  |  Rust        |----------------->|  policy check (chaincode) |
  |  gateway     |<-----------------|  allow / deny + reason    |
  |  (tokio,     |                  +---------------------------+
  |   rustls)    |         |
  +--------------+         v  append decision
        |            +---------------------------+
     allow?          |  Hyperledger Fabric       |
        |            |  channel: policy + audit  |
        v            +---------------------------+
   upstream service
```

## What it does

- **Identity first (mTLS).** The gateway terminates mutual TLS with `rustls`/`tokio-rustls` and pulls
  the client identity from the presented certificate (subject, SPKI fingerprint, issuing CA). No
  certificate, no conversation.
- **Policy from the ledger, not the gateway.** For each request it invokes a Fabric chaincode query
  with the caller identity, the target action, and context, and gets back an allow or deny with a
  reason. Rules, roles, approvals, and revocations live on-chain and can change without redeploying
  the gateway.
- **Enforce before forward.** Only an `allow` reaches the upstream service; a `deny` is refused at
  the edge, before the action executes.
- **Immutable audit.** Every decision (who, what, allow/deny, policy version, timestamp) is written to
  an audit channel as a Fabric transaction, so the log is append-only and tamper-evident. Raw request
  bodies are never written; only a hash and the metadata needed to prove the decision.
- **Revocation that bites.** A revoked identity or a withdrawn permission on the ledger takes effect on
  the next request, because the gateway checks the ledger rather than a cached grant.

## The Fabric side

- **Chaincode (Go):** `policy` contract with `PutRule`, `Evaluate`, `Revoke`; `audit` contract with an
  append-only `Record`. State keyed by identity and resource, versioned so a decision can name the
  exact rule set it used.
- **Channels:** a `policy` channel and an `audit` channel, so read/write patterns and access can be
  separated.
- **Fabric CA:** issues the org and client identities; the same trust root the gateway validates
  client certificates against, so identity is consistent from the edge to the ledger.

## Stack

Rust (`tokio`, `tower`, `rustls`, `hyper`) for the gateway; Hyperledger Fabric with Go chaincode; a
local Fabric test network via `docker compose`; deployable to Kubernetes.

## Run

```bash
# bring up a local Fabric test network + the gateway
docker compose up

# seed a couple of policy rules on the ledger
scripts/seed-policy.sh

# call through the gateway with a valid client cert (allowed)
curl --cert client.pem --key client.key https://localhost:8443/action/read

# call with a revoked identity (denied at the edge, and recorded)
scripts/revoke.sh client-a && curl --cert client.pem --key client.key https://localhost:8443/action/read
```

## Tests

Identity extraction from the client certificate; allow and deny paths end to end; a revoked identity
denied on the very next request; audit entries written for both allow and deny; tamper check showing
the audit record cannot be altered after the fact; and behaviour when the ledger is unreachable
(fail closed, never fail open).

## Evidence (to be filled with real captured output)

> Captured by running the network and the gateway. Real output, not edited.
> Nothing in this table is filled in yet.

| Item | Result |
|------|--------|
| Allowed request end to end | _(fill: gateway log + upstream hit)_ |
| Denied request (no cert / wrong identity) | _(fill: refused at edge)_ |
| Revocation effective next request | _(fill: allow then deny after revoke)_ |
| Audit entry on the ledger | _(fill: Fabric tx id, block number)_ |
| Fail-closed when ledger down | _(fill: deny, not allow)_ |

## Repository layout

```
zt-policy-gateway/
  gateway/                 Rust: mTLS termination, policy client, enforcement
    src/identity.rs        certificate identity extraction
    src/policy.rs          Fabric chaincode client (evaluate)
    src/audit.rs           append decision to the audit channel
    src/main.rs            tower/hyper service
  chaincode/
    policy/                Go chaincode: rules, evaluate, revoke
    audit/                 Go chaincode: append-only record
  network/                 Fabric test network, channels, Fabric CA config
  deploy/                  Dockerfiles, Kubernetes manifests
  scripts/                 seed-policy, revoke, demo drivers
  tests/
  docker-compose.yml
```

## Notes

- The gateway has no policy of its own on purpose: authority lives on the ledger, the gateway only
  enforces it. That is what makes the audit trail meaningful.
- Fail closed, always: if the policy ledger cannot be reached, the request is denied, never allowed.
- Synthetic identities and rules only; no real customer data and no secrets in the repo.

MIT licensed.
