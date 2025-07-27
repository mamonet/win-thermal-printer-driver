// chaincode/audit/audit_contract.go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// AuditContract is an APPEND-ONLY decision log.
//
// Tamper-evidence: a key can be written exactly once. Record rejects any write
// to a key that already exists, and there is deliberately no Update or Delete
// method. Combined with Fabric's per-key history (GetHistoryForKey) and the
// ordering service, a mutated or missing record is detectable. Callers should
// use a collision-resistant key (e.g. the tx request_hash) so distinct
// decisions never share a key.
//
// Privacy: only request_hash is stored, never a raw request body. The hash is
// enough to bind a decision to a request without persisting its contents.
type AuditContract struct {
	contractapi.Contract
}

// Record is the immutable proof of a decision. Field names match the gateway's
// audit record: who/what/decision(allow-deny)/policy_version/ts/request_hash.
type Record struct {
	Who           string `json:"who"`
	What          string `json:"what"`
	Decision      string `json:"decision"` // "allow" | "deny"
	PolicyVersion string `json:"policy_version"`
	Ts            string `json:"ts"`
	RequestHash   string `json:"request_hash"`
}

// Record appends a decision under key. Fails if key already exists (append-only).
// Records BOTH allow and deny decisions; the gateway calls this for every
// decision, and a failure here is itself a reason to deny (fail closed).
func (c *AuditContract) Record(ctx contractapi.TransactionContextInterface, key, who, what, decision, policyVersion, ts, requestHash string) error {
	if key == "" {
		return fmt.Errorf("audit key is required")
	}
	if requestHash == "" {
		return fmt.Errorf("request_hash is required")
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("read audit key: %w", err)
	}
	if existing != nil {
		// Append-only: refuse to overwrite an existing record.
		return fmt.Errorf("audit record %s already exists; append-only", key)
	}
	r := Record{Who: who, What: what, Decision: decision, PolicyVersion: policyVersion, Ts: ts, RequestHash: requestHash}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, b)
}

// Get returns a record by key. Read-only; there is intentionally no mutation API.
func (c *AuditContract) Get(ctx contractapi.TransactionContextInterface, key string) (*Record, error) {
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("no record for key %s", key)
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Exists reports whether a key is already written. Used by tests to prove the
// append-only rule.
func (c *AuditContract) Exists(ctx contractapi.TransactionContextInterface, key string) (bool, error) {
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return false, err
	}
	return b != nil, nil
}

// No Update, no Delete. Their absence is the contract.
