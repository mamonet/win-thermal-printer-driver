// chaincode/audit/audit_contract.go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// AuditContract stores one decision record per key. Append semantics.
type AuditContract struct {
	contractapi.Contract
}

// Record is the immutable proof of a decision. Field names match the gateway's
// audit record: who/what/decision(allow-deny)/policy_version/ts/request_hash.
// Only request_hash is stored, never the raw request body.
type Record struct {
	Who           string `json:"who"`
	What          string `json:"what"`
	Decision      string `json:"decision"` // "allow" | "deny"
	PolicyVersion string `json:"policy_version"`
	Ts            string `json:"ts"`
	RequestHash   string `json:"request_hash"`
}

// Record appends a decision under the given key.
func (c *AuditContract) Record(ctx contractapi.TransactionContextInterface, key, who, what, decision, policyVersion, ts, requestHash string) error {
	r := Record{Who: who, What: what, Decision: decision, PolicyVersion: policyVersion, Ts: ts, RequestHash: requestHash}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, b)
}

// Get returns a record by key.
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
