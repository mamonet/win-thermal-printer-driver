// chaincode/policy/policy_contract.go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// PolicyContract holds versioned access rules keyed by identity+resource.
//
// Versioning: each identity+resource carries a monotonically bumped version.
// PutRule and Revoke both bump it, so a Decision names the exact policy_version
// that produced it. Revocation is a state write, so it is visible to the very
// next Evaluate (no cache anywhere; the gateway re-reads the ledger per request).
type PolicyContract struct {
	contractapi.Contract
}

// Rule is a stored grant for identity+resource. Revoked flips Allow to false
// but keeps the record so the version history stays legible.
type Rule struct {
	Identity string `json:"identity"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Allow    bool   `json:"allow"`
	Version  int    `json:"version"`
	Revoked  bool   `json:"revoked"`
}

// Decision mirrors the gateway's Decision{allow,reason,policy_version}.
// policy_version is stringified "<resource>@v<N>" so the audit trail can point
// at the exact rule revision used.
type Decision struct {
	Allow         bool   `json:"allow"`
	Reason        string `json:"reason"`
	PolicyVersion string `json:"policy_version"`
}

func ruleKey(identity, resource string) string {
	return fmt.Sprintf("rule~%s~%s", identity, resource)
}

func versionTag(resource string, v int) string {
	return fmt.Sprintf("%s@v%d", resource, v)
}

// readRule returns the current rule or nil if none exists.
func (c *PolicyContract) readRule(ctx contractapi.TransactionContextInterface, identity, resource string) (*Rule, error) {
	b, err := ctx.GetStub().GetState(ruleKey(identity, resource))
	if err != nil {
		return nil, fmt.Errorf("read rule: %w", err)
	}
	if b == nil {
		return nil, nil
	}
	var r Rule
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *PolicyContract) writeRule(ctx contractapi.TransactionContextInterface, r *Rule) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(ruleKey(r.Identity, r.Resource), b)
}

// PutRule creates or updates an allow grant, bumping the version.
func (c *PolicyContract) PutRule(ctx contractapi.TransactionContextInterface, identity, resource, action string) (string, error) {
	if identity == "" || resource == "" {
		return "", fmt.Errorf("identity and resource are required")
	}
	prev, err := c.readRule(ctx, identity, resource)
	if err != nil {
		return "", err
	}
	v := 1
	if prev != nil {
		v = prev.Version + 1
	}
	r := &Rule{Identity: identity, Resource: resource, Action: action, Allow: true, Version: v, Revoked: false}
	if err := c.writeRule(ctx, r); err != nil {
		return "", err
	}
	return versionTag(resource, v), nil
}

// Revoke turns off an existing grant and bumps the version so the change is
// versioned and immediately visible. Idempotent if already revoked.
func (c *PolicyContract) Revoke(ctx contractapi.TransactionContextInterface, identity, resource string) (string, error) {
	r, err := c.readRule(ctx, identity, resource)
	if err != nil {
		return "", err
	}
	if r == nil {
		return "", fmt.Errorf("no rule to revoke for %s/%s", identity, resource)
	}
	r.Version++
	r.Allow = false
	r.Revoked = true
	if err := c.writeRule(ctx, r); err != nil {
		return "", err
	}
	return versionTag(resource, r.Version), nil
}

// Evaluate answers allow/deny and names the exact policy_version used.
// No rule, or a revoked rule, yields deny. The gateway maps any error from
// this call to a deny as well (fail closed at the edge).
func (c *PolicyContract) Evaluate(ctx contractapi.TransactionContextInterface, identity, action, resource string) (*Decision, error) {
	r, err := c.readRule(ctx, identity, resource)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return &Decision{Allow: false, Reason: "no matching rule", PolicyVersion: versionTag(resource, 0)}, nil
	}
	pv := versionTag(resource, r.Version)
	if r.Revoked || !r.Allow {
		return &Decision{Allow: false, Reason: "rule revoked", PolicyVersion: pv}, nil
	}
	if r.Action != "" && r.Action != action {
		return &Decision{Allow: false, Reason: "action not permitted", PolicyVersion: pv}, nil
	}
	return &Decision{Allow: true, Reason: "allowed by rule", PolicyVersion: pv}, nil
}
