// chaincode/policy/policy_contract.go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// PolicyContract holds access rules keyed by identity+resource.
type PolicyContract struct {
	contractapi.Contract
}

// Rule is a stored allow grant. Absence of a matching rule means deny.
type Rule struct {
	Identity string `json:"identity"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Allow    bool   `json:"allow"`
	Version  string `json:"policy_version"`
}

// Decision mirrors the gateway's Decision{allow,reason,policy_version}.
type Decision struct {
	Allow         bool   `json:"allow"`
	Reason        string `json:"reason"`
	PolicyVersion string `json:"policy_version"`
}

// ruleKey composes the state key. identity+resource is the unit of policy.
func ruleKey(identity, resource string) string {
	return fmt.Sprintf("rule~%s~%s", identity, resource)
}

// PutRule writes/overwrites an allow rule for identity+resource.
func (c *PolicyContract) PutRule(ctx contractapi.TransactionContextInterface, identity, resource, action, version string) error {
	if identity == "" || resource == "" {
		return fmt.Errorf("identity and resource are required")
	}
	r := Rule{Identity: identity, Resource: resource, Action: action, Allow: true, Version: version}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(ruleKey(identity, resource), b)
}

// Evaluate answers allow/deny for identity+action(resource). No rule => deny.
// The gateway treats any error as deny (fail closed); this returns an explicit
// deny Decision for the common "no rule" case so the reason is legible.
func (c *PolicyContract) Evaluate(ctx contractapi.TransactionContextInterface, identity, action, resource string) (*Decision, error) {
	b, err := ctx.GetStub().GetState(ruleKey(identity, resource))
	if err != nil {
		return nil, fmt.Errorf("read rule: %w", err)
	}
	if b == nil {
		return &Decision{Allow: false, Reason: "no matching rule", PolicyVersion: ""}, nil
	}
	var r Rule
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if !r.Allow || (r.Action != "" && r.Action != action) {
		return &Decision{Allow: false, Reason: "rule does not permit action", PolicyVersion: r.Version}, nil
	}
	return &Decision{Allow: true, Reason: "allowed by rule", PolicyVersion: r.Version}, nil
}
