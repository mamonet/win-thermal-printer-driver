// chaincode/audit/main.go
package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	cc, err := contractapi.NewChaincode(&AuditContract{})
	if err != nil {
		log.Panicf("create audit chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("start audit chaincode: %v", err)
	}
}
