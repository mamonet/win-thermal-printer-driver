// chaincode/policy/main.go
package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	cc, err := contractapi.NewChaincode(&PolicyContract{})
	if err != nil {
		log.Panicf("create policy chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("start policy chaincode: %v", err)
	}
}
