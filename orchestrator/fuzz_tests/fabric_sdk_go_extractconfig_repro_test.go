package chconfig

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go/common"
)

// PoC real: extractConfig() (chconfig.go:367) chequea block.Header == nil
// pero indexa block.Data.Data[0] sin chequear que block.Data no sea nil
// ni que el slice tenga al menos un elemento. Un Block protobuf con solo
// Header seteado (proto3 -- Data es opcional, perfectamente valido no
// mandarlo) es indistinguible de un mensaje legitimo a nivel de
// proto.Unmarshal, y llega tal cual desde una respuesta real de un peer
// u orderer (queryBlockFromPeers / queryBlockFromOrderer, ambas pasan el
// *common.Block directo a extractConfig sin validar Data en el medio).
func TestFractureReproNilBlockData(t *testing.T) {
	block := &common.Block{
		Header: &common.BlockHeader{Number: 1},
		// Data intencionalmente nil -- exactamente lo que un peer/orderer
		// malicioso o con un bug propio podria devolver.
	}
	_, _ = extractConfig("mychannel", block)
	t.Log("no panic con Data==nil (inesperado si esto es explotable)")
}

func TestFractureReproEmptyBlockData(t *testing.T) {
	block := &common.Block{
		Header: &common.BlockHeader{Number: 1},
		Data:   &common.BlockData{Data: [][]byte{}}, // Data no nil, pero vacio
	}
	_, _ = extractConfig("mychannel", block)
	t.Log("no panic con Data.Data vacio (inesperado si esto es explotable)")
}
