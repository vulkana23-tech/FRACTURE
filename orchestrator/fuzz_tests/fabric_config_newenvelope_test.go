// Fuzz real de NewEnvelope (paquete configtx, hyperledger/fabric-config) --
// deserializa marshaledUpdate ([]byte) como protobuf real
// (proto.Unmarshal contra cb.ConfigUpdate) para construir un envelope de
// actualizacion de canal. En una red Fabric real, una actualizacion de
// canal es propuesta por un participante y estos bytes viajan por la
// red -- input externo real, no solo interno del proceso.
package configtx

import "testing"

func FuzzNewEnvelope(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not a protobuf message"))
	f.Fuzz(func(t *testing.T, marshaledUpdate []byte) {
		NewEnvelope(marshaledUpdate)
	})
}
