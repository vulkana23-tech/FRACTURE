// Fuzz real de NewStateEP (paquete statebased, hyperledger/fabric-chaincode-go) --
// deserializa policy ([]byte) como protobuf real (proto.Unmarshal contra
// common.SignaturePolicyEnvelope), y despues hace un segundo Unmarshal
// anidado por cada Identity.Principal contra msp.MSPRole
// (setMSPIDsFromSP). Reachability real: esta es la funcion publica que
// un chaincode usa para construir una politica de endorsement por clave
// (state-based endorsement) a partir de bytes serializados -- en
// aplicaciones que arman esa politica dinamicamente, esos bytes pueden
// venir de datos de la transaccion. Doble Unmarshal anidado es
// exactamente el patron donde suelen esconderse panics de
// type-confusion en codigo basado en protobuf.
package statebased

import "testing"

func FuzzNewStateEP(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not a protobuf message"))
	f.Fuzz(func(t *testing.T, policy []byte) {
		NewStateEP(policy)
	})
}
