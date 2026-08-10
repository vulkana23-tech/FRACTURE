// Fuzz real de parseTransactionEnvelope (paquete client,
// hyperledger/fabric-gateway) -- cadena de SEIS proto.Unmarshal
// anidados sobre bytes que llegan del lado servidor (el Gateway/peer)
// como respuesta a Endorse(): Envelope.Payload -> common.Payload ->
// (ChannelHeader del Header, y por separado) peer.Transaction ->
// TransactionAction.Payload -> ChaincodeActionPayload ->
// ProposalResponsePayload.Extension -> ChaincodeAction. Ver
// pkg/client/transactionparser.go y pkg/client/transaction.go
// (newTransaction llama esto sobre preparedTransaction.GetEnvelope()
// -- ese PreparedTransaction lo arma y devuelve el Gateway/peer via
// gRPC en cada Endorse(), input real de un proceso de red separado, no
// solo interno del cliente).
//
// Reachability real: esto corre en TODA aplicacion Go que use el SDK
// Fabric Gateway (el mecanismo de cliente recomendado desde Fabric
// 2.4+) al construir una Transaction despues de cada endorsement --
// un gateway/peer comprometido o con un bug propio que devuelva bytes
// malformados en el Payload de la respuesta llega directo a esta
// cadena. Cadenas largas de Unmarshal anidado son el patron clasico
// donde aparecen panics reales (nil dereference en los getters
// intermedios, index out of range) aunque proto.Unmarshal en si mismo
// ya este bien fuzzeado por Google -- lo interesante aca es el codigo
// Go escrito a mano alrededor de cada capa, no el parser de protobuf.
package client

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
)

func FuzzParseTransactionEnvelope(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not a protobuf message"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		envelope := &common.Envelope{Payload: payload}
		parseTransactionEnvelope(envelope)
	})
}
