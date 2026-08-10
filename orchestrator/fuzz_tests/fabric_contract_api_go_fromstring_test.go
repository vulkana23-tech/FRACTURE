// Fuzz real de JSONSerializer.FromString (paquete serializer,
// hyperledger/fabric-contract-api-go) -- convierte un argumento de
// transaccion (string, tal cual llega en la propuesta de transaccion
// de un cliente real) al tipo Go declarado por la firma del chaincode,
// via reflection + json.Unmarshal (ver createArraySliceMapOrStruct en
// json_transaction_serializer.go). Reachability real: esto corre en
// TODA invocacion de chaincode que use el framework contractapi (el
// mas usado para escribir chaincode en Go) -- cada argumento de string
// que un cliente manda en una transaccion pasa por aca antes de
// llegar a la logica del contrato. Reflection + json.Unmarshal es un
// patron clasico de panics reales (type confusion, interfaces nil,
// recursion via structs auto-referenciados).
//
// fieldType se fija a un struct compuesto (string, int, slice, map,
// puntero recursivo a si mismo, time.Time) para cubrir de una sola vez
// los distintos caminos de conversion reales de convertArg() -- el
// fuzzer de Go nativo no puede variar un reflect.Type en tiempo de
// corrida, solo el string de entrada.
package serializer

import (
	"reflect"
	"testing"
)

type fuzzNestedStruct struct {
	Name    string                 `json:"name"`
	Amount  int                    `json:"amount"`
	Tags    []string               `json:"tags"`
	Meta    map[string]interface{} `json:"meta"`
	Nested  *fuzzNestedStruct      `json:"nested"`
}

func FuzzFromString(f *testing.F) {
	f.Add("{}")
	f.Add(`{"name":"a","amount":1,"tags":["x","y"],"meta":{"k":"v"},"nested":{"name":"b","amount":2}}`)
	f.Add("not json")
	f.Add("")

	js := &JSONSerializer{}
	fieldType := reflect.TypeOf(fuzzNestedStruct{})

	f.Fuzz(func(t *testing.T, param string) {
		js.FromString(param, fieldType, nil, nil)
	})
}
