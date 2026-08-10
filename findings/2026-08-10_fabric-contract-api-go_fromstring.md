# fabric-contract-api-go -- quinto target real, JSONSerializer.FromString

## Por qué este target

Quinto de los 12 candidatos reales de Hyperledger. Los 4 anteriores
(fabric-amcl, fabric-ca, fabric-config, fabric-chaincode-go) no dieron
crash todavía. Elegí `fabric-contract-api-go` porque es el framework
MÁS usado para escribir chaincode en Go (capa de más alto nivel sobre
`fabric-chaincode-go`) -- su paquete `serializer/` es literalmente
donde los argumentos de una transacción, tal cual los manda un cliente
real, se convierten al tipo Go declarado por la firma de la función
del contrato.

## Candidato real confirmado

`serializer/json_transaction_serializer.go`:

```go
func (js *JSONSerializer) FromString(param string, fieldType reflect.Type,
    paramMetadata *metadata.ParameterMetadata, components *metadata.ComponentMetadata,
) (reflect.Value, error) {
	converted, err := convertArg(fieldType, param)
	...
```

`convertArg` -> para tipos struct/slice/map/array/puntero-a-struct,
llama a `createArraySliceMapOrStruct`:

```go
func createArraySliceMapOrStruct(param string, objType reflect.Type) (reflect.Value, error) {
	obj := reflect.New(objType)
	err := json.Unmarshal([]byte(param), obj.Interface())
	...
```

**Reachability real**: esto corre en TODA invocación de chaincode
construido con `contractapi.NewChaincode` (el patrón estándar
documentado por Hyperledger para escribir chaincode en Go) -- cada
argumento string que un cliente manda en una propuesta de transacción
pasa por `FromString` antes de llegar a la lógica real del contrato.
Reflection (`reflect.New` sobre un tipo arbitrario) + `json.Unmarshal`
es un patrón clásico de panics reales en Go (type confusion,
interfaces nil, deserialización recursiva).

## Fuzz test

`orchestrator/fuzz_tests/fabric_contract_api_go_fromstring_test.go`,
`FuzzFromString`. El fuzzer nativo de Go no puede variar un
`reflect.Type` en tiempo de corrida (solo tipos primitivos como
parámetro fuzzeable) -- se fija `fieldType` a un struct compuesto a
propósito (`fuzzNestedStruct`: string, int, slice, map, puntero
recursivo a sí mismo, para cubrir de una sola vez varios caminos
reales de `convertArg`/`json.Unmarshal`) y se fuzzea solo el string de
entrada (`param`), que es exactamente el dato real controlado por el
cliente en la ruta real.

**Detalle real encontrado validando el harness**: el primer intento
de correrlo a mano colgó 60s (matado por timeout de sanity check) --
no era un bug del fuzz test, sino la descarga real de dependencias
pesadas de este módulo (gRPC + `fabric-chaincode-go` completo, que
`fabric-contract-api-go` importa) la primera vez. Confirmado corriendo
`go build ./...` aparte (bajó las deps, exit 0), y reintentando el
fuzz test -- corrió limpio (139 inputs interesantes en 15s). El cache
de módulos de Go (`$GOPATH/pkg/mod`) es global, así que quedó tibio
para la corrida real vía `run_go_fuzzer.py`.

## Corrida

Lanzada vía `orchestrator/run_go_fuzzer.py`, 30 minutos,
`-parallel=12`. Resultado se documenta acá cuando termine.
