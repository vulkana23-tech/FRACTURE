# fabric-chaincode-go -- cuarto target real, NewStateEP

## Por qué este target

Después de dos campañas reales sobre `zbx_json_open` (zabbix, ver
`2026-08-10_zabbix_candidate.md`) sin encontrar nada, tocaba mover el
esfuerzo a superficie nueva en vez de seguir extendiendo la misma
campaña. Evalué extender zabbix hacia la capa de red real
(`src/libs/zbxcomms/comms.c`, el parseo real del header `ZBXD` +
longitud antes de descomprimir) pero es una máquina de estados
dirigida por I/O de socket real (`tcp_read`/`tcp_peek` estáticas
dentro del mismo archivo) -- aislarla en un harness puro hubiera sido
un trabajo mucho más grande que lo que rindió zbxjson. En vez de
forzarlo, volví a los 9 repos Go de Hyperledger todavía sin tocar de
la lista real de `targets/select_targets.py` (12 candidatos totales,
3 ya cubiertos: fabric-amcl, fabric-ca, fabric-config).

## Candidato real confirmado

`fabric-chaincode-go/pkg/statebased/statebasedimpl.go`:

```go
func NewStateEP(policy []byte) (KeyEndorsementPolicy, error) {
	s := &stateEP{orgs: make(map[string]msp.MSPRole_MSPRoleType)}
	if policy != nil {
		spe := &common.SignaturePolicyEnvelope{}
		if err := proto.Unmarshal(policy, spe); err != nil {
			return nil, fmt.Errorf("Error unmarshaling to SignaturePolicy: %s", err)
		}
		err := s.setMSPIDsFromSP(spe)
		...
```

`setMSPIDsFromSP` hace un SEGUNDO `proto.Unmarshal` anidado, por cada
`Identity` del envelope, contra `identity.Principal` como `msp.MSPRole`.
Doble-unmarshal anidado de protobuf es exactamente el patrón donde
suelen esconderse panics de type-confusion en código Go basado en
protobuf -- clase de bug similar a la que ya probamos (sin éxito) en
`NewEnvelope` (fabric-config).

**Reachability real**: `NewStateEP` es la función pública que un
chaincode usa para construir una política de endorsement por clave
(state-based endorsement, ver también `ChaincodeStub.GetStateValidationParameter`/
`SetStateValidationParameter` en `shim/stub.go`, que persisten/leen
exactamente este mismo formato serializado en el ledger). En
aplicaciones que arman esta política dinámicamente a partir de datos
de la transacción, `policy` es input externo real.

**Función chica, sin recursión profunda** (a diferencia de
`NewEnvelope`) -- solo un loop plano sobre `sp.Identities` con un
segundo unmarshal por iteración. Menor superficie que `NewEnvelope`,
pero limpia y rápida de fuzzear.

## Fuzz test

`orchestrator/fuzz_tests/fabric_chaincode_go_newstateep_test.go`,
`FuzzNewStateEP`, mismo patrón que los 3 anteriores (Go nativo,
`go test -fuzz`, sin seeds protobuf-válidas a mano -- la mutación
guiada por cobertura encuentra estructura sola, mismo criterio ya
usado en `NewEnvelope`).

## Corrida

Lanzada vía `orchestrator/run_go_fuzzer.py`, 30 minutos,
`-parallel=12` (de 18 cores reales del VPS).

**Primer intento invalidado**: terminó con `returncode=1` sin ningún
crash guardado en `testdata/fuzz/FuzzNewStateEP/`, pero el `stderr`
mostraba `go: downloading github.com/stretchr/testify v1.11.1` --
sospechoso porque esa dependencia la usa el archivo de test YA
existente del paquete (`statebasedimpl_test.go`), no el fuzz test
nuevo. Investigado antes de confiar en el resultado (mismo criterio de
esta sesión: nunca reportar sin verificar): reproduje el mismo comando
a mano dos veces (10s serial, 90s a `-parallel=12` igual que la
corrida real) y ambas salieron limpias (`returncode=0`). Conclusión:
fue un flake del entorno -- probablemente resolución de dependencias
de Go interrumpida por contención real de CPU/red con la campaña de
90 min sobre zabbix que recién estaba terminando en ese momento, no un
problema del fuzz test ni del código real. Descartado el resultado,
re-lanzado limpio.

**Resultado real (corrida limpia, 30 min, `-parallel=12`)**:
`returncode=0`, sin crashes. `NewStateEP` sobrevivió esta campaña sin
que se encontrara un panic real de type-confusion en el doble
unmarshal anidado.

## Estado de los 4 targets Go probados hasta ahora

Ninguno de los 4 (`fabric-amcl`/Dilithium, `fabric-ca`/decodeToken,
`fabric-config`/NewEnvelope, `fabric-chaincode-go`/NewStateEP) generó
un crash real todavía, entre campañas de 30-90 min cada una. Quedan 8
de los 12 candidatos originales de Hyperledger sin tocar.
