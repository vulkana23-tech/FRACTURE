# fabric-gateway -- octavo target real, parseTransactionEnvelope

## Por qué este target

`fabric-gateway` es el SDK cliente moderno de Fabric (recomendado
desde 2.4+, todos los SDKs de alto nivel lo usan por debajo hoy),
todavía sin tocar de la lista real de candidatos Hyperledger. Se
priorizó por la misma señal que ya rindió en `fabric-sdk-go`
(`extractConfig`, ver `2026-08-10_fabric-sdk-go_chconfig_extractconfig_CONFIRMED.md`):
código de parseo manual de protobuf anidado, escrito a mano alrededor
de la deserialización estructural.

## Candidato real

`pkg/client/transactionparser.go`: cadena de SEIS `proto.Unmarshal`
anidados sobre `preparedTransaction.GetEnvelope()` -- el
`PreparedTransaction` que el Gateway/peer arma y devuelve como
respuesta a `Endorse()`. Ver `FuzzParseTransactionEnvelope` en
`orchestrator/fuzz_tests/fabric_gateway_parsetransactionenvelope_test.go`
para el detalle completo de la cadena y el análisis de reachability.

## Complicación real de build (no un bug, del entorno)

El paquete `pkg/client` tiene mocks generados (`mockery`) que no
vienen commiteados al repo -- `go vet`/`go test` fallan con
`undefined: MockClientConnInterface` si se intenta compilar junto con
los tests existentes del paquete. Resuelto sacando temporalmente
todos los `*_test.go` existentes del clon (nunca tocando el repo
real), dejando solo el fuzz test nuevo -- el paquete en sí (no-test)
compila limpio sin los mocks, solo los TESTS existentes los
necesitaban.

## Corridas

1. Smoke test, 60s, `-parallel=18`: limpio, 1,690,561 ejecuciones,
   157 entradas "interesting" encontradas (cobertura real creciendo,
   no solo ejecutando sin explorar).
2. Campaña completa, 40 min (2400s), `-parallel=18` (18 cores reales
   del VPS): **limpio -- `PASS`, 171,494,451 ejecuciones reales,
   `ok  	github.com/hyperledger/fabric-gateway/pkg/client	2401.325s`**.
   Sin ningún crash guardado en `testdata/fuzz/FuzzParseTransactionEnvelope/`.

## Conclusión

La cadena de 6 unmarshals anidados sobrevivió una campaña real y
larga sin producir ningún panic. A diferencia de `NewStateEP`
(fabric-chaincode-go) y `NewEnvelope` (fabric-config), que también
sobrevivieron pero con corridas más cortas (30-40 min igual), acá el
volumen de ejecuciones fue notablemente mayor (171M vs. las decenas
de millones típicas de las corridas anteriores) gracias a que la
función es más liviana por ejecución -- da más confianza real en el
resultado limpio, aunque sigue sin ser una garantía de ausencia de
bugs.

## Estado acumulado de targets Go probados

Van 6 targets fuzzeados sin encontrar un panic vía fuzzing puro
(`fabric-amcl`/Dilithium -- código muerto, no cuenta;
`fabric-ca`/decodeToken; `fabric-config`/NewEnvelope;
`fabric-chaincode-go`/NewStateEP; `fabric-contract-api-go`/FromString;
`fabric-gateway`/parseTransactionEnvelope), más 2 hallazgos reales
confirmados SIN fuzzing (lectura de código + repro directo):
`fabric-private-chaincode`/parson (crash + fuga de confidencialidad
en SGX real) y `fabric-sdk-go`/extractConfig (nil deref/index out of
range). El patrón que rindió las dos veces reales fue el mismo:
leer con cuidado el código alrededor de un `proto.Unmarshal`/parseo
externo buscando un chequeo de límite faltante, no el fuzzing puro
en sí -- vale la pena seguir priorizando ese tipo de revisión manual
antes de invertir 30-40 min de campaña por candidato.
