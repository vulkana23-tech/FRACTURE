# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Repositorio creado, arquitectura de 4 piezas definida (targets/
  harness_gen/ orchestrator/ triage/) -- ver README.md para el detalle
  completo.
- `targets/select_targets.py`: primera pieza real implementada. Lee el
  scope de programas ya trackeados por SPECTRE (solo lectura), cruza
  contra GitHub (lenguaje real, excluye archivados) y contra OSS-Fuzz de
  Google (confirma `main_repo` en el `project.yaml` real, no solo
  coincidencia de nombre). Corrido en vivo: 12 candidatos reales del
  ecosistema Hyperledger Fabric (todos Go), excluyendo correctamente el
  repo principal `hyperledger/fabric` (ya cubierto por OSS-Fuzz con
  libFuzzer+ASAN) y `hyperledger/besu` (Java, fuera de scope de
  lenguaje).
- `harness_gen/generate_harness.py`: segunda pieza real implementada.
  Clona un repo C/C++, lee un header público, y usa `qwen3-coder:30b`
  (Ollama, reusando la instancia que ya corre para SPECTRE) para
  redactar un borrador de harness de libFuzzer. Instalado clang 18 en
  el VPS para poder compilar/validar de verdad. Validado en vivo contra
  cJSON (librería de prueba, no target real): la primera corrida tenía
  2 bugs reales (include con case incorrecto, `stdint.h` faltante),
  corregidos con post-procesamiento determinístico
  (`_fix_common_issues`) -- confirmado que una segunda corrida ya
  compila y corre sin intervención manual (543,934 ejecuciones reales
  en 6 segundos).
- `orchestrator/run_go_fuzzer.py`: tercera pieza real implementada.
  Fuzzing nativo de Go (`go test -fuzz`) contra un repo real, con
  paralelismo real. Bug real encontrado y arreglado: `fabric-amcl` no
  tiene `go.mod` (código viejo estilo GOPATH) — `_ensure_go_module()`
  genera uno local en el clon temporal antes de fuzzear.
  **Primer hallazgo real de todo el proyecto**: `DL_verify_2`
  (verificación de firma Dilithium post-cuántica) crashea con un panic
  real de Go en el primer input de prueba (bytes vacíos) — falta
  validar la longitud de la clave pública antes de indexarla en
  `DL_unpack_pk`. Documentado con evaluación honesta de severidad en
  `findings/2026-08-09_fabric-amcl-dilithium-panic.md` — candidato
  real, todavía sin confirmar reachability end-to-end antes de
  reportarlo.
- `triage/classify_go_panic.py`: cuarta y última pieza de la
  arquitectura original implementada. Extrae mensaje + stack real
  (filtra plomería interna de Go) de un panic, dedup por hash, clasifica
  severidad por tipo. Validado contra el fixture REAL del hallazgo de
  `DL_verify_2` (no sintético) — bug real encontrado y arreglado en el
  camino: la regex de frames no incluía `-` en la clase de caracteres,
  no matcheaba `fabric-amcl` (tiene guión), el frame de origen quedaba
  vacío. 5/5 tests contra el fixture real.

### Estado: las 4 piezas de la arquitectura original están implementadas
y validadas en vivo, con un hallazgo real (sin confirmar todavía como
submission-ready) encontrado en el primer target real probado.

- Investigación de reachability del hallazgo de `fabric-amcl`: rastreada
  la cadena real de dependencias (`fabric` → `IBM/idemix` →
  `fabric-amcl`), confirmado que `IBM/idemix` solo usa las curvas BN254
  (esquema actual), nunca Dilithium. Conclusión honesta: probablemente
  código muerto, **no se reporta a Hyperledger**. Actualizado en
  `findings/2026-08-09_fabric-amcl-dilithium-panic.md`.
- Segundo fuzz test real: `decodeToken` (`hyperledger/fabric-ca`),
  elegido por reachability directa (parsea el token de autenticación de
  cada request HTTP real a la API de fabric-ca-server). Corrida de 30
  minutos con 16 cores en paralelo: sin crashes -- resultado limpio y
  real, sugiere que el parseo es razonablemente robusto.
- Piloto real de CodeQL como selector de targets (a pedido explícito
  del usuario, probado en FRACTURE primero por ser de menor riesgo que
  meterlo directo en el pipeline de producción de SPECTRE). Instalado
  CodeQL CLI (`/opt/codeql-bundle`). Resultado honesto: construir la
  base semántica tardó 5m47s para un repo mediano (mucho más lento que
  semgrep); la consulta `targets/codeql_queries/fuzz_candidates.ql` SÍ
  encontró `VerifyToken` -- la misma función elegida a mano para el
  fuzz test de `decodeToken`, validación real de que el enfoque
  funciona -- pero con 420 resultados totales, demasiado ruido para
  usar sin refinar la consulta primero.
- Quinto y sexto target reales: `FromString` (fabric-contract-api-go,
  limpio) y `json_parse_string`/parson dentro del enclave SGX real de
  fabric-private-chaincode -- **hallazgo real confirmado**, primero
  con ASan (heap-buffer-overflow determinístico en `skip_quotes`) y
  después con un PoC completo contra un enclave SGX real (SDK oficial
  de Intel, modo simulación): crash real del proceso enclave
  confirmado, y **fuga de confidencialidad end-to-end confirmada y
  reproducida 3/3** -- memoria de stack del enclave devuelta al host
  no confiable disfrazada de JSON válido. Ver
  `findings/2026-08-10_fabric-private-chaincode_parson_CONFIRMED.md`.
  Reporte en inglés preparado para enviar, PoC empaquetado en
  `orchestrator/fuzz_harnesses/fpc_sgx_leak_poc.zip`.
- Corregido un error propio: se había asumido que Hyperledger no tenía
  programa de bug bounty pago. Es falso -- programa real en HackerOne
  (`hackerone.com/hyperledger`, bajo LFDT desde la reorganización),
  con pagos reales (Critical desde \$2000, High desde \$1500, Medium
  desde \$500, Low desde \$200). Confirmado que `fabric-private-chaincode`
  y `fabric-sdk-go`, entre otros, están en el alcance elegible
  (`eligible_for_submission=true` en la tabla `bugbounty_scope_assets`
  de SPECTRE). El reporte del hallazgo de parson se va a reformatear
  para ese canal en vez de la Security Advisory genérica de GitHub.
- Séptimo target real: `extractConfig` (`pkg/fab/chconfig/chconfig.go`,
  fabric-sdk-go) -- **segundo hallazgo real confirmado de la sesión**,
  esta vez sin necesitar fuzzing: se vio leyendo el código
  (`block.Data.Data[0]` indexado sin chequear que `block.Data` no sea
  nil ni que el slice tenga elementos, pese a que sí chequea
  `block.Header == nil`) y se confirmó con un repro directo --
  panic real (nil pointer dereference y, en la variante con slice
  vacío, index out of range), 100% determinístico, misma línea exacta
  en ambos casos. Reachable desde `ChannelConfig.Query()` (API pública
  real) contra la respuesta de un peer u orderer ya autenticado del
  canal -- no hace falta un atacante externo, alcanza con que un solo
  participante bizantino/con bug propio devuelva un bloque de config
  incompleto para crashear cualquier cliente que lo consulte. Ver
  `findings/2026-08-10_fabric-sdk-go_chconfig_extractconfig_CONFIRMED.md`.
- Octavo target real, completo: `FuzzParseTransactionEnvelope`
  (`pkg/client/transactionparser.go`, fabric-gateway) -- cadena de 6
  `proto.Unmarshal` anidados sobre bytes que devuelve el Gateway/peer
  como respuesta a `Endorse()`. Campaña de 40 min con los 18 cores
  reales del VPS: **limpia, `PASS`, 171,494,451 ejecuciones reales**,
  sin ningún crash. Ver
  `findings/2026-08-10_fabric-gateway_parsetransactionenvelope.md`.
- Revisión manual de `fabric-admin-sdk` (mismo criterio que encontró
  los dos hallazgos reales de la sesión: buscar indexado `[0]`/acceso
  a slice sin chequeo de longitud cerca de `proto.Unmarshal`) --
  resultado honesto: nada obvio. A diferencia de `fabric-sdk-go`, acá
  `ensureValidResponses()` sí chequea `len(responses) == 0` antes de
  indexar, y el resto de los `Unmarshal` son wrappers de un solo nivel
  con manejo de error correcto. Candidato para una campaña de fuzzing
  real si se quiere invertir más tiempo, pero no hubo señal de lectura
  de código que lo priorizara sobre otros repos todavía sin tocar
  (`fabric-cli`, `fabric-lib-go` -- ambos revisados y descartados por
  baja superficie relevante; quedan `fabric-protos-go-apiv2`,
  `fabric-sdk-py/java/node/java-chaincode` sin tocar).
