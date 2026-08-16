# targets/

Selección de qué proyecto OSS fuzzear. Criterios (ver README.md raíz
para el detalle completo): scope de bounty real, poca cobertura de
fuzzing existente (chequear OSS-Fuzz primero), lenguaje memory-unsafe o
con superficie unsafe real.

## Estado real (2026-08-15)

`select_targets.py` ya estaba implementado (este README decía "sin
implementación todavía" pero estaba desactualizado, no el código --
mismo problema que se encontró en `harness_gen/README.md` esta misma
ronda, dos READMEs desactualizados de dos en dos no es casualidad, ver
nota abajo). Pipeline real: repos watched de SPECTRE (solo lectura,
nunca escribe ahí) → GitHub API (lenguaje real, archived) → OSS-Fuzz
(`project.yaml` real, no coincidencia de nombre) → tier por lenguaje.

**Agregado esta ronda**: ranking por actividad reciente
(`pushed_at`, que ya viene GRATIS en la misma respuesta de GitHub que
se pedía para lenguaje/archived -- sin llamada extra a la API, el rate
limit sin auth ya es apretado, 60/hora) -- dentro del mismo tier, un
repo con push reciente ordena primero. Señal barata para "código
probablemente sin fuzzear todavía": el piloto de CodeQL
(`targets/codeql_queries/README.md`) ya había concluido que seguir el
grafo de llamadas para esto pierde targets reales (dispatch por
interfaz) y cuesta 5+ minutos de preparación por repo -- esto no
reemplaza esa idea, es la alternativa barata que sí se puede correr
para TODOS los candidatos sin ese costo.

Corrida real contra la base de SPECTRE (2026-08-15): de 15 candidatos
reales que sobreviven los filtros duros, `fabric-samples`,
`fabric-lib-go`, `fabric-private-chaincode`, `fabric-protos-go` y
`cb-mpc-go` salieron con actividad reciente real (15-136 días) y
CERO harnesses todavía en `orchestrator/targets.json` -- candidatos
concretos, no teóricos, para la próxima ronda de `harness_gen/`.

## `find_patch_directed_candidates.py` -- fuzzing dirigido por parche

Complementa `select_targets.py` (qué REPO fuzzear) con "qué FUNCIÓN
específica priorizar dentro de un repo ya elegido": busca commits
recientes cuyo mensaje suene a seguridad (overflow, UAF, CVE, null
pointer, etc. -- inglés y español) y filtra los que en realidad son
bumps de dependencias/CI (que sí mencionan "CVE" en el mensaje pero no
tocan código propio). El código *alrededor* de un parche reciente es
donde más probablemente haya variantes del mismo bug o un fix
incompleto -- mucho más rápido que fuzzing ciego, y es una técnica
real de bug bounty (muchos programas pagan por "regresión"/"fix
incompleto"), no algo teórico.

**Dos iteraciones reales de filtro, probadas en vivo contra
`hyperledger/fabric-ca`** (documentado como caso de estudio en los
tests, no solo en este README):
1. Filtro por lista negra de archivos "ruido" (`go.mod`, `vendor/`,
   `.github/`) -- un archivo nuevo (`osv-scanner.toml`) la esquivó en
   la primera corrida real.
2. Cambiado a lista BLANCA: un commit solo es candidato si toca al
   menos un archivo con extensión de código fuente real, Y ese archivo
   no está bajo `vendor/`/`node_modules/`/`third_party/`/`docs/`
   (código vendoreado de terceros o tooling de docs, no lógica de la
   app). Mucho más robusto -- no necesita mantenimiento cada vez que
   aparece una herramienta de CI nueva.

**Resultado real contra `hyperledger/fabric-ca`** (4 años de
historial): 0 candidatos -- honesto, no un bug: TODO el historial de
seguridad real de ese repo fueron bumps de dependencias, correctamente
filtrados.

**Resultado real contra `cloudflare/workerd`** (1 año): encontró 8
commits reales relacionados a seguridad. **Corrección honesta post-
revisión manual (2026-08-15)**: los 3 candidatos revisados a fondo
(UAF en `streams/`, UAF en `jsg::Function`, bypass de flag RPC en
deserialización de wrapped-binding) resultaron ser **bugs de ciclo de
vida de V8/JS** (re-entrancy vía `toString()` de usuario, GC de
ArrayBuffers, semántica de capacidades RPC) -- no bugs de parseo de
bytes no confiables. Ese tipo de bug necesita ejecutar JS real dentro
del motor V8 en una secuencia específica de llamadas (exactamente lo
que los tests `autovuln-*.js`/`.wd-test` del propio workerd ya hacen),
no algo que un harness `bytes -> función` de libFuzzer pueda
encontrar. Se intentó generar un harness igual (`dale, arrancá con
harness_gen para el candidato de workerd`) y se descartó honestamente
en vez de forzar algo que no iba a funcionar -- ver
`harness_gen/README.md`. Conclusión real: el filtro actual (mensaje +
extensión de archivo) encuentra commits de seguridad reales, pero no
distingue la FORMA del bug (parseo de bytes vs. lógica/lifecycle de
runtime) -- ver "Lo que falta" abajo.

**Resultado real contra `hyperledger/fabric-private-chaincode`** (2
años): encontró el commit real `1e92847744` ("Fix null pointer issuer
in unmarshal_values", 2025-03-29) -- la MISMA función que ya motivó el
harness de parson existente en este proyecto, pero cubriendo mucho
menos que la función completa. Se construyó un harness nuevo
(`fpc_unmarshal_values_harness.c++`) que sí replica la función
completa (post-fix) -- encontró un memory leak real en el primer
intento (LeakSanitizer, `[{"key":"a"}]` sin campo `"value"` no libera
el `JSON_Value*`). Ver
`findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md`.
Este SÍ era la forma correcta de bug (parseo de bytes no confiables
dentro de un enclave SGX) -- contraste real y útil con el caso de
`workerd` de arriba.

## Uso

```
venv/bin/python3 targets/select_targets.py [--program handle]

venv/bin/python3 targets/find_patch_directed_candidates.py \
  --repo https://github.com/cloudflare/workerd --since-days 365

venv/bin/python3 -m pytest targets/ -v
```

## `patch_directed_go_harness.py` -- pipeline automático (2026-08-15)

Conecta `find_patch_directed_candidates.py` con
`harness_gen/generate_go_harness.py` sin copiar/pegar nombres de
función a mano: descarta commits marcados como ciclo de vida V8/JS,
extrae nombres de función Go reales del contexto de cada hunk
(`func (recv Type) Nombre(...)`), prioriza los que mencionan
`[]byte`/`string` en la firma (superficie de bytes real), y llama a
`generate_and_validate_go_harness` para el primer candidato que
compila y corre de verdad.

**Resultado real contra `hyperledger/fabric`** (no los satélites más
chicos ya explorados -- el repo principal del peer, mucho más activo):
encontró 4 commits reales de seguridad con candidatos Go reales
(`Push` en `gossip/state/payloads_buffer.go`, `HandleTransaction` en
`core/chaincode/handler.go` -- literalmente "Recover from panic...to
prevent peer crash" --, `directMessage` en `gossip/state/state.go`).
**Primer intento, sin el filtro de `[]byte`/`string` todavía**: generó
y validó un harness real para `Ready()` -- compiló y corrió de
verdad, pero `Ready()` no toma NINGÚN parámetro relevante (solo
devuelve un canal), así que el harness resultante fuzzeaba un
`uint64` arbitrario sin ninguna superficie de bytes no confiables que
ejercitar. **Se descartó ese harness a propósito** (nunca se registró
en `orchestrator/targets.json` -- hubiera gastado cores reales en algo
sin valor) y se agregó la priorización por `[]byte`/`string` en la
firma.

**Limitación real, honesta, encontrada re-analizando los 4 candidatos**:
ni `Push(payload *proto.Payload)`, ni `HandleTransaction(msg
*pb.ChaincodeMessage, ...)`, ni `directMessage(msg
protoext.ReceivedMessage)` toman `[]byte`/`string` tampoco -- todos
reciben structs YA deserializados. El límite entre bytes crudos y
struct (el `proto.Unmarshal` real) casi nunca está en la MISMA función
que el commit de seguridad tocó -- está en código generado o en un
wrapper, en otro lugar del repo. Encontrar el punto de entrada real de
bytes crudos cerca de un commit de seguridad seguiría necesitando
criterio humano (exactamente lo que se hizo a mano para
`unmarshal_values`) -- este pipeline automatiza la mecánica
(generar+validar) pero no reemplaza esa lectura real del código
cuando el candidato obvio no alcanza.

## Nota sobre los READMEs de este repo

Dos de dos READMEs revisados a fondo esta ronda (`harness_gen/`, este)
decían "sin implementación todavía" con código real y funcionando
adentro. Vale la pena, en algún momento, auditar el resto
(`orchestrator/`, `triage/` ya se corrigieron esta ronda) en vez de
asumir que un README desactualizado significa que hay que empezar de
cero -- leer el código primero.

## `GITHUB_TOKEN` (2026-08-16)

`select_targets.py` ya acepta un `GITHUB_TOKEN` opcional (fine-grained
PAT, **solo lectura pública**, generado por el usuario específicamente
para esto -- nunca se reusó el token de push de Vigia de una ronda
anterior, a propósito: un token de solo-lectura-pública tiene mucho
menos blast radius si se filtra que uno con permiso de escritura).
Confirmado en vivo: `5000` req/hora reales con el token vs `60` sin
él. Se lee desde `.env` (gitignoreado, `chmod 600`) vía un loader
mínimo agregado a `targets/config.py` -- sin agregar `python-dotenv`
como dependencia nueva, nunca pisa una variable ya seteada de verdad
en el entorno. Sin el token, todo sigue funcionando igual, solo con el
límite sin autenticar.

## Lo que falta (honesto)

- No hay heurística de "qué PATHS específicos tocó el push reciente"
  (parsers/serializers vs. CI/docs) -- con el rate limit real ya en
  5000/hora esto dejó de ser el problema (ver arriba), pero la
  heurística en sí (qué extensión de archivo prioriza mejor un
  candidato) no se implementó todavía.
- ~~No distingue la FORMA del bug~~ **implementado (2026-08-15)**:
  `_looks_js_engine_lifecycle_bound()` marca un candidato si el
  contexto del hunk (heurística de `git show`) menciona
  `jsg::`/`v8::`/`V8::` -- probado contra las firmas reales de los 3
  candidatos de `workerd` ya investigados a mano Y contra
  `unmarshal_values` (fabric-private-chaincode, que correctamente NO
  se marca). Corrida real contra `workerd` de nuevo: **5 de 8**
  candidatos quedaron marcados con la advertencia real en el output
  del CLI.

  **Limitación real encontrada corriendo esto en vivo, no teórica**:
  el commit `644f2c1598` (el fix real de UAF en `jsg::Function`) **NO**
  quedó marcado -- el hunk de git anclò el contexto a la clase
  contenedora (`class Function<Ret(Args...)> {`) en vez de a la firma
  del método real (`Ret operator()(jsg::Lock& jsl, ...)`), porque es
  un método definido inline dentro del cuerpo de una clase template en
  un header -- el propio heurístico de contexto de `git show` no
  siempre baja hasta la firma del método en ese caso, es una
  limitación de git mismo, no del regex.

  **Cerrado (2026-08-16)**: `targets/ast_function_boundary.py` agrega
  una SEGUNDA fuente de señal via tree-sitter real (C++, Go, Rust,
  Java) -- para cada hunk, parsea el archivo POST-parche completo y
  encuentra TODOS los nodos `function_definition`/`method_declaration`/
  `function_item` ancestros que contienen la línea cambiada (no solo el
  más específico), en vez de confiar solo en el contexto de una línea
  que `git show` infiere. No reemplaza `_guess_functions_touched`
  (sigue siendo la señal barata de primera línea), la complementa: solo
  agrega firmas NUEVAS que la heurística de git no encontró.

  **Segundo hallazgo real, encontrado validando esto en vivo contra el
  archivo real (no la reproducción sintética)**: la primera versión
  devolvía solo el nodo MÁS CHICO que contiene la línea -- y en
  `workerd`, los macros `KJ_SWITCH_ONEOF`/`KJ_CASE_ONEOF` (forma
  `NOMBRE(args) { ... }`, muy usados en ese repo) engañan a
  tree-sitter-cpp sin preprocesar: los parsea como definiciones de
  función ANIDADAS dentro del `operator()` real que las contiene. Con
  "nodo más chico" solamente, el resultado real era
  `KJ_CASE_ONEOF(native, Ref<NativeFunction>)` -- ruido de macro, sin
  `jsg::` en el texto, así que el commit `644f2c1598` seguía sin
  marcarse. Corregido devolviendo la cadena COMPLETA de ancestros
  función-como, no solo el más específico -- inofensivo agregar el
  ruido del macro de más, lo que importa es que la firma real de más
  afuera (`Ret operator()(jsg::Lock& jsl, Args... args)`) también quede
  incluida.

  **Confirmado extremo a extremo contra el repo real** (no solo el
  archivo aislado): `644f2c1598` ahora sí queda marcado
  (`js_engine_lifecycle_bound: True`), con las 5 firmas reales
  (`wd_test(`, `class Function<Ret(Args...)> {`, `Ret operator()(jsg::Lock&
  jsl, Args... args)`, `KJ_SWITCH_ONEOF(impl)`,
  `KJ_CASE_ONEOF(native, Ref<NativeFunction>)`) -- corrida real contra
  `cloudflare/workerd` (400 días, 20 commits máx): 14/20 candidatos
  quedan marcados. Ver `targets/test_ast_function_boundary.py`
  (incluye el caso de regresión real del macro).
- ~~`find_patch_directed_candidates.py` no está conectado todavía a
  `harness_gen/`~~ **cerrado (2026-08-15/16)**: `patch_directed_go_harness.py`
  (Go), `patch_directed_rust_harness.py` (Rust) y `patch_directed_jvm_harness.py`
  (JVM) conectan el pipeline completo, todos probados en vivo contra
  repos reales -- ver `harness_gen/README.md` para el detalle de cada
  uno. C/C++ sigue siendo manual (`generate_harness.py` ya tiene loop
  de validación real desde 2026-08-16, pero sin pipeline automático de
  patch-directed todavía -- los 2 targets de C/C++ encontrados esta
  ronda se armaron a mano porque el contexto ya estaba investigado a
  fondo).

## Barrido completo del scope real de SPECTRE (2026-08-16)

Corridos los 15 candidatos reales que devuelve `select_targets.py`
(tier 1 + tier 2, scope de bounty real) contra
`find_patch_directed_candidates.py`, uno por uno, con criterio humano
sobre cada resultado en vez de generar harnesses ciegamente:

| Repo | Resultado real |
|---|---|
| `cloudflare/workerd` | 8 commits, 3 investigados a fondo -> bugs de lifecycle V8/JS, no fuzzeable con harness bytes->función (ver arriba) |
| `coinbase/cb-mpc` | 2 targets registrados (`cbmpc_bits_convert`, converter previo), campañas reales limpias |
| `hyperledger/fabric-contract-api-go` | 1 candidato, pero es ruido: bump de dependencia npm (`form-data` CVE-2025-7783), no código Go propio |
| `hyperledger/fabric-chaincode-go` | 0 commits de seguridad en 400 días |
| `hyperledger/fabric-samples` | 2 targets nuevos (`add`/`sub` overflow en chaincode token ERC20) |
| `hyperledger/fabric-ca` | 0 candidatos (verificado en ronda anterior, 4 años de historial) |
| `hyperledger/fabric-admin-sdk` | 0 commits de seguridad nuevos (ya tiene 1 target por otra vía) |
| `hyperledger/fabric-lib-go` | 1 candidato real (`8fe16c9967`, fix de **race condition** con `atomic.Pointer`) -- **no fuzzeable con libFuzzer**, es un bug de concurrencia, no de parseo de bytes |
| `hyperledger/fabric-private-chaincode` | memory leak real encontrado y documentado (`unmarshal_values`) |
| `hyperledger/fabric-config` | 0 commits de seguridad nuevos (ya tiene 1 target por otra vía) |
| `hyperledger/fabric-protos-go` | 0 commits de seguridad |
| `hyperledger/fabric-protos-go-apiv2` | 0 candidatos reales, solo bumps de dependencias |
| `coinbase/cb-mpc-go` | 1 candidato real (`72eca12622`, mTLS hardening -- reemplaza un peer-ID leído directo del wire sin atar criptográficamente por verificación de SAN del certificado, buen fix real) -- pero **código muerto**: el paquete `pkg/cbmpc/transport/mtls` entero fue eliminado en un refactor posterior (`b10edd5`, "cb-mpc-v0.2.0"), no vale la pena un harness para código que ya no existe en HEAD |
| `hyperledger/fabric-cli` | 0 commits de seguridad (1200 días de historial) |
| `hyperledger/fabric-amcl` | 0 commits de seguridad nuevos (ya tiene 1 target por otra vía) |

**Conclusión real**: de 15 repos del scope, 11 no aportaron candidatos
nuevos fuzzeables (0 commits, ruido de dependencias, código muerto, o
bug de concurrencia fuera del alcance de libFuzzer). Los 4 que sí
aportaron (`cb-mpc`, `fabric-samples`, `fabric-private-chaincode`, y el
histórico `fabric-ca`→`workerd` de rondas previas) ya están cubiertos
con targets reales en `orchestrator/targets.json`. El scope actual de
SPECTRE está efectivamente agotado para esta técnica -- la próxima
ronda de descubrimiento necesita ampliar el scope (nuevos programas de
bounty) o cambiar de técnica (ver limitaciones de `git show`
documentadas arriba).
