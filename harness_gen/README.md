# harness_gen/

Generación de harnesses de fuzzing asistida por IA — lee la API/tests
públicos del target y redacta un harness real. Reusa Ollama
(qwen3-coder:30b, ya corriendo en este VPS para SPECTRE, puerto 11435 —
**no** el Ollama nativo del host en el puerto default 11434, que está
corriendo pero sin modelos descargados).

## Estado real (2026-08-15)

Dos generadores, un objetivo distinto cada uno:

- **`generate_harness.py`** (C/libFuzzer) — le das un header real +
  una función, te devuelve un harness de `LLVMFuzzerTestOneInput`. Ya
  no es solo un borrador: **compila y corre de verdad** (agregado
  2026-08-16, ver sección propia más abajo) para librerías amalgamadas
  en 1-2 archivos -- para lo demás, o si no se puede validar,
  igual sirve como borrador para revisión humana. Post-procesamiento
  determinístico contra 2 bugs reales (include en minúscula que no
  matchea el nombre real del header case-sensitive; `<stdint.h>`
  faltante).

- **`generate_go_harness.py`** (Go nativo, `go test -fuzz`) — la pieza
  nueva de esta ronda. A diferencia del generador de C, este SÍ
  compila y corre de verdad lo que genera el modelo contra el repo
  real clonado (reusa `_clone_shallow`/`_ensure_go_module` de
  `orchestrator/run_go_fuzzer.py`, el mismo código que después lo va a
  correr en producción) y, si falla, le pasa el error REAL del
  compilador de vuelta al modelo para que se corrija — hasta 3
  intentos. Mismo criterio de "iterar contra el error real del
  toolchain" que ya se usó en el piloto de CodeQL
  (`targets/codeql_queries/README.md`).

  Probado end-to-end contra un target real nunca antes tocado por este
  proyecto: `GetAttributesFromIdemix` en
  `hyperledger/fabric-chaincode-go/pkg/attrmgr` — encadena dos
  `proto.Unmarshal` sobre bytes crudos, la MISMA forma de bug que ya
  encontró un hallazgo real en `fabric-sdk-go` este mismo proyecto.
  Harness validado, agregado a `orchestrator/fuzz_tests/` y
  `orchestrator/targets.json` (16º target real del registro).

### Dos bugs reales encontrados armando esto (no teóricos)

1. **Contención de CPU real, sin GPU**: `nvidia-smi` ni siquiera está
   instalado en este VPS — qwen3-coder:30b corre 100% en CPU. Medido
   en vivo sin contención: ~0.8 tokens/seg. Con
   `orchestrator/scheduler.py` corriendo 24/7 de verdad compitiendo
   por los 18 cores, la primera corrida real dio timeout a los 240s
   que tenía configurados al principio. Subido a 1200s, documentado en
   el código que la opción real si vuelve a pasar es pausar el
   scheduler (`systemctl stop fracture-orchestrator`), no seguir
   subiendo el timeout a ciegas.

2. **El validador de Go daba falsos positivos, y no era obvio**: el
   archivo del harness candidato se escribía como
   `_harness_gen_candidate_test.go`. Un nombre que EMPIEZA con `_` (o
   `.`) es ignorado EN SILENCIO por el propio `go` tool (regla real y
   documentada del toolchain, no un bug de este proyecto) — `go test`
   nunca vio el archivo, así que devolvía `returncode=0` + `PASS`
   pasara lo que pasara adentro. Se encontró porque el primer harness
   real que generó el modelo (con dos imports sin usar, un error de
   compilación real y trivial) "pasó la validación" igual — algo que
   no debería haber pasado nunca. Confirmado reproduciendo el bug a
   mano, corregido (nombre sin underscore inicial), y con un test de
   regresión real en `test_generate_go_harness.py` que compila el
   MISMO harness inválido contra un paquete Go local (sin red) y
   confirma que ahora se rechaza. Con el fix, el mismo target real
   necesitó 2 intentos (el primero falló exactamente por ese error de
   imports, el segundo lo corrigió solo).

## Uso

```
# C/libFuzzer -- borrador sin validar, revisar antes de compilar:
venv/bin/python3 harness_gen/generate_harness.py \
  --repo https://github.com/DaveGamble/cJSON --header cJSON.h \
  --function cJSON_Parse --out /tmp/harness_cjson.c

# Go nativo -- SI compila y corre de verdad antes de escribir el archivo final:
venv/bin/python3 harness_gen/generate_go_harness.py \
  --repo https://github.com/hyperledger/fabric-chaincode-go \
  --package-path pkg/attrmgr --function GetAttributesFromIdemix \
  --out orchestrator/fuzz_tests/nuevo_test.go

venv/bin/python3 -m pytest harness_gen/ -v
```

## Intento real: candidato de `workerd` (2026-08-15)

`targets/find_patch_directed_candidates.py` había marcado 3 commits
reales de `cloudflare/workerd` como candidatos de alta prioridad (UAF
en streams, UAF en `jsg::Function`, bypass de RPC flag). Se investigó
en serio antes de generar nada: los 3 diffs reales mostraron que son
bugs de **ciclo de vida de V8/JS** (re-entrancy vía `toString()` de
usuario, GC de `ArrayBuffer`/`BackingStore`, semántica de capacidades
RPC vía `jsg::Deserializer`) -- no bugs de parseo de bytes no
confiables. Ese tipo de bug solo se dispara con una secuencia
específica de llamadas JS reales dentro de V8 (exactamente lo que los
tests `autovuln-*.js`/`.wd-test` del propio `workerd` ya cubren), no
algo que `LLVMFuzzerTestOneInput(bytes)` pueda alcanzar. Se decidió
NO generar un harness falso que nunca iba a compilar/tener sentido
-- ni con `generate_harness.py` (C, sin validación real de todas
formas) ni forzando `generate_go_harness.py` (Go, lenguaje
equivocado).

**Se pivoteó a un candidato real y mejor**: `fabric-private-chaincode`,
función `unmarshal_values` (misma función que ya motivó el harness de
parson existente en este proyecto). Ahí SÍ el bug real
(`1e92847744`, "Fix null pointer issuer in unmarshal_values") es
exactamente parseo de bytes no confiables dentro de un enclave SGX --
la forma correcta para este stack. Harness nuevo escrito A MANO
(`orchestrator/fuzz_harnesses/fpc_unmarshal_values_harness.c++`, C++,
no generado por IA -- ya se tenía todo el contexto real de la lectura
manual del código, generar hubiera sido más lento que escribirlo) que
replica la función completa (post-fix), a diferencia del harness de
parson existente que solo cubre el tokenizado JSON. Encontró un leak
real (LeakSanitizer) en el primer intento real -- ver
`findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md`.

**Lección real para el próximo candidato de C++ con JSG/V8 en la
firma**: no es candidato de `harness_gen/` tal como está hoy -- ver
`targets/README.md`, "Lo que falta", para la heurística propuesta
(chequear `jsg::Lock`/`v8::` en la firma antes de siquiera intentar
generar).

## `generate_rust_harness.py` (2026-08-16)

Mismo criterio que `generate_go_harness.py` (genera con qwen3-coder,
compila y CORRE de verdad, reintenta con el error real del
compilador) pero para cargo-fuzz. A diferencia de Go, los crates de
Rust en este proyecto son clones PERSISTENTES bajo
`build/rust_targets/` (mismo patrón ya establecido por
`run_rust_fuzzer.py`) -- `--crate-dir` apunta a un clon YA HECHO,
nunca clona nada solo. Reusa `run_rust_fuzzer()` de
`orchestrator/run_rust_fuzzer.py` directo para la validación real (el
mismo código que después corre esto en producción).

Dos casos reales cubiertos y probados en vivo:
- **Crate sin `fuzz/` todavía** -- corre `cargo +nightly fuzz init`
  solo (bootstrap real, confirmado que arma el
  `[dependencies.<crate>] path = ".."` correcto), y borra el target
  placeholder (`fuzz_target_1`, sin fuzzing real adentro) que la
  herramienta genera sola.
- **Crate con `fuzz/` ya existente** (el caso real de
  `build/rust_targets/tofn` y el resto de los targets ya en
  producción) -- agrega un nuevo `[[bin]]` al `fuzz/Cargo.toml`
  existente sin tocar los targets ya registrados. Confirmado en vivo
  agregando un segundo target a un crate que ya tenía uno.

Probado end-to-end contra un crate real y mínimo (`parse_len_prefixed`,
mismo patrón de bug de longitud-mal-declarada que ya se usó en otros
fixtures de este proyecto): primer intento con la versión inicial del
código dio un build roto (retry real, no simulado); el segundo,
después de recibir el error real del compilador, compiló y corrió.

**Bug real encontrado y corregido en el camino**: la limpieza del
target placeholder usaba un regex no-greedy genérico
(`.*?\n\n?`) que paraba de matchear demasiado pronto, dejando
`test = false`/`doc = false`/`bench = false` huérfanos (sin su
`[[bin]]`/`name`/`path`) en el `fuzz/Cargo.toml` real -- TOML mal
formado que `cargo` toleró esta vez pero no había garantía de que
siguiera tolerándolo. Como el bloque que genera `cargo fuzz init` es
determinístico (confirmado corriéndolo en vivo), se cambió a un match
literal del bloque exacto en vez de un patrón genérico -- con test de
regresión real (`test_generate_rust_harness.py`, contra un crate Rust
local en `testdata/`, sin red).

## `targets/patch_directed_rust_harness.py` (2026-08-16)

Cierra el gap de arriba -- conecta `find_patch_directed_candidates.py`
con `generate_rust_harness.py`. A diferencia de la versión Go (que
clona el repo fresco), acá `--crate-dir` apunta al clon PERSISTENTE
real (`build/rust_targets/<crate>`, mismo patrón ya establecido para
Rust en este proyecto) -- `--repo` se usa solo para escanear
historial, en un clon temporal aparte.

**Bug real encontrado extendiendo esto a Rust, no solo Go**: el mismo
problema de `git show` anclando el contexto del hunk al bloque
contenedor (`impl<E: Engine> Proof<E> {`) en vez de a la firma real
(`pub fn read_many(proof_bytes: &[u8], ...)`) que ya se había visto
con C++ (`workerd`/`jsg::Function`) volvió a aparecer, esta vez con
Rust real (`filecoin-project/bellperson`). Se resolvió agregando un
segundo lugar donde buscar: además de `functions_touched_guess` (el
contexto que `git show` elige), también se escanea el cuerpo crudo del
diff (`diff_excerpt`) por firmas `pub fn` reales -- ahí la firma
completa SÍ aparece como línea de contexto normal del hunk, aunque
`git` no la haya elegido como header.

**Resultado real, end-to-end, primer intento**: candidato real
encontrado (`read_many`, el propio mensaje del commit real
`361d245447` dice "`proof_bytes` is untrusted, user input"),
harness generado y VALIDADO (compiló y corrió de verdad) en el primer
intento -- registrado como target real
(`bellperson_read_many`, target 20 de `orchestrator/targets.json`),
cobertura nueva de verdad (el harness existente de bellperson
solo cubre `Proof::read` de un proof individual, `read_many` es la
variante batch/paralela, código distinto).

## `generate_harness.py` (C) -- validación real (2026-08-16)

Mismo criterio que Go/Rust: compila y CORRE de verdad, reintenta con
el error real del compilador. C no tiene un comando de build universal
(sin `cargo fuzz build`/`go test -fuzz`) -- cubre el caso real más
común de los targets de C que ya tiene este proyecto (cJSON, parson,
zbxjson): una librería chica, amalgamada en (o cerca de) un solo
archivo `.c` junto a su `.h`. Por default busca un `.c` con el mismo
nombre base que el header en el mismo directorio del repo clonado; si
la librería real necesita más archivos (como zbxjson, que necesita
zbxalgo/zbxstr/zbxcommon/zbxnum además), hay que pasarlos a mano con
`--extra-source` -- no hay forma barata de resolver dependencias de C
solo, sin un build system real (mismo límite ya documentado en
`orchestrator/run_c_fuzzer.py`).

Probado end-to-end contra el ejemplo real ya referenciado en este
README (`cJSON_Parse`, `DaveGamble/cJSON`): **intento 1 falló con un
error REAL de compilador** (`memcpy` sin `<string.h>`, "implicit
function declaration" -- error real en C99+, no un warning), **intento
2 corrigió solo y compiló+corrió de verdad**. El harness final usa
`cJSON_Delete` correctamente para liberar memoria, tal cual pedía la
regla del prompt.

## `generate_jvm_harness.py` (2026-08-16)

Cuarto generador, mismo criterio (compila y CORRE de verdad, reintenta
con el error real). Mismo patrón que Rust: `--classes-dir`/`--lib-dir`
tienen que estar YA PREPARADOS de forma persistente
(`build/jvm_targets/<target>/`, un `*_build.sh` real por target --
Gradle/Maven real, no hay forma barata de bootstrapear un proyecto
Java arbitrario). `--repo` se usa solo para leer el `.java` fuente
real, clon shallow aparte.

Cubre los dos casos reales que ya aparecieron en este proyecto:
método público (llamada directa) y método privado (bypass de
constructor vía `ReflectionFactory`, mismo patrón ya validado a mano
en `parseAttributes`, dado al modelo como ejemplo concreto en el
prompt).

**Primer intento real, en vivo, contra `JSONTransactionSerializer.fromBuffer`**
(candidato encontrado a mano vía `javap`, no todavía por el pipeline
automático -- ver abajo): 2 corridas fallaron primero, con hallazgos
reales:

1. El modelo eligió innecesariamente el patrón de reflection para un
   método que es **público** -- se enredó con nombres de paquete mal
   escritos y símbolos no importados. Regla del prompt reforzada:
   "si es público, SIEMPRE llamada directa, nunca reflection".
2. El modelo adivinó un método (`TypeSchema.setType(...)`) que no
   existe en la API real de una clase cuyo código fuente nunca se le
   mostró. Regla agregada: nunca adivinar métodos de una clase sin ver
   su código real, construir la instancia más simple posible en su
   lugar (`new Tipo()` sin llamadas encima).

Con esas 2 reglas agregadas, el intento siguiente validó en el
**primer intento real** -- y el harness resultante encontró un
`NullPointerException` real en `JSONTransactionSerializer.convert`
(bug real, no del harness) en menos de 20s de fuzzing. Ver
`findings/2026-08-16_fabric-chaincode-java_jsontransactionserializer_npe.md`.

**Bug real propio encontrado en el camino, en `run_jvm_fuzzer.py` (no
en el generador)**: el classpath usaba rutas RELATIVAS -- funcionaba
siempre desde `orchestrator/targets.json` (que ya usa rutas absolutas)
pero rompía apenas se probó desde `generate_jvm_harness.py` con una
ruta relativa, porque Jazzer corre con un cwd aislado DISTINTO de
donde se invoca el script (mismo motivo real por el que
`run_c_fuzzer.py` ya hace `os.path.abspath(binary)` -- acá faltaba el
mismo fix). Corregido con `os.path.abspath()` en las 4 rutas reales
que recibe la función.

## `targets/patch_directed_jvm_harness.py` (2026-08-16)

Conecta `find_patch_directed_candidates.py` con
`generate_jvm_harness.py` -- mismo patrón que la versión Rust
(`--classes-dir`/`--lib-dir` ya preparados, `--repo` solo para
escanear historial). Regex de extracción de métodos Java propio,
prioriza firmas con `byte[]`/`String`, y escanea el cuerpo crudo del
diff además del contexto de hunk (mismo motivo real ya documentado en
las versiones Go/Rust: `git show` a veces ancla el contexto a la clase
contenedora, no al método).

**Resultado real contra `hyperledger/fabric-chaincode-java`** (2 años):
0 candidatos -- honesto, no un bug: el único commit de seguridad real
en esa ventana es un bump de dependencias sin ningún cambio a nivel de
función real (mismo patrón ya visto con `fabric-ca` para Go). Mecánica
del pipeline probada correcta con tests unitarios reales (firmas
exactas de `parseAttributes`/`fromBuffer`, los dos métodos que ya se
fuzzearon de verdad).

## Lo que falta (honesto)

- El generador de C solo cubre el caso de librería amalgamada en 1-2
  archivos -- no resuelve dependencias reales de un build system (ej.
  no podría validar `zbxjson` solo, que necesita 5 archivos reales
  además del propio; ahí `--extra-source` sigue siendo manual).
- `patch_directed_jvm_harness.py` no encontró todavía un candidato
  real vivo (los otros 2 repos Java en scope, `fabric-sdk-java` y
  `besu`, no tienen classpath persistente preparado todavía -- `besu`
  además dio, en la búsqueda manual, candidatos que resultaron ser
  código de test/reference-tests, no producción, mismo tipo de
  descarte honesto que ya pasó con el candidato de `workerd`).
