# harness_gen/

Generación de harnesses de fuzzing asistida por IA — lee la API/tests
públicos del target y redacta un harness real. Reusa Ollama
(qwen3-coder:30b, ya corriendo en este VPS para SPECTRE, puerto 11435 —
**no** el Ollama nativo del host en el puerto default 11434, que está
corriendo pero sin modelos descargados).

## Estado real (2026-08-15)

Dos generadores, un objetivo distinto cada uno:

- **`generate_harness.py`** (C/libFuzzer) — le das un header real +
  una función, te devuelve un *borrador* de
  `LLVMFuzzerTestOneInput`. **Nunca lo compila ni lo corre** — es
  input directo para revisión humana antes de usarlo. Ya tenía
  post-procesamiento determinístico documentado contra 2 bugs reales
  (include en minúscula que no matchea el nombre real del header
  case-sensitive; `<stdint.h>` faltante).

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

## Lo que falta (honesto)

- `generate_harness.py` (C) sigue sin loop de validación real (compila
  y corre) -- sigue siendo un borrador para ojo humano. Se podría
  extender con el mismo patrón ahora que ya está probado en Go y Rust,
  no se hizo en esta ronda para no inflar el scope.
- `generate_rust_harness.py` no tiene un pipeline automático desde
  `find_patch_directed_candidates.py` como sí tiene Go
  (`targets/patch_directed_go_harness.py`) -- extensión natural, misma
  mecánica (extraer `pub fn nombre(` del contexto de un hunk), no se
  hizo en esta ronda.
