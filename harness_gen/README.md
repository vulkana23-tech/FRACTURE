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

## Lo que falta (honesto)

- No hay generador para Rust/cargo-fuzz todavía (el otro engine real
  de `orchestrator/`) -- el patrón de "generar + compilar de verdad +
  reintentar contra el error real" de `generate_go_harness.py` se
  traslada directo, pero cargo-fuzz necesita scaffolding de crate
  (`cargo fuzz init`/`fuzz/Cargo.toml`) que Go nativo no, así que no es
  una copia mecánica del mismo código.
- `generate_harness.py` (C) sigue sin loop de validación real (compila
  y corre) -- sigue siendo un borrador para ojo humano. Se podría
  extender con el mismo patrón ahora que ya está probado en Go, no se
  hizo en esta ronda para no inflar el scope.
