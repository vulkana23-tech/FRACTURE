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
