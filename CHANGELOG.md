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
