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
