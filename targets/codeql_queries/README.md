# CodeQL como selector de targets de fuzzing (piloto)

Probado a pedido explícito del usuario como *piloto en FRACTURE*, no
directo en SPECTRE — bajo riesgo (sin cronograma de producción que
romper), caso de uso chico y acotado (identificar funciones candidatas
a fuzzing, no buscar vulnerabilidades directamente).

## Instalación real

CodeQL CLI bundle (incluye motor + query packs estándar) instalado en
`/opt/codeql-bundle`, symlink en `/usr/local/bin/codeql`. ~823MB
descargados desde el release oficial de `github/codeql-action`.

## Resultado real del piloto (2026-08-10, contra hyperledger/fabric-ca)

**Tiempo de construcción de la base**: 5m47s para un repo Go mediano --
confirma en la práctica que CodeQL es MUCHO más lento que semgrep (que
en SPECTRE escanea el allowlist completo en ~6 minutos, pero eso son
2207 templates contra TODO el repo, no la preparación de un solo repo).
Cualquier uso en un pipeline con cronograma fijo necesita presupuesto
de tiempo explícito para este paso.

**`fuzz_candidates.ql`**: consulta real, corrida contra la base real.
Encontró `VerifyToken` (y sus parámetros `token`/`method`/`uri`) --
exactamente la misma función que se identificó a mano leyendo código
para el fuzz test real de `decodeToken` (ver
`orchestrator/fuzz_tests/fabric_ca_decodetoken_test.go`). Validación
real de que el enfoque encuentra targets genuinos.

**Pero**: 420 resultados totales para un repo mediano -- demasiado
ruido para ser útil sin refinar. La heurística actual ("cualquier
función exportada con un parámetro `string`/`[]byte`") es
deliberadamente ingenua para la primera prueba; trae de todo (parseo de
flags de CLI, manejo de paths de archivo) mezclado con las funciones
realmente interesantes (parseo de input de red no confiable).

## Próximo paso (no implementado todavía)

Refinar la consulta para acotar a paquetes/contextos de mayor señal
real (ej. funciones alcanzables desde un handler HTTP, o dentro de
paquetes como `util`/`server` en vez de `cmd`/herramientas de línea de
comandos) antes de usar esto para automatizar la selección de targets
sin revisión humana.
