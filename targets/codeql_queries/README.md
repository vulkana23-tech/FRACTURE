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

## Intento 2: excluir vendor/test/cmd por path (2026-08-10)

`fuzz_candidates.ql` extendido con exclusiones de `vendor/`, `_test.go`
y paquetes `cmd/`/`tools/`. Resultado real: **420 → 416**, prácticamente
sin cambio. Revisando el output real, la hipótesis original era
incorrecta -- el ruido no viene de CLI/vendor, viene de funciones de
**formateo de mensajes de error** (`format string` para `fmt.Errorf`,
ej. `NewHTTPErr`, `CreateHTTPErr`) y **lookups internos sobre mapas
propios** (`Contains`, `Value`, `True` en `attrmgr`) -- estructuralmente
idénticas en TIPO a una función real de parseo de input externo, pero
semánticamente nada que ver. Un filtro basado solo en el tipo del
parámetro nunca va a distinguir esto -- hace falta seguir el flujo real
de datos.

## Intento 3: alcanzabilidad real desde ServeHTTP (2026-08-10)

`fuzz_candidates_reachable.ql`: en vez de filtrar por tipo/path, sigue
el grafo de llamadas REAL (cierre transitivo) desde `ServeHTTP`
(`lib/serverendpoint.go`, el método real que implementa `http.Handler`
en fabric-ca -- confirmado leyendo el código, no asumido). 3 errores de
compilación reales en el camino (API incorrecta -- `getACallExpr()` no
existe, tipos `Function`/`FuncDecl` incompatibles), corregidos
iterando contra los mensajes de error reales del compilador de CodeQL
hasta que compiló y corrió.

**Resultado real**: 420/416 → **2** candidatos. Reducción de ruido
dramática -- confirma que seguir el flujo real de datos SÍ funciona
mucho mejor que filtrar por tipo de dato. **Pero**: los 2 resultados son
`CreateHTTPErr`/`NewHTTPErr` (formateo de errores, no parseo de input) --
y **`decodeToken`/`VerifyToken` (las funciones reales que SÍ fuzzeamos
hoy) desaparecieron del todo**. Investigado por qué: `VerifyToken` se
llama como `ctx.ca.issuer.VerifyToken(...)` -- una llamada a través de
una **interfaz** (`issuer` es un campo de tipo interfaz), no una
llamada directa. El seguimiento de grafo de llamadas simple de CodeQL
(`CallExpr.getTarget()`) resuelve llamadas estáticas directas, pero NO
sigue despacho por interfaz sin un análisis de "points-to" más
sofisticado (determinar qué implementación concreta resuelve
`issuer.VerifyToken` en tiempo de ejecución).

## Conclusión honesta del piloto completo

Ninguna de las 3 versiones de la consulta, tal cual están hoy, sirve
para automatizar selección de targets sin revisión humana:
- La ingenua (v1) trae demasiado ruido (420).
- Excluir por path (v2) casi no ayuda (416) -- el ruido real es
  semántico, no estructural.
- Seguir el grafo de llamadas (v3) es preciso pero **pierde targets
  reales** que pasan por una interfaz -- exactamente el patrón más común
  en código Go bien diseñado (fabric-ca usa una interfaz `issuer`
  a propósito, para poder testear con un mock).

Resolver esto bien necesitaría la librería de DataFlow real de CodeQL
(seguimiento de flujo con resolución de interfaces, no solo el grafo de
llamadas estático) -- una inversión de tiempo mayor, no algo para
resolver en una sesión más. Por ahora, la selección de targets sigue
siendo manual (leer el código real, como se hizo hoy con
`fabric-amcl`/`fabric-ca`) -- CodeQL sirve como ayuda exploratoria
puntual (confirmó `VerifyToken` en el intento 1), no como reemplazo
automático del criterio humano todavía.
