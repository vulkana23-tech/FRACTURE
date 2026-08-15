# workerd — `DataUrl::tryParse` (api/data-url.c++) — resultado limpio

**Programa:** Cloudflare (HackerOne `hackerone.com/cloudflare`, `automated_scanning: allowed`)
**Repo:** `cloudflare/workerd` (Tier 1, C++, no cubierto por OSS-Fuzz)
**Target:** `workerd::api::DataUrl::tryParse(kj::StringPtr)` en `src/workerd/api/data-url.c++`

## Por qué este target

Parsea una URL `data:` completa (comma-split entre mimetype y payload,
detección de `;base64`, percent-decode, decode base64 permisivo vía
`simdutf`, y el mimetype resultante vía `MimeType::tryParse`) —
alcanzable desde cualquier Worker que procese una `data:` URL no
confiable (`fetch()`, `Response.redirect`, etc.). Combina tres piezas
reales (parseo propio de workerd + `ada`/`jsg::Url` + `simdutf`) detrás
de una sola función pública.

## Revisión manual (antes de fuzzear)

Repasado a mano: `isBase64` chequea `res.size() == 6` antes de indexar
`res[0..5]`; `decodeDataUrlBase64` chequea `base64.size() == 0` y
`result.error != SUCCESS` antes de usar el buffer decodificado, con
`KJ_ASSERT(result.count <= size)` como cinturón extra. Sin bug
encontrado a mano (ver también la revisión de `mimetype.c++` en
`findings/2026-08-11_workerd_mimetype_tryparse.md`, dependencia directa
de este mismo target).

## Setup de fuzzing (nota de infraestructura)

Reusa el `libkj` standalone armado para el finding anterior de
`mimetype`. Dependencias nuevas para este target:

- **`ada` (la librería real detrás de `jsg::Url`)**: vendoreada vía su
  propio script de amalgamación (`singleheader/amalgamate.py` del repo
  `ada-url/ada` v4.0.0, la misma versión que declara `workerd` en
  `build/deps/deps.jsonc`) -- genera un `ada.h`/`ada.cpp` de un solo
  archivo cada uno, mucho más simple que su build real de CMake.
- **`simdutf`**: mismo patrón, amalgamado desde `simdutf/simdutf` con
  su propio `singleheader/amalgamate.py`.
- **ICU** (`libicu-dev`, usada por `jsg::Url` para manejo de Unicode):
  ya estaba instalada en la VPS, se linkeó con `-licuuc -licui18n`.
- Bug real de build encontrado y arreglado en el camino: el archivo
  copiado `workerd/util/strings.h` chocaba de nombre con el header
  POSIX real del sistema `<strings.h>` (`strcasecmp` etc.) -- al agregar
  `-I.`, la copia local tapaba la del sistema y rompía la compilación de
  KJ río abajo con errores crípticos ("templates must have C++
  linkage"). Renombrado a `workerd_strings.h`/`.c++` en todas las copias
  locales.
- Mismo patch que en el finding de `mimetype`: la dependencia a
  `jsg/memory.h` (V8 completo) se reemplazó por un stub compartido
  (`fuzz_stubs.h`) con una clase `MemoryTracker` no-op y el macro
  `JSG_MEMORY_INFO(Type)` -- usado por `url.h` en tres puntos
  (`Url`, `Component`, `UrlPattern`). Lógica de parseo real intacta.
- Harness (`fuzz_dataurl.c++`): llama `DataUrl::tryParse` directo, y si
  parsea OK también ejercita `getData()`/`getMimeType().toString()`.
- Compiló limpio en todos los `.c++`/`.cpp` sin necesidad de tocar la
  lógica real de ninguno.

## Resultado

- Smoke test: 30s, 1,326,331 ejecuciones, limpio.
- Campaña completa: `-fork=18`, 2400s (40 min), **794,504,570
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura todavía subiendo levemente al final (7339→7438,
  corpus más rico que el target de `mimetype` solo) -- valdría una
  corrida más larga si se quiere exprimir más, pero sin señal de nada
  hasta acá.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza. No se reporta nada a Cloudflare. Quedan
reusables para el próximo target de `workerd`: el build de `libkj`
standalone, el patrón de amalgamación para dependencias vendoreadas
(`ada`, `simdutf`), y el stub compartido de `jsg::MemoryTracker`
(`fuzz_stubs.h`) para cualquier clase que use `JSG_MEMORY_INFO`.
