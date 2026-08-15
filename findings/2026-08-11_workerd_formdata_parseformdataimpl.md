# workerd — `parseFormDataImpl` (api/form-data.c++) — resultado limpio

**Programa:** Cloudflare (HackerOne `hackerone.com/cloudflare`, `automated_scanning: allowed`)
**Repo:** `cloudflare/workerd` (Tier 1, C++, no cubierto por OSS-Fuzz)
**Target:** `parseFormDataImpl(kj::ArrayPtr<const char>, kj::StringPtr, ParseCallback)` en `src/workerd/api/form-data.c++`

## Por qué este target

Parser hecho a mano de `multipart/form-data` -- split manual por
substring del delimitador de boundary, regex para encontrar el fin de
los headers de cada parte, y un parser combinator propio (`kj::parse`)
para el header `Content-Disposition`. Alcanzable directamente desde
`await request.formData()` en cualquier Worker con un body de request no
confiable. Boundary también viene de input atacante-influenciable (header
`Content-Type` real), así que el harness lo deja variar junto con el
body en vez de fijarlo.

## Por qué no necesitó nada de la infraestructura de `ada`/`simdutf`/`libkj` pesada

A diferencia de `mimetype`/`data-url`, `parseFormDataImpl` es una función
**standalone** (no depende de `jsg::Lock` ni V8 en su cuerpo) -- el único
motivo por el que `form-data.h`/`.c++` completos arrastran V8 es la
clase contenedora `FormData : public jsg::Object`. Se extrajo la función
(y sus helpers de namespace anónimo: `splitAtSubString`,
`FormDataHeaderTable`, los combinators `httpIdentifier`/
`contentDisposition`) tal cual del original a un archivo standalone
(`form_data_parse.c++`), sacando solo el prefijo `FormData::` de la
firma -- cero cambios de lógica.

Dependencia nueva real: `kj::HttpHeaders`/`kj::HttpHeaderTable`
(`<kj/compat/http.h>`) vive en un target de CMake separado de Cap'n
Proto (`kj-http`, que a su vez depende de `kj-async`) -- se compiló
ambos con el mismo `cmake`/cflags que ya se había armado para `libkj`.
Único ajuste de link: `kj-http` trae soporte de WebSocket con
compresión, así que hizo falta `-lz` (zlib, ya estaba instalado).
`JSG_REQUIRE`/`JSG_FAIL_REQUIRE`/`JSG_REQUIRE_NONNULL` resultaron ser
wrappers finos sobre `KJ_REQUIRE`/`KJ_FAIL_REQUIRE`/`KJ_REQUIRE_NONNULL`
(`jsg/exception.h`) -- ninguna dependencia de V8, se copió el header tal
cual.

## Revisión manual

No se hizo una revisión línea por línea exhaustiva antes de fuzzear esta
vez (a diferencia de `mimetype`/`fabric-config`) -- se fue directo a
fuzzing dado el tiempo ya invertido en la sesión, confiando en el
fuzzing real + ASan para la cobertura de bugs de memoria. Sí se notó al
extraer el código que el manejo de índices (`match[0].second -
rawText.begin()`, `message.size() - (message.back() == '\r')`) depende
de que `std::regex_search`/`splitAtSubString` devuelvan posiciones
consistentes con el buffer real -- superficie exactamente del tipo que
un fuzzer cubre mejor que una lectura manual.

## Resultado

- Smoke test: 30s, 365,498 ejecuciones (más lento que targets previos --
  regex + parsing con más allocations -- pero limpio).
- Campaña completa: `-fork=18`, 2400s (40 min), **~255 millones de
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable. Cobertura
  (`cov`/`ft`) estancada en 3734/3899 bastante antes del final -- corpus
  saturado.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio. No se reporta nada a Cloudflare. El patch de `kj-http`+`kj-async`
standalone (además del `kj` base ya armado) queda reusable para
cualquier otro target de `workerd` que use headers/HTTP real sin
necesitar V8 (ej. partes de `headers.c++` si en algún momento se separa
su lógica de parseo pura de la clase `jsg::Object`).
