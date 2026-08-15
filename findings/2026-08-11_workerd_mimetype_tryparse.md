# workerd — `MimeType::tryParse` (util/mimetype.c++) — resultado limpio

**Programa:** Cloudflare (HackerOne `hackerone.com/cloudflare`, `automated_scanning: allowed`)
**Repo:** `hyperledger/../` no aplica — `cloudflare/workerd` (Tier 1, C++, no cubierto por OSS-Fuzz al momento de la selección)
**Target:** `workerd::MimeType::tryParse(kj::ArrayPtr<const char>, ParseOptions)` en `src/workerd/util/mimetype.c++`

## Por qué este target

Parsea el valor crudo de un header `Content-Type`/`Accept` (o el prefijo de
una `data:` URL) — superficie directamente alcanzable desde una request
HTTP no confiable que llega a cualquier Worker. Parser manual
carácter-por-carácter con escritura de buffer a mano (`*out++`) para el
manejo de strings entre comillas con escapes — el tipo de código donde
suelen aparecer overflows.

## Revisión manual (antes de fuzzear)

Se hizo la cuenta exacta de peor caso del loop de parseo de quoted-string
(líneas ~176-212 de `mimetype.c++`): el buffer de salida se aloca con
`input.size()` bytes, y cada iteración consume al menos tantos bytes de
`input` como escribe a `out` (el caso de escape `\x` consume 2 bytes y
escribe 1; nunca al revés). No es posible que `out` avance más que
`input.size()` — no hay overflow posible por construcción. Resto del
parser: todos los accesos por índice (`input[n]`, `res[0..5]`) están
detrás de un chequeo de `size()`/`findFirst`/`findLast` previo. Sin bug
encontrado a mano.

## Setup de fuzzing (nota de infraestructura)

`workerd` no tiene nada compilable aislado (todo pasa por Bazel + V8
completo). Se armó un build standalone para este target específico:

- Se compiló `libkj` (la librería base de Cap'n Proto de la que depende
  todo `workerd`) fuera de Bazel, vía su CMake propio
  (`build/deps/capnproto/c++/build_kj`), con
  `-fsanitize=address,fuzzer-no-link`. Requirió instalar `cmake` y
  `g++-14`/`libstdc++-14-dev` (Cap'n Proto pide C++23 real, `<print>`
  no está en libstdc++-13).
- Se copiaron `mimetype.h/.c++`, `strings.h/.c++`, `string-buffer.h` a
  `build/fuzz_workerd_mimetype/` y se saco la unica dependencia
  problematica: `mimetype.h` incluia `<workerd/jsg/memory.h>` (arrastra
  `<v8-profiler.h>`, o sea V8 completo) solo para el metodo
  `visitForMemoryInfo` (tracking de heap snapshots de V8, sin relacion
  con el parseo). Se reemplazo por un forward-declare de
  `jsg::MemoryTracker` y se dejo `visitForMemoryInfo` declarado sin
  cuerpo (nunca se llama desde el harness) -- la logica de parseo real
  de `tryParse` no se toco.
- Harness (`fuzz_mimetype.c++`): llama `MimeType::tryParse` directo con
  los bytes de fuzzing, y si parsea OK tambien ejercita `toString()`
  (mismos buffers, path de vuelta).
- Compilado con `clang++ -std=c++23 -fsanitize=address,fuzzer` contra
  `libkj.a`, sin errores en el primer intento.

## Resultado

- Smoke test: 30s, 1,503,777 ejecuciones, limpio.
- Campaña completa: `-fork=18`, 2400s (40 min), **929,582,000
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura (`cov`/`ft`) estancada en 1819/1632 bastante antes
  del final -- corpus saturado, no hace falta correr mas tiempo sobre
  este mismo target.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza (revisión manual + casi mil millones de
ejecuciones reales con ASan). No se reporta nada a Cloudflare. El
harness/build de `libkj` standalone queda reusable en
`build/deps/capnproto/c++/build_kj/` y `build/fuzz_workerd_mimetype/`
para el próximo target de `workerd` que no necesite V8/simdutf (ej.
otras funciones de parsing puro en `src/workerd/util/`).
