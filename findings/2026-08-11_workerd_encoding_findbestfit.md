# workerd — `findBestFit` (api/encoding.c++) — resultado limpio (fuzzing de propiedad)

**Programa:** Cloudflare (HackerOne `hackerone.com/cloudflare`, `automated_scanning: allowed`)
**Repo:** `cloudflare/workerd` (Tier 1, C++, no cubierto por OSS-Fuzz)
**Target:** `findBestFit<Char>(const Char*, size_t length, size_t bufferSize)` en `src/workerd/api/encoding.c++`

## Por qué este target, y por qué es distinto a los anteriores

`TextEncoder`/`TextDecoder` en sí (`encoding.h`) tocan `jsg::Lock`/V8
directamente en cada método público -- no hay forma de extraerlos sin
fakear una parte real de la lógica (a diferencia de `parseFormDataImpl`,
que era standalone de verdad). Pero adentro de `TextEncoder::encodeInto`
hay una función pura, sin V8 ni ICU: `findBestFit`, que calcula cuántas
unidades UTF-16 (o Latin1) de entrada entran, convertidas a UTF-8, en un
buffer de salida de tamaño fijo -- usa un algoritmo adaptativo por
chunks con un factor de expansión estimado (heurística real, con
división de punto flotante y ajuste iterativo).

`findBestFit` en sí **nunca escribe a ningún buffer** (solo devuelve un
`size_t`), así que fuzzearla buscando crashes directos no tiene sentido
-- no puede crashear sola. El bug real que importa es si **miente**
sobre cuánto entra: el caller real (`TextEncoder::encodeInto`, línea
~742/751 del original) usa ese valor para acotar cuántos bytes escribe
a un buffer real (`outputBuf`) sin volver a chequear. Si `findBestFit`
sobreestima, el caller desborda el buffer de verdad.

Por eso este harness es de **fuzzing de propiedad**, no de crash: para
cada input genera `(bufferSize, data)`, llama `findBestFit`, y verifica
con la misma librería que confía el código real (`simdutf`) que el
resultado nunca miente:

```
real_utf8_len = simdutf::utf8_length_from_utf16_with_replacement(data, pos)  // o _from_latin1
assert(real_utf8_len <= bufferSize)   // el invariante de seguridad real
assert(pos <= length)                  // nunca "usa" mas datos de los que hay
```

Usando `abort()` explícito en vez de `assert()` (para no depender de
`NDEBUG`/flags de build) -- si el invariante se rompe, libFuzzer lo
agarra como crash real y guarda el input que lo disparó.

## Setup

Función extraída tal cual (junto a sus dos helpers, `isSurrogatePair` y
`simpleUtfEncodingLength`) a un header standalone
(`find_best_fit.h`) -- único cambio: `kj::min`/`kj::max` reemplazados
por `std::min`/`std::max` (semánticamente idénticos, verificado contra
la implementación real de `kj::min`/`kj::max` en `kj/common.h`:
`a < b ? a : b`/`a > b ? a : b`) para no necesitar linkear `libkj` en
absoluto para este target -- el más liviano de infraestructura de toda
la sesión (solo `simdutf`, vendoreada de sesiones anteriores).

## Resultado

- Smoke test: 30s, 4,982,445 ejecuciones (mucho más rápido que los
  targets anteriores -- pura aritmética, sin allocations pesadas ni
  I/O).
- Campaña completa: `-fork=18`, 2400s (40 min), **4,026,808,207
  ejecuciones reales** (el target con más ejecuciones de toda la
  sesión), `oom/timeout/crash: 0/0/0` estable. Cobertura estancada en
  797/652 bastante antes del final.
- Cero violaciones del invariante de capacidad, en las dos variantes
  (UTF-16 y Latin1).

## Conclusión honesta

El algoritmo de estimación adaptativa de `findBestFit` es correcto con
alta confianza (4 mil millones de casos, incluyendo bufferSize=0,
bufferSize pequeño con datos grandes -- el caso más peligroso -- y
surrogate pairs deliberadamente cortados en el límite del chunk). No se
reporta nada a Cloudflare.
