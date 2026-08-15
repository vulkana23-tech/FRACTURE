# cb-mpc — coinbase::converter_t (deserializador de mensajes MPC) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz -- confirmado 404
en `google/oss-fuzz`), repo especifico en scope (no wildcard), elegible
para bounty. Descubierto vía búsqueda directa en HackerOne (no vía el
feed público de GitHub que usa `discovery.py`), ver también findings
de la sesión de SPECTRE del mismo día.

## Por qué este target

`converter_t` (`include-internal/cbmpc/internal/core/convert.h` +
`src/cbmpc/core/convert.cpp`) es el (de)serializador binario usado para
mensajes del protocolo MPC. El propio código documenta explícitamente
el modelo de amenaza en un comentario: `MAX_CONVERT_LEN`/
`MAX_CONTAINER_ELEMENTS` existen para "protect against
attacker-controlled allocations and loops if a malicious peer supplies
an oversized length prefix" -- confirma que el propio equipo considera
esto superficie de entrada no confiable (un peer malicioso en el
protocolo MPC).

## Revisión manual (antes de fuzzear)

- `convert(std::string&)`: el length-prefix se lee como `short`
  (16 bits con signo). Un atacante que mande `0x8000`-`0xFFFF` haría
  que ese valor se reinterprete como negativo -- pero el código
  explícitamente chequea `value_size < 0` inmediatamente después de
  leerlo y aborta, así que ese caso está cubierto. `at_least(value_size)`
  (chequeo de bytes restantes) usa resta en vez de suma, evitando
  overflow.
- `convert_len`: decoder variable-length de 1 a 4 bytes (estilo
  UTF-8/varint, prefijo de bits indica cuántos bytes siguen). Cada una
  de las 4 ramas chequea `len > MAX_CONVERT_LEN` al final y usa
  `is_error()` para descartar el resultado si algún byte intermedio
  falló -- el valor de `len` queda forzado a `0` en cualquier camino
  de error, así que un byte "viejo" reusado tras un error de lectura
  nunca se expone.
- Sin bug encontrado a mano en ninguno de los dos.

## Setup

`core/` (buf.h/.cpp, convert.h/.cpp, error.h/.cpp, strext.h/.cpp,
buf128/256) resultó completamente autocontenido -- sin dependencia de
OpenSSL ni de ninguna otra librería externa a este nivel, solo headers
estándar de Linux. Compiló limpio a la primera con
`clang++ -fsanitize=address,fuzzer`, sin necesidad de vendorear nada
(a diferencia de casi todos los targets anteriores de la sesión).

Harness (`fuzz_converter.cpp`): construye un `converter_t` desde los
bytes del fuzzer y encadena varios `convert()` reales sobre el mismo
stream (enteros de ancho fijo, string con length-prefix,
`vector<bool>`, bool) más una corrida aislada de `convert_len` --
mismo patrón de invocación que tendría un mensaje MPC real con varios
campos.

## Resultado

- Smoke test: 30s, 2,516,042 ejecuciones, limpio.
- Campaña completa: `-fork=18`, 2400s (40 min), **3,307,716,158
  ejecuciones reales** (segundo target con más volumen de la sesión,
  detrás de `findBestFit`), `oom/timeout/crash: 0/0/0` estable en toda
  la corrida. Cobertura estable en 395/305 bastante antes del final.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza -- el deserializador base del protocolo MPC
resistió tanto la lectura de código como más de 3 mil millones de
ejecuciones reales. No se reporta nada a Coinbase. Quedan sin tocar:
el resto de `cb-mpc` (protocolo real de MPC en `src/cbmpc/protocol/`,
zero-knowledge proofs en `src/cbmpc/zk/`, la capa `c_api` -- todos
candidatos reales para una próxima sesión, con más superficie
criptográfica específica que la capa base de serialización ya cubierta
acá).
