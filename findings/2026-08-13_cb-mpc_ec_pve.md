# cb-mpc — coinbase::mpc::ec_pve_t (deserializador de ciphertext PVE) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz -- confirmado 404
en `google/oss-fuzz`), repo específico en scope, elegible para bounty.
Segundo target de esta sesión dentro de `cb-mpc`, después de
`converter_t` (ver `2026-08-13_cb-mpc_converter.md`).

## Por qué este target

`ec_pve_t` (`include-internal/cbmpc/internal/protocol/pve.h` +
`src/cbmpc/protocol/pve.cpp`/`pve_base.cpp`) es el deserializador de un
ciphertext de Publicly Verifiable Encryption -- la estructura que
contiene, entre otros campos, un punto de curva elíptica (`ecc_point_t
Q`), un buffer de label y arrays de `bn_t`/`buf128_t`/`buf_t`. Superficie
de entrada no confiable real y distinta de `converter_t`: un ciphertext
PVE típicamente viaja por storage/backup, exactamente el escenario donde
un atacante podría alterar los bytes antes de que se deserialicen para
un intento de recovery -- a diferencia de `converter_t` (mensajes
peer-to-peer del protocolo), acá el input hostil llega desde disco/backup,
no de la red.

## Setup (la parte cara de este target)

A diferencia de `converter_t` (autocontenido, sin dependencias), `pve.cpp`
arrastra la pila criptográfica completa de `cb-mpc`:

- **OpenSSL 3.6.3 desde fuente**: `base_bn.h` tiene un
  `#error "cb-mpc copied OpenSSL BN internals require OpenSSL 3.6.3"` --
  el código accede directo al layout interno de `bignum_st` (ABI-fragile,
  atado a una versión exacta). El sistema solo tenía 3.0.13 y 3.6.3 no
  está en los repos de Ubuntu. Se clonó el tag `openssl-3.6.3` upstream y
  se compiló/instaló en un prefix propio (`Configure --prefix=...
  no-shared no-tests`, `make -j18`, `make install_dev`).
- **secp256k1 vendorizado**: se copió el árbol fuente completo de
  `vendors/secp256k1` y se usó vía `-I` (include path), sin build
  separado -- `base_ecc_secp256k1.cpp` incluye directamente archivos
  internos (`precomputed_ecmult.c`, `*_impl.h`).
- **27 archivos fuente compilados** (6 `core/` + 19 `crypto/` + 2
  `protocol/`: `pve.cpp`, `pve_base.cpp`), todos limpios con solo
  warnings benignos (`-Wparentheses` sobre el patrón
  `if (x = f())` usado a propósito en el código real).

Harness (`fuzz_pve.cpp`): construye un `converter_t` desde los bytes del
fuzzer y llama `ec_pve_t::convert(c)` directo -- no importa si la
deserialización "tuvo éxito" lógico (`c.is_error()`), lo que importa es
que nunca corrompa memoria al intentarlo. No se llama `verify()`/
`decrypt()` (necesitarían un curve/keyref real construido aparte) -- ver
"Qué queda sin cubrir" abajo.

## Resultado

- Smoke test: 30s, 594,330 ejecuciones, cov 480, limpio. Errores
  esperados y correctos observados en stderr (`Converter error`,
  `Curve not found`, `EC-point is not on curve`) -- confirman que el
  parser SÍ está validando la curva/el punto contra bytes arbitrarios,
  no solo aceptando cualquier cosa silenciosamente.
- Campaña completa: `-fork=18`, 2400s (40 min), **590,936,751
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura se estabilizó en 1226/914 bastante antes del final
  (corpus final: 144 casos), sin crecimiento de cobertura en el último
  tercio de la corrida.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza -- el deserializador de ciphertext PVE
resistió tanto la lectura de código como más de 590 millones de
ejecuciones reales, incluyendo la reconstrucción de puntos de curva
elíptica arbitrarios (la parte más propensa a corrupción de memoria de
este parser). No se reporta nada a Coinbase.

## Qué queda sin cubrir

- `verify()`/`decrypt()` de `ec_pve_t` -- necesitan un `curve`/`keyref`
  real construido por fuera del harness, no solo bytes deserializados;
  candidato para un harness más elaborado en una próxima sesión.
- El resto del protocolo MPC real en `src/cbmpc/protocol/` (ECDSA-2PC,
  ECDSA-MPC, key generation/refresh) y las zero-knowledge proofs en
  `src/cbmpc/zk/` -- ambos con más superficie criptográfica específica
  que las dos capas de (de)serialización ya cubiertas (`converter_t` +
  `ec_pve_t`) entre `converter_t` y este target.
- La capa `c_api` (bindings C de cara a lenguajes externos).
