# cb-mpc — coinbase::zk::uc_dl_t (prueba ZK de discrete-log, Fischlin) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz), repo
específico en scope. Tercer target de esta sesión dentro de `cb-mpc`,
después de `converter_t` y `ec_pve_t`.

## Por qué este target

`uc_dl_t` (`include-internal/cbmpc/internal/zk/zk_ec.h` +
`src/cbmpc/zk/zk_ec.cpp`) es una prueba zero-knowledge "UC-ZK-DL"
(discrete log, esquema Fischlin) -- la estructura (`params`, `A[]`,
`e[]`, `z[]`) es exactamente el tipo de objeto que un peer no confiable
del protocolo MPC manda para probar conocimiento de un secreto sin
revelarlo. A diferencia de `ec_pve_t` (solo `convert()`), acá
`verify()` sí es alcanzable con datos completamente construidos a mano
en el harness (solo requiere un punto `Q` válido fijo, no un
curve/keyref completo como PVE) -- permite fuzzear la superficie
completa: deserialización + aritmética real de curva elíptica
(`sum_mul`, comparación de puntos, hash Fischlin) en un solo harness.

## Revisión manual (antes de fuzzear)

- `fischlin_params_t::convert` solo serializa `rho` y `b` (no `t`) --
  confirmado en el header con el comentario explícito `// t is not
  sent`. `t` queda en su valor default-construido (9), así que
  `e_max() = 1<<t` nunca es atacante-controlado directamente, acotando
  ese vector de ataque.
- `params.check()` exige `rho>0`, `0<b<31`, `b*rho >= SEC_P_COM` antes
  de tocar ningún vector -- no pone techo a `rho`, pero `A`/`e`/`z` ya
  vienen acotados por `MAX_CONTAINER_ELEMENTS` (1<<20) desde
  `converter_t::convert(vector<T>&)`, y el propio `verify()` rechaza
  con `A.size() != rho` si no calzan exactamente. Sin bug encontrado a
  mano.

## Setup

Reutiliza el 100% de la infra ya construida para `ec_pve_t` en esta
misma sesión (OpenSSL 3.6.3 compilado desde fuente, secp256k1
vendorizado, los 25 objetos de `core/`+`crypto/`). Solo se agregaron y
compilaron 2 archivos nuevos: `zk/fischlin.cpp` y `zk/zk_ec.cpp`,
limpios a la primera (solo warnings benignos ya vistos toda la sesión).

Harness (`fuzz_zk_ec.cpp`): deserializa `uc_dl_t` desde los bytes del
fuzzer vía `converter_t`, y llama `verify()` real contra un `Q` fijo y
válido (`1 * G` sobre secp256k1, no fuzzeado -- sin esto `verify()`
nunca pasa de `curve.check(Q)`).

## Resultado

- Smoke test: 30s, 1,829,428 ejecuciones, cov 325, limpio. Errores
  esperados observados (`b >= 31`, `Curve not found`, `Converter
  error`, `secp256k1_eckey_pubkey_parse failed`) -- confirman
  validación real tanto de los parámetros Fischlin como de cada punto
  `A[i]` deserializado (cada uno lleva su propio id de curva en los
  bytes).
- Campaña completa: `-fork=18`, 2400s (40 min), **309,620,794
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura estable en 1423/2107 (corpus final: 260-282 casos)
  bastante antes del final.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza -- tanto el deserializador como la
aritmética de curva elíptica de `verify()` resistieron más de 300
millones de ejecuciones reales, incluyendo la ruta más profunda
fuzzeada hasta ahora en `cb-mpc` (deserialización + verificación
criptográfica real, no solo parseo). No se reporta nada a Coinbase.

## Qué queda sin cubrir

- El resto de `zk/`: `uc_batch_dl_finite_difference_impl_t` (batch DL,
  mismo archivo), `zk_elgamal_com.cpp`, `zk_paillier.cpp`,
  `zk_pedersen.cpp`, `zk_unknown_order.cpp`, `fischlin.cpp::prove()`
  (no fuzzeado, solo la validación en verify()) -- candidatos directos
  para una próxima sesión, con la misma infra ya lista.
- `verify()`/`decrypt()` de `ec_pve_t` (necesitan curve/keyref real).
- El protocolo MPC real (ECDSA-2PC/MPC, key gen/refresh) y la capa
  `c_api`.
