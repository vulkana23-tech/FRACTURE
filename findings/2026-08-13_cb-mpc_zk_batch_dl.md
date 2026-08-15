# cb-mpc — coinbase::zk::uc_batch_dl_t (prueba ZK-DL en batch) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz), repo
específico en scope. Quinto target de esta sesión dentro de `cb-mpc`, y
tercero dentro de `zk/`.

## Por qué este target

`uc_batch_dl_finite_difference_impl_t` (alias `uc_batch_dl_t`, mismo
archivo `zk_ec.cpp` que `uc_dl_t`) es la variante batch de la prueba
ZK-DL: en vez de probar conocimiento de un solo discrete-log, prueba
conocimiento de varios a la vez (`std::vector<ecc_point_t> Q`) con una
única prueba más compacta -- usa un polinomio de Horner
(`horner_poly_small_vartime`) sobre los puntos en vez de la suma
lineal simple de `uc_dl_t`. El código ya estaba compilado como parte de
`obj/zk_zk_ec.o` (mismo archivo fuente que `uc_dl_t`, target anterior
de esta sesión) -- solo faltaba un harness dedicado, el target más
barato de infraestructura de todo `cb-mpc` hasta ahora.

## Revisión manual (antes de fuzzear)

- `verify()` calcula `b_minus_log2n = params.b - int_log2(n)` (con
  `n = Q.size()`, fijo en el harness) y lo valida vía
  `check_with_effective_b()` antes de tocar cualquier vector -- mismo
  patrón defensivo que `uc_dl_t`. `R`/`e`/`z` (atacante-controlados)
  quedan acotados por `MAX_CONTAINER_ELEMENTS` en la deserialización, y
  el propio `verify()` rechaza si no calzan con `rho`. Sin bug
  encontrado a mano.

## Setup

Cero compilación nueva de fuente -- `zk_zk_ec.o` ya estaba compilado
para el target `uc_dl_t`. Solo harness nuevo (`fuzz_zk_batch_dl.cpp`):
deserializa `uc_batch_dl_t` (`params`, `R[]`, `e[]`, `z[]`) vía
`converter_t` y llama `verify()` real contra un vector `Q` fijo de 4
puntos válidos de secp256k1 (`{1,2,3,4} * G`, no fuzzeados).

## Resultado

- Smoke test: 30s, 2,258,938 ejecuciones, cov 481, limpio.
- Campaña completa: `-fork=18`, 2400s (40 min), **306,094,393
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura estable en 1869/2118 (corpus final: 268-270 casos)
  bastante antes del final.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza -- el deserializador y la variante batch de
la aritmética ZK-DL (polinomio de Horner sobre puntos EC en vez de suma
lineal) resistieron más de 300 millones de ejecuciones reales sin
corrupción de memoria. No se reporta nada a Coinbase.

## Qué queda sin cubrir

- Lo que depende de una clave Paillier real
  (`valid_paillier_t`/`paillier_zero_t`/`two_paillier_equal_t`/`pdl_t`/
  `paillier_pedersen_equal_t`).
- `range_pedersen_t` (arrays de tamaño fijo, no revisado en detalle).
- `unknown_order_dl_t` (necesita un módulo RSA-like coherente con
  `a`,`b`).
- `fischlin.cpp::prove()` (no fuzzeado, solo la validación en
  `verify()`).
- El protocolo MPC real (ECDSA-2PC/MPC, key gen/refresh) y la capa
  `c_api` -- con esto se cierra por ahora `zk/` como superficie
  "barata" (sin clave externa); lo que queda requiere generación de
  claves o setup más elaborado.
