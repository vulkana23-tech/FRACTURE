# cb-mpc — coinbase::zk::two_paillier_equal_t (igualdad de plaintext entre 2 claves Paillier) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz), repo
específico en scope. Séptimo target de esta sesión dentro de `cb-mpc`.

## Por qué este target

`two_paillier_equal_t` prueba que dos ciphertexts, cifrados bajo **dos
claves Paillier distintas** (`P0`, `P1`), contienen el mismo plaintext
-- sin revelarlo. Es el tipo de prueba que aparece en el resharing/
key-refresh del protocolo MPC (mover un secreto de una clave Paillier a
otra manteniendo el valor). Deserializable desde bytes de un peer no
confiable (`convert(e, d, r0_hat, r1_hat)`), con `verify()` alcanzable
generando 2 claves fijas en el harness.

## Detalle no obvio de la API (relevante para el diseño del harness)

`verify()` empieza con varios chequeos `if (p0_valid_key ==
zk_flag::unverified) return E_CRYPTO;` sobre campos (`p0_valid_key`,
`p1_valid_key`, `c0_plaintext_range`) que **no son parte de
`convert()`** -- por diseño de la API, el caller real debe validar cada
clave por separado (vía `valid_paillier_t::verify()`, el target
anterior de esta sesión) y setear estos flags manualmente antes de
llamar `verify()` acá. El harness los marca `verified` explícitamente,
igual que haría un caller real que ya corrió esa validación aparte --
no es un bypass de seguridad, es el flujo de uso documentado por el
propio código.

## Setup

Segundo target de la sesión con claves criptográficas reales generadas
en el harness, y el primero con **dos** (`P0`, `P1`, ambas 2048 bits,
generadas una sola vez de forma estática por proceso fuzzeado). `q`
(el módulo del rango del plaintext compartido) se fijó al orden de
`curve_secp256k1` (256 bits, muy por debajo del límite de 2048 bits que
exige `verify()`). `c0`/`c1` son ciphertexts fijos de `0` bajo cada
clave, con aleatoriedad de cifrado muestreada vía
`paillier_t::rand_N_star(resample_until_coprime=true)`. Cero
compilación nueva de fuente -- reutiliza `zk_zk_paillier.o` del target
anterior.

## Resultado

- Smoke test: 30s (+ ~1s de overhead por 2 keygens de 2048 bits al
  arranque), 9,927 ejecuciones, cov 158, limpio. Throughput bajo
  (~320 exec/s) -- esperado: cada `verify()` hace exponenciación modular
  real contra **dos** módulos de 2048 bits (`param::t` veces cada uno).
- Campaña completa: `-fork=18`, 2400s (40 min), **6,104,082
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura estable en 953/991 (corpus final: 88-99 casos)
  bastante antes del final -- el menor volumen de ejecuciones de todo
  `cb-mpc` en esta sesión, coherente con ser el harness más caro por
  ejecución (doble exponenciación modular de 2048 bits).
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio. El volumen absoluto (6.1M) es bajo comparado con el resto de
`cb-mpc` en esta sesión, pero sigue siendo un volumen sustancial para
un target con este costo computacional por ejecución, y la cobertura
se estabilizó bien antes de agotar el tiempo -- confianza razonable, no
tan alta como en los targets EC (cientos de millones de ejecuciones).
No se reporta nada a Coinbase.

## Qué queda sin cubrir

- `two_paillier_equal_interactive_t` (variante interactiva).
- `pdl_t`, `paillier_range_exp_slack_t`, `paillier_pedersen_equal_t`
  (combinan Paillier + Pedersen, más setup todavía).
- `valid_paillier_interactive_t`, `range_pedersen_t` (ya compilado,
  sin harness dedicado), `unknown_order_dl_t`.
- El protocolo MPC real (ECDSA-2PC/MPC, key gen/refresh) y la capa
  `c_api`.
