# cb-mpc — coinbase::zk::unknown_order_dl_t (ZK-DL sobre grupo de orden desconocido) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz), repo
específico en scope. Noveno target de esta sesión dentro de `cb-mpc`, y
el último de la serie "barata" (sin generar clave nueva ni combinar
Paillier+Pedersen) dentro de `zk/`.

## Por qué este target

`unknown_order_dl_t` (`src/cbmpc/zk/zk_unknown_order.cpp`) prueba
conocimiento de un discrete-log sobre un grupo de orden desconocido
(tipo RSA) -- usada en partes del protocolo que combinan Paillier con
pruebas de rango. Deserializable desde bytes de un peer no confiable
(`convert(e, z)`, con `z` como array de tamaño fijo `bn_t[SEC_P_COM]`,
mismo patrón que `range_pedersen_t`), con `verify()` alcanzable
reutilizando la clave Paillier ya generada en un target anterior como
fuente de un `N` compuesto real de 2048 bits (sin necesitar generar
nada nuevo).

## Revisión manual (antes de fuzzear)

- `verify()` acota `z[i]` explícitamente: rechaza `z[i] < 0` y
  `z[i].get_bits_count() > max_z_bits` (con `max_z_bits = l +
  SEC_P_STAT + 2`, `l` fijo en 256 en el harness) -- ningún exponente
  atacante-controlado puede crecer sin límite antes de entrar a
  `a.pow(z[i])` mod N. `e.size()` se valida contra
  `bits_to_bytes(SEC_P_COM)` exacto antes de usarse. Sin bug encontrado
  a mano.

## Setup

Cero generación de clave nueva -- reutiliza `fixed_paillier().get_N()`
(la clave de 2048 bits ya generada para el target `zk_paillier`/
`two_paillier_equal`) como el módulo `N` de orden desconocido, con
`a=2`, `b=3` fijos (coprimos a cualquier `N` RSA real con probabilidad
abrumadora). Un solo archivo nuevo compilado (`zk_unknown_order.cpp`),
limpio a la primera.

## Resultado

- Smoke test: 30s, 52,763 ejecuciones, cov 218, limpio. Errores
  esperados observados (`invalid e size`, `z[i] < 0`, `Converter
  error`), confirmando que las cotas explícitas del código sí bloquean
  bytes arbitrarios antes de la aritmética modular.
- Campaña completa: `-fork=18`, 2400s (40 min), **26,224,159
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura estable en 1150/846 (corpus final: 114-122 casos)
  bastante antes del final.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con confianza razonable -- las cotas explícitas sobre `z[i]` y
`e.size()` resistieron 26 millones de ejecuciones reales de
exponenciación modular sobre un módulo real de 2048 bits, sin
corrupción de memoria. No se reporta nada a Coinbase.

## Cierre de la serie "barata" de zk/ en esta sesión

Con este target se completan 6 harnesses dentro de `src/cbmpc/zk/`
(`uc_dl_t`, `uc_batch_dl_t`, 4 structs de `zk_elgamal_com.cpp`,
`valid_paillier_t`+`paillier_zero_t`, `two_paillier_equal_t`,
`range_pedersen_t`, `unknown_order_dl_t`), todos limpios, sumando más
de 1.7 mil millones de ejecuciones reales solo en `zk/` +
`protocol/pve*.cpp` + `core/convert.cpp` en esta sesión. Lo que queda
en `cb-mpc` requiere un salto de complejidad real:

- Variantes interactivas (`valid_paillier_interactive_t`,
  `two_paillier_equal_interactive_t`, `range_pedersen_interactive_t`) --
  requieren simular el intercambio challenge/response completo, no solo
  deserializar un mensaje final.
- Combinaciones Paillier+Pedersen (`pdl_t`,
  `paillier_pedersen_equal_t`, `paillier_range_exp_slack_t`) --
  requieren ambos setups a la vez más coherencia entre los parámetros.
- `verify()`/`decrypt()` de `ec_pve_t` (necesita curve/keyref real).
- El protocolo MPC real (`ecdsa_2p.cpp`, `ecdsa_mp.cpp`, `ec_dkg.cpp`,
  `schnorr_2p.cpp`, `schnorr_mp.cpp`) -- mensajes reales entre partes
  del protocolo, superficie distinta a deserialización de pruebas ZK
  aisladas.
- La capa `c_api`.
