# cb-mpc — coinbase::zk::range_pedersen_t (prueba de rango sobre commitment de Pedersen) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz), repo
específico en scope. Octavo target de esta sesión dentro de `cb-mpc`.

## Por qué este target

`range_pedersen_t` (`src/cbmpc/zk/zk_pedersen.cpp`) prueba que el valor
commiteado en un commitment de Pedersen está dentro de un rango `[0,q)`
sin revelarlo -- usado junto a Paillier en varias partes del protocolo
(ej. `pdl_t`, no cubierto todavía). Deserializable desde bytes de un
peer no confiable (`convert(e, d, f, c_tilde)`, con `d`/`f`/`c_tilde`
como arrays de tamaño fijo `bn_t[SEC_P_COM]`, un patrón de
deserialización distinto a los `std::vector` de targets anteriores),
con `verify()` alcanzable usando los parámetros de grupo Pedersen fijos
que expone el propio código como singleton
(`pedersen_commitment_params_t::get()`).

## Setup (el más barato de esta sub-serie de Paillier/Pedersen)

`zk_zk_pedersen.o` ya estaba compilado como dependencia de link del
target anterior (`zk_paillier.cpp` necesita `range_pedersen_t::verify()`
vía `pdl_t`) -- cero compilación nueva de fuente. El único setup nuevo
fue un commitment `c = h^r mod p` fijo y válido (commitment a `0` con
aleatoriedad `r`), usando los campos `g`/`h`/`p`/`p_tag` del singleton
de parámetros -- no requirió generar ninguna clave nueva (a diferencia
de los 2 targets Paillier anteriores).

## Resultado

- Smoke test: 30s, 14,662 ejecuciones, cov 171, limpio. Errores
  esperados observados (`Converter error`, y errores sin mensaje
  consistentes con fallos de `check_safe_prime_subgroup`/rangos sobre
  los `t=128` elementos deserializados).
- Campaña completa: `-fork=18`, 2400s (40 min), **17,573,394
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura estable en 688/550 (corpus final: 83-96 casos).
  Throughput bajo (~430-450 exec/s) -- coherente con `t=128`
  operaciones de exponenciación modular real sobre el grupo Pedersen
  (primo seguro grande) por cada `verify()`.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio. Volumen menor que los targets EC (esperado, dado el costo por
ejecución), pero mayor que `two_paillier_equal_t` (single-key vs.
double-key, y el grupo Pedersen es más liviano que Paillier de 2048
bits) -- confianza razonable de que el manejo de los arrays de tamaño
fijo (`d[128]`, `f[128]`, `c_tilde[128]`) deserializados desde bytes
arbitrarios no tiene bugs de memoria explotables. No se reporta nada a
Coinbase.

## Qué queda sin cubrir

- `range_pedersen_interactive_t` (variante interactiva del mismo
  archivo).
- `paillier_pedersen_equal_t`, `pdl_t`, `paillier_range_exp_slack_t`
  (combinan Paillier + Pedersen, requieren ambos setups a la vez).
- `valid_paillier_interactive_t`, `two_paillier_equal_interactive_t`
  (variantes interactivas de Paillier).
- `unknown_order_dl_t` (necesita un módulo RSA-like coherente con
  `a`,`b` -- último target "caro" de `zk/` sin tocar).
- `fischlin.cpp::prove()` (nunca fuzzeado, solo la validación en los
  `verify()`), el protocolo MPC real (ECDSA-2PC/MPC, key gen/refresh) y
  la capa `c_api`.
