# cb-mpc — coinbase::zk::zk_elgamal_com.cpp (4 pruebas ZK sobre EC-ElGamal commitments) — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz), repo
específico en scope. Cuarto target de esta sesión dentro de `cb-mpc`, y
segundo dentro de `zk/` (después de `uc_dl_t` en `zk_ec.cpp`).

## Por qué este target

`src/cbmpc/zk/zk_elgamal_com.cpp` define 4 pruebas ZK distintas sobre
EC-ElGamal commitments (`elg_com_t` = par de puntos `L,R`) -- la
primitiva base para compartir secretos de forma verificable en el
protocolo MPC de `cb-mpc`. Las 4 son deserializables desde bytes de un
peer no confiable (todas implementan `convert(converter_t&)`) y las 4
tienen `verify()` alcanzable sin necesitar una clave Paillier real (a
diferencia de `zk_paillier.cpp`/`zk_pedersen.cpp`, que sí la necesitan
-- quedan fuera de esta ronda):

- `uc_elgamal_com_t` -- prueba UC de conocimiento del valor commiteado.
- `elgamal_com_pub_share_equ_t` -- envuelve un `dh_t` (prueba DH ya
  usada en `zk_ec.cpp`), prueba que un share público corresponde al
  commitment.
- `elgamal_com_mult_t` -- prueba de multiplicación homomórfica entre 3
  commitments.
- `uc_elgamal_com_mult_private_scalar_t` -- variante UC de la misma
  idea con un escalar privado.

## Setup

Reutiliza el 100% de la infra de los 3 targets anteriores en `cb-mpc`
de esta sesión (OpenSSL 3.6.3, secp256k1 vendorizado, `core/`+`crypto/`
ya compilados, `zk_fischlin.o`+`zk_zk_ec.o` de `uc_dl_t`). Solo un
archivo nuevo, `zk_elgamal_com.cpp`, compilado limpio a la primera.

Harness (`fuzz_zk_elgamal_com.cpp`): las 4 structs se deserializan
desde 4 vistas independientes de los MISMOS bytes fuzzeados (mismo
patrón de encadenamiento que `fuzz_converter.cpp`), cada una seguida de
su `verify()` real contra puntos/commitments fijos y válidos
construidos una sola vez (`Q = 1*G`, `A = 2*G`, y 4 commitments vía
`ec_elgamal_commitment_t::make_commitment`) -- maximiza cobertura por
ejecución sin necesitar generación de claves externas.

## Resultado

- Smoke test: 30s, 116,175 ejecuciones (más lento que targets previos
  por las 4 verificaciones EC reales encadenadas por input, esperado),
  cov 603, limpio.
- Campaña completa: `-fork=18`, 2400s (40 min), **87,733,497
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura estable en 2661/3264 (corpus final: 515-558
  casos), el mayor conteo de cobertura de todos los targets de
  `cb-mpc` en esta sesión -- consistente con ser el harness que cubre
  más código distinto (4 structs en un solo binario).
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza -- las 4 rutas de deserialización + la
aritmética EC real de sus respectivos `verify()` resistieron casi 88
millones de ejecuciones reales sin ninguna corrupción de memoria. No se
reporta nada a Coinbase.

## Qué queda sin cubrir

- `zk_paillier.cpp` y las partes de `zk_pedersen.cpp` que dependen de
  una clave Paillier real (`valid_paillier_t`, `paillier_zero_t`,
  `two_paillier_equal_t`, `pdl_t`, `paillier_pedersen_equal_t`) --
  requieren generar una clave Paillier real en el harness (`paillier_t
  ::generate()`), fuera de alcance de esta ronda por el costo/tiempo de
  key generation.
- `range_pedersen_t` (`zk_pedersen.cpp`) -- usa arrays de tamaño fijo
  (`bn_t d[SEC_P_COM]`, etc.) en vez de `std::vector`, no revisado en
  detalle esta ronda.
- `unknown_order_dl_t` (`zk_unknown_order.cpp`) -- necesita un módulo
  `N` de orden desconocido (tipo RSA) real y coherente con `a`,`b` para
  que `verify()` tenga sentido; requiere más setup que los targets EC.
- `uc_batch_dl_finite_difference_impl_t` (batch DL, mismo archivo que
  `uc_dl_t`) -- ya compilado (`zk_zk_ec.o`), solo falta un harness
  dedicado.
- El protocolo MPC real (ECDSA-2PC/MPC, key gen/refresh) y la capa
  `c_api`.
