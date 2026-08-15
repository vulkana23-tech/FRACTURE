# cb-mpc — zk_paillier.cpp: valid_paillier_t + paillier_zero_t — resultado limpio

**Programa:** Coinbase (HackerOne `hackerone.com/coinbase`, `automated_scanning: allowed`)
**Repo:** `coinbase/cb-mpc` (Tier 1, C++, no cubierto por OSS-Fuzz), repo
específico en scope. Sexto target de esta sesión dentro de `cb-mpc`, y
primero que requiere una clave criptográfica real generada en el
harness (a diferencia de los 4 targets EC anteriores, que solo
necesitaban puntos fijos derivados del generador de la curva).

## Por qué este target

`zk_paillier.cpp` contiene las pruebas ZK sobre el cifrado Paillier
(homomórfico aditivo) que usa `cb-mpc` para varias partes del
protocolo MPC. De los 2 structs cubiertos:

- `valid_paillier_t` -- prueba que una clave pública Paillier `N` está
  bien formada (sin factores primos pequeños, generada correctamente),
  sin necesitar ningún ciphertext. La superficie más directa: solo
  depende de la clave.
- `paillier_zero_t` -- prueba que un ciphertext cifra el valor 0 sin
  revelar la aleatoriedad usada. Necesita además un ciphertext real
  (`paillier.encrypt(0)`).

Ambas son deserializables desde bytes de un peer no confiable
(`convert(converter_t&)`) y ambas tienen `verify()` alcanzable con solo
una clave Paillier fija -- a diferencia de `two_paillier_equal_t`/
`pdl_t` (necesitan 2 claves o un rango específico), quedan para una
próxima ronda.

## Setup (el más caro hasta ahora dentro de `zk/`)

A diferencia de los 3 targets EC anteriores de esta sesión (que solo
necesitaban `curve_secp256k1.mul_to_generator`), acá se generó una
clave Paillier real de 2048 bits (`paillier_t::generate()`) -- **una
sola vez, de forma estática, al primer input de cada proceso
fuzzeado** (18 veces en total con `-fork=18`, no por ejecución). Se
compilaron 2 archivos nuevos: `zk_paillier.cpp` y `small_primes.cpp`
(tabla de los primeros 10,000 primos, usada para el chequeo rápido de
factores pequeños de `N` en cada `verify()`). El linkeo de
`zk_paillier.cpp` reveló una dependencia no obvia: `pdl_t::verify()`
(no fuzzeada acá) llama a `range_pedersen_t::verify()`, así que también
hubo que compilar `zk_pedersen.cpp` solo para resolver ese símbolo en
el link -- limpio a la primera, sin agregar `pdl_t` al alcance del
harness.

Harness (`fuzz_zk_paillier.cpp`): clave Paillier fija + ciphertext de
cero fijo, ambos generados una sola vez de forma estática (lazy, en el
primer input). Cada struct se deserializa desde una vista independiente
de los mismos bytes fuzzeados y llama su `verify()` real.

## Resultado

- Smoke test: 30s (+ ~1s de overhead de key generation al arranque,
  despreciable), 72,825 ejecuciones, cov 239, limpio. Throughput más
  bajo que los targets EC (~2,349 exec/s vs. decenas de miles) --
  esperado: cada `verify()` hace ~10 exponenciaciones modulares reales
  mod un número de 2048 bits, más costoso que aritmética de curva
  elíptica.
- Campaña completa: `-fork=18`, 2400s (40 min), **64,846,477
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura estable en 1118/711 (corpus final: 66-72 casos)
  bastante antes del final.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza -- tanto la validación de la clave Paillier
como la prueba de ciphertext-de-cero resistieron casi 65 millones de
ejecuciones reales con exponenciación modular real de 2048 bits, sin
ninguna corrupción de memoria. Menor volumen que los targets EC (más
lento por operación), pero un volumen todavía muy por encima del umbral
donde bugs de memoria triviales suelen aparecer. No se reporta nada a
Coinbase.

## Qué queda sin cubrir

- `two_paillier_equal_t`, `pdl_t`, `paillier_range_exp_slack_t`,
  `paillier_pedersen_equal_t` (necesitan 2 claves Paillier, o un rango
  `q`/commitment Pedersen coherente -- más setup).
- `valid_paillier_interactive_t` (variante interactiva, distinto flujo
  challenge/response).
- `range_pedersen_t` (arrays de tamaño fijo, ya compilado vía
  `zk_zk_pedersen.o` pero sin harness dedicado).
- `unknown_order_dl_t` (necesita un módulo RSA-like coherente).
- `fischlin.cpp::prove()`, el protocolo MPC real (ECDSA-2PC/MPC, key
  gen/refresh) y la capa `c_api`.
