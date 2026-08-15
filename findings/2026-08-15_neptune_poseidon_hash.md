# lurk-lab/neptune -- sexto target no-HackerOne (Immunefi), poseidon_hash

## Por qué este target

Sexto y último target del batch de Immunefi de esta sesión (ver los
cinco anteriores: `tofn`, `serai-dkg-pedpop`, `wsts`, `bellperson`, y
el hallazgo confirmado en `rust-fil-proofs/fr32`). `neptune` es la
implementación Rust de Poseidon sobre BLS12-381 que usa Filecoin en
varios de sus circuitos ZK -- listada a mano en el scope de Immunefi
para Filecoin (Critical $25,000-$50,000).

## Candidato real -- invariante distinta a los cinco targets anteriores

A diferencia de los targets anteriores (todos: parsear bytes NO
confiables en un tipo, rechazando codificaciones inválidas de forma
segura), acá la invariante a testear es otra: `Poseidon::hash()` es
una función hash, no un parser -- **nunca debería entrar en pánico
para ningún elemento de campo válido** de la aridad correcta,
sin importar el valor. No hay "input inválido" posible una vez que ya
es un `Fr` válido; cualquier elemento de campo es un input legítimo
(ej. un leaf de un Merkle tree armado a partir de datos reales de un
sector, datos que en la práctica puede influenciar quien sea dueño de
esos datos).

Revisé a mano antes de fuzzear: `new_with_preimage` usa
`assert_eq!`/`panic!` explícitos para longitud de preimage incorrecta
-- pero eso es un contrato de API para el CALLER (longitud fija por
tipo `Arity`, no data externa), no una superficie de ataque real.
También encontré un `.unwrap()` sobre `F::from_repr()` en
`sponge/vanilla.rs:446` (`initialize_capacity`) que a primera vista
preocupaba, pero es provablemente seguro: codifica un `u128` (`tag`)
en los primeros 16 bytes de un `Repr` de 32 bytes con el resto en
cero -- como el módulo del campo BLS12-381 es de ~255 bits, CUALQUIER
valor de 128 bits cabe sin exceder el módulo, así que ese `unwrap()`
nunca puede fallar por construcción. Documentado acá para que quede
registro de que se revisó y se descartó, no que se pasó por alto.

## Harness

`fuzz_targets/poseidon_hash.rs`
(`orchestrator/fuzz_harnesses/neptune_poseidon_hash_harness.rs`):
64 bytes del input -> dos intentos de `Fr` vía
`PrimeField::from_repr` (`CtOption`, rechaza de forma segura
cualquier codificación >= módulo sin panic) -> si ambos son válidos,
`Poseidon::<Fr, U2>::new_with_preimage(&[a, b], constants).hash()`.
El campo escalar de BLS12-381 tiene el módulo entre 2^254 y 2^255, así
que una fracción real de bytes aleatorios de 32 bytes ya caen dentro
del campo sin necesitar corpus/diccionario especial.

## Bug real de mi propio harness (no del código de neptune) -- encontrado y corregido antes de la campaña

El primer smoke test dio solo 180 ejecuciones/s con RSS creciendo sin
límite -- causa: estaba llamando `PoseidonConstants::<Fr, U2>::new()`
(recalcula las round constants y la matriz MDS desde cero, no es
gratis) **dentro** del closure de `fuzz_target!`, o sea en cada una de
las ejecuciones. Corregido con `std::sync::OnceLock` para memoizar las
constantes una sola vez por proceso -- el throughput subió a
82,340/s (~450x). Ninguna campaña anterior de esta sesión tenía este
problema porque ninguna involucraba una constante tan cara de
recalcular por iteración.

## Corridas

1. Smoke test (post-fix), 60s: 5,022,752 ejecuciones, limpio,
   82,340/s.
2. Campaña completa, 40 min (2400s), 18 workers, corrida con
   `orchestrator/run_rust_fuzzer.py` (número confiable, sin la
   salvedad de "orden de magnitud" de los primeros targets de la
   sesión): **limpia -- 1,517,860,574 ejecuciones reales**, la
   campaña de mayor volumen de toda la sesión (más que las de `wsts`,
   que ya habían sido las más rápidas hasta ahora). Cero archivos en
   `fuzz/artifacts/poseidon_hash/`.

## Conclusión

Sin panic en más de 1500 millones de ejecuciones del hash Poseidon
real sobre elementos de campo válidos. Da confianza real en que la
implementación no tiene un caso borde de indexación/aritmética que
rompa la invariante "nunca panics ante input válido" para la aridad
U2 -- no se probaron otras aridades (U4/U8/U11/U16/U24/U36, todas
compiladas vía features separadas) ni la ruta `VariableLength`
(explícitamente `panic!("not yet supported")` en el código, ni
implementada todavía).

## Cierre del batch de Immunefi/Filecoin de esta sesión

Seis targets no-HackerOne fuzzeados, vía el mirror público de
Immunefi como fuente de candidatos:

| Target | Resultado |
|---|---|
| `axelarnetwork/tofn` (ecdsa+ed25519 verify) | Limpio |
| `serai-dex/serai` (dkg-pedpop read_commitments) | Limpio |
| `stacks-sbtc/sbtc` (wsts point/scalar from_bytes) | Limpio |
| `filecoin-project/bellperson` (groth16 proof read) | Limpio |
| `filecoin-project/rust-fil-proofs` (fr32 write_unpadded) | **Hallazgo real confirmado (CWE-190)** |
| `lurk-lab/neptune` (poseidon hash) | Limpio |

Un hallazgo real confirmado sobre seis targets -- de paso, dos bugs
reales de tooling propios encontrados y corregidos en el camino
(colisión de logs de `cargo-fuzz` en corridas paralelas, y el
recálculo de constantes por iteración acá) quedan como mejoras
permanentes de `orchestrator/` para toda campaña futura, no solo para
este batch.
