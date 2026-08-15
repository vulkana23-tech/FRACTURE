# filecoin-project/bellperson -- cuarto target no-HackerOne (Immunefi), groth16::Proof::read

## Por qué este target

Cuarto target de la fuente Immunefi (ver los tres anteriores: `tofn`,
`serai-dkg-pedpop`, `wsts`). `bellperson` es la librería zk-SNARK
(Groth16) que usa Filecoin para sus proof systems -- listada a mano en
el scope de Immunefi para Filecoin (`filecoin-project/bellperson`,
Critical $25,000-$50,000).

## Candidato real

`bellperson::groth16::Proof::<Bls12>::read()`
(`src/groth16/proof.rs:69`) -- el parseo real de un proof Groth16
(`A: G1, B: G2, C: G1` sobre BLS12-381, la curva real de Filecoin) que
cualquier verificador invoca sobre bytes enviados por un prover NO
confiable. Exactamente el mismo tipo de superficie que ya rindió en
los tres targets anteriores (parsing de curva elíptica desde bytes de
origen no confiable), esta vez para una curva distinta (BLS12-381 vía
`blstrs`/`blst`, en vez de secp256k1 o Ristretto/Ed25519) y un formato
de mensaje distinto (proof Groth16 de tamaño fijo: `2*48 + 96 = 192`
bytes para BLS12-381, en vez de un mensaje DKG o una firma).

La implementación real decodifica cada punto vía
`GroupEncoding::from_bytes` (de `blst`, biblioteca C real de
supranational, bien auditada -- otra dependencia C real bajo un crate
Rust, mismo patrón que `libsecp256k1` en `wsts`) y agrega chequeos
propios explícitos ("not on curve", "point at infinity") antes de
aceptar cada punto. El código alrededor de esa llamada (offsets fijos,
manejo de rangos, la lógica de rechazo) es de `bellperson`, no de
`blst` -- ahí es donde vale la pena fuzzear, no en la primitiva en sí.

Nota aparte (no fuzzeada, documentada para la próxima sesión): el
`impl Deserialize for Proof` en el mismo archivo (línea ~41) hace
`Proof::read(v).unwrap()` dentro del visitor de serde -- si `read()`
devuelve `Err` (bytes malformados), esto **panicquea** en vez de
propagar un error de deserialización normal. Es una superficie
distinta a la que se fuzzeó acá (requiere que el `Proof` se
deserialice vía un `Deserializer` de serde, no vía `Proof::read`
directo) -- vale la pena un fuzz target separado si se sigue
invirtiendo en este repo.

## Complicación real de build (no un bug)

`cargo fuzz init` detectó el crate equivocado: el `Cargo.toml` raíz de
`bellperson` combina `[package] name = "bellperson"` con
`[workspace] members = ["verifier-bench"]` (un binario de benchmark
separado, mismo repo) -- cargo-fuzz terminó generando
`fuzz/Cargo.toml` con una dependencia a `verifier-bench` en vez de a
`bellperson`. Corregido a mano: `[dependencies.bellperson] path = ".."`
más `[workspace]` vacío en el propio `fuzz/Cargo.toml` (mismo patrón
que en `dkg-pedpop`/`wsts` para desacoplarlo del workspace real).

## Harness

Un solo target, `groth16_proof_read.rs`
(`orchestrator/fuzz_harnesses/bellperson_groth16_proof_read_harness.rs`).
Bytes crudos directo a `Proof::<Bls12>::read()`, sin forzar el tamaño
de antemano -- se deja que el propio fuzzer explore longitudes
inválidas además de contenido inválido.

## Corridas

1. Smoke test, 60s: 125,758 ejecuciones, limpio. Throughput bajo
   comparado con los targets anteriores (2,061/s) -- `Proof::read`
   usa `rayon::into_par_iter()` internamente incluso para un solo
   proof (paraleliza la decodificación de los 3 puntos entre
   threads), overhead de scheduling real por llamada que no tienen
   los targets anteriores (una sola conversión directa).
2. Campaña completa, 40 min (2400s), 18 workers -- **primera campaña
   de esta sesión corrida con `orchestrator/run_rust_fuzzer.py`** (el
   fix del bug de colisión de logs documentado en
   `2026-08-14_wsts_point_scalar_from_bytes.md` y el CHANGELOG):
   **limpia, 81,329,736 ejecuciones reales** -- número confiable esta
   vez, sin la salvedad de "orden de magnitud" de los targets
   anteriores. Cero crashes (`fuzz/artifacts/groth16_proof_read/`
   vacío).

## Conclusión

Sin panic ni problema de memoria en el parseo real de un proof Groth16
tras 81M ejecuciones. Menor volumen que los targets anteriores por el
overhead real de paralelización interna de la función (no una
limitación del fuzzer) -- coherente con lo esperado dado el diseño de
`Proof::read` (pensado para lotes grandes vía `read_many`, no para un
solo proof a la vez).

## Balance del batch de Immunefi hasta ahora

Cuatro targets no-H1 fuzzeados esta sesión (Axelar/tofn,
Serai/dkg-pedpop, sBTC/wsts, Filecoin/bellperson), cero crashes en
ninguno. Quedan sin tocar del mismo batch: `rust-fil-proofs`
(Filecoin, pruebas de espacio-tiempo) y `lurk-lab/neptune`
(implementación Rust de Poseidon, hash usado en varios de los
circuitos ZK de Filecoin) -- ambos también Critical $25k-$50k en el
mismo programa de Filecoin.
