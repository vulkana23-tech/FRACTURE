# serai-dex/serai -- segundo target no-HackerOne (Immunefi), dkg-pedpop::Commitments::read

## Por qué este target

Segundo target de la nueva fuente Immunefi (ver
`2026-08-14_axelar-tofn_verify_ecdsa_ed25519.md` para el primero).
`serai-dex/serai` es el candidato que mejor encaja de todo el batch:
a diferencia de `tofn` (donde el protocolo threshold real ya no
estaba en el código, sacado por el ataque TSSHock), acá el DKG está
vivo y en uso -- PedPoP es el protocolo de distributed key generation
que Serai usa hoy, no una implementación legada. Listado a mano en el
scope de Immunefi (`crypto/dkg/src`, bounty Critical fijo de $30,000).

## Candidato real

`dkg-pedpop::Commitments::read()` (`crypto/dkg/pedpop/src/lib.rs`) --
el mensaje de "commitments" que cada participante de PedPoP transmite
a todos los demás en la ronda 1 del DKG, y que cada receptor parsea
desde bytes que llegaron por red. El propio doc-comment de la struct
lo dice explícito:

> Every participant should only provide one set of commitments to all
> parties. If any participant sends multiple sets of commitments, they
> are faulty and should be presumed malicious.

El modelo de amenaza de la librería ya asume participantes
maliciosos mandando mensajes crafteados -- exactamente lo que fuzzing
simula. `read()` hace `params.t()` lecturas de un `C::G` (punto de
curva, vía `GroupEncoding`/`C::read_G`) más una `SchnorrSignature::read`
al final, todo sobre bytes 100% controlados por el remitente.

Revisé a mano el resto de `k256_serde`-equivalente de Serai
(`ciphersuite`, `multiexp`) antes de fuzzear: mismo patrón defensivo
que en `tofn` (`Option`/`Result` en los `from_bytes`, sin `.unwrap()`
sobre datos externos) -- otra vez el tipo de caso donde vale más
fuzzear que confiar en la lectura manual.

## Complicación real de build (no un bug, del entorno)

Dos problemas reales, ninguno del código de Serai:

1. **Monorepo grande, clone sparse.** `serai` es un workspace de ~40
   members (substrate, coordinator, processor, networks/bitcoin,
   etc.) -- clonar todo hubiera sido enorme y en su mayoría
   irrelevante para este target. Se hizo `git clone --filter=blob:none
   --sparse` y `git sparse-checkout set crypto common`, pero el
   `Cargo.toml` raíz del repo sigue listando los ~40 members
   igual, y Cargo falla si un member listado no existe en disco.
   Resuelto agregando `[workspace]` (vacío) + `[workspace.lints]`
   (vacío) al `Cargo.toml` de `dkg-pedpop` -- lo convierte en su
   propia raíz de workspace en vez de subir al del monorepo. Cambio
   solo en el clon local, nunca en el repo real.

2. **`Commitments::read` está detrás de un trait sellado.** El método
   real vive en `impl ReadWrite for Commitments`, donde `ReadWrite`
   está definido dentro de `mod sealed` (privado) en
   `encryption.rs`, re-exportado solo como `pub(crate)`. Un patrón de
   sellado intencional (evita que crates externos implementen el
   trait), pero como efecto secundario tampoco se puede *invocar*
   `Commitments::read()` desde afuera del crate -- ni siquiera para
   fuzzear. Se agregó un wrapper público mínimo en el mismo `lib.rs`
   (dentro del crate, donde el trait sellado sí está en scope):

   ```rust
   #[doc(hidden)]
   pub fn fuzz_read_commitments<C: Ciphersuite>(
     data: &[u8],
     params: ThresholdParams,
   ) -> io::Result<Commitments<C>> {
     let mut cursor = io::Cursor::new(data);
     Commitments::<C>::read(&mut cursor, params)
   }
   ```

   Sin lógica propia, solo expone el mismo `read()` real. Cambio local
   únicamente, documentado acá para que quede claro que el target
   fuzzeado es el código real de la librería, no una reimplementación.

## Harness

`cargo-fuzz` con curva `dalek_ff_group::Ristretto` (una de las
ciphersuites reales que expone Serai) y `ThresholdParams` fijos
(t=2, n=3, nosotros=participante 1) -- no son bytes que lleguen por
red en esta firma, son config local del receptor. Todo el input del
fuzzer va al reader (el mensaje de commitments en sí). Harness real en
`orchestrator/fuzz_harnesses/serai_dkg_pedpop_read_commitments_harness.rs`.

## Corridas

1. Smoke test, 60s: 2,160,172 ejecuciones, limpio, cobertura
   (`cov: 333 ft: 829`) ya estabilizada desde temprano.
2. Campaña completa, 40 min (2400s), 18 cores (`-jobs=18 -workers=18`):
   **limpia, `PASS`** -- **1,089,233,549 ejecuciones reales** sumando
   los 18 workers (rango real por worker: 58.6M-62.7M, buen balance
   entre cores), cobertura estable en `cov: 333 ft: 829` en todos.
   Cero archivos en `fuzz/artifacts/read_commitments/` -- ningún
   crash guardado, ningún ASan/panic en los logs de los 18 workers.

## Conclusión

Sin panic ni problema de memoria en el parser real del mensaje de
DKG más expuesto a participantes maliciosos, tras mil millones de
ejecuciones reales. Mayor volumen que cualquier target Rust/Go previo
de esta sesión (comparar con los ~22M de `tofn::ecdsa::verify` en el
mismo tiempo) -- esperable, cada ejecución acá es mucho más liviana
(la mayoría de los inputs aleatorios fallan temprano en
`read_exact` antes de llegar a decodificar un punto de curva real).
Da confianza real en el resultado, sin ser garantía de ausencia de
bugs -- el corpus se estabilizó rápido (11-12 entradas), señal de que
mutación aleatoria pura ya exploró la mayor parte de los caminos de
error simples (longitud insuficiente, punto inválido) y lo que queda
sin cubrir probablemente necesite un corpus semilla más inteligente
(commitments reales, válidos, generados por el propio protocolo) para
llegar más profundo en la verificación de la firma Schnorr al final
del mensaje.

## Próximo candidato

Quedan sin tocar del mismo batch de Immunefi: `stacks-sbtc/sbtc/wsts`
(Weighted Threshold Signature Scheme, Rust, Critical $25k-$250k) y
`filecoin-project/bellperson`/`rust-fil-proofs`/`lurk-lab/neptune`
(librerías ZK, Rust, Critical $25k-$50k) -- ver CHANGELOG.md.
