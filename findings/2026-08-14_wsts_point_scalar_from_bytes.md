# stacks-sbtc/sbtc (WSTS) -- tercer target no-HackerOne (Immunefi), point/scalar from_bytes

## Por qué este target

Tercer target de la fuente Immunefi (ver los dos anteriores:
`2026-08-14_axelar-tofn_verify_ecdsa_ed25519.md`,
`2026-08-14_serai-dkg-pedpop_read_commitments.md`). `wsts` (Weighted
Schnorr Threshold Signatures, basado en FROST) vive en
`stacks-sbtc/sbtc/wsts` -- listado a mano en el scope de Immunefi para
sBTC (`The WSTS library`, Critical $25,000-$250,000).

## Candidato real -- distinto de los dos anteriores

A diferencia de `tofn`/`serai-dkg-pedpop`, WSTS **no hace su propio
parsing de bytes**. Los tipos de mensaje de red (`net.rs`: `Message`,
`DkgPublicShares`, `NonceRequest`, etc.) son structs Rust planos (sin
`derive(Serialize/Deserialize)` en ningún lado del crate) -- la
deserialización real de bytes-de-red a estos structs vive en el crate
`signer` de `sbtc`, que no está en este clon (no forma parte del scope
explícito de Immunefi para este asset).

Revisé a mano el resto del state machine (`state_machine/signer/mod.rs`)
buscando el mismo patrón que ya encontró bugs reales esta sesión
(indexado `map[id]` sin chequeo previo cerca de un `signer_id`/`key_id`
que llega en un mensaje): las tres ocurrencias reales
(`self.public_keys.key_ids[&dst_key_id]`,
`self.public_keys.signers[&src_signer_id]` x2) están todas precedidas
por un `.get(&id)` explícito unas líneas antes que corta temprano si
el id no existe -- código defensivo real, sin bug obvio de lectura
esta vez.

El parsing real de bytes SÍ existe, pero un nivel más abajo: en
`wsts::curve` (= el crate `p256k1`, re-exportado directo en
`wsts/src/lib.rs` como `pub use p256k1 as curve`), que envuelve
`libsecp256k1` real (vendored en `_secp256k1/`, el mismo C de
bitcoin-core) vía bindgen. Dos funciones, ambas invocadas directo por
el propio código de wsts sobre bytes de mensajes de red:

- `Point::try_from(&Compressed)` -- usada en
  `state_machine/signer/mod.rs:754` y `:850` para parsear claves
  públicas/commitments de otros participantes. La implementación real
  (en el crate `p256k1`, `point.rs`) hace la validación dentro de un
  bloque `unsafe` llamando funciones **internas** de libsecp256k1
  (`secp256k1_fe_set_b32`, `secp256k1_ge_set_xo_var` -- no son parte de
  la API pública estable de la librería) sobre structs armados a mano
  en el stack. Al ser API interna vía bindings propios, es mucho menos
  probable que esta ruta específica ya esté cubierta por el fuzzing
  que bitcoin-core/OSS-Fuzz corren sobre libsecp256k1 (que apunta a la
  API pública).
- `Scalar::try_from(&[u8])` -- usada en `state_machine/signer/mod.rs:859`
  sobre bytes ya **desencriptados** de un DKG private share recibido
  de otro signer. Si ese signer es malicioso o el share está
  corrupto, el contenido desencriptado es arbitrario antes de llegar
  acá.

Ninguna de las dos vive literalmente en `wsts/src/` (están en la
dependencia `p256k1`, de Trust-Machines), pero son el pipeline
bytes->curva real que el propio código en scope invoca directo sobre
datos de otros participantes -- mismo criterio que ya usé en `tofn`
(fuzzear el wrapper delgado, no el crate externo bien auditado en sí).

## Complicación real de build (no un bug)

Mismo patrón que en `serai`: workspace de sBTC con 11 members, clon
sparse (solo `wsts/`), `[workspace]` vacío en `wsts/Cargo.toml` para
que no dependa de los demás members no clonados, y las dependencias
`.workspace = true` reemplazadas por sus versiones reales (leídas del
`Cargo.toml` raíz real del repo, que sí queda en cualquier sparse
clone). A diferencia de `dkg-pedpop`, wsts no depende de ningún crate
hermano del monorepo (solo deps externas), así que fue más simple.

## Harness

Dos targets, `point_from_bytes.rs` y `scalar_from_bytes.rs`, ambos en
`orchestrator/fuzz_harnesses/wsts_*_harness.rs`. `point_from_bytes`
filtra a exactamente 33 bytes (tamaño fijo del formato comprimido)
antes de llamar `Compressed::try_from` + `Point::try_from`;
`scalar_from_bytes` pasa el input crudo directo a `Scalar::try_from`.

## Corridas

1. Smoke test, 60s cada uno (secuencial, sin colisión):
   `point_from_bytes` 30,307,508 ejecuciones, `scalar_from_bytes`
   45,163,717 ejecuciones -- ambos limpios. Throughput muy alto
   (496,844/s y 740,388/s respectivamente) comparado con los targets
   anteriores, esperable: son conversiones puntuales, sin el overhead
   de una verificación de firma completa.
2. Campaña completa, 40 min (2400s), 9 workers cada uno, **corridos en
   paralelo entre sí** (mismo patrón que con `tofn::ecdsa`/`ed25519`).
   Confirmado por monitoreo de proceso que ambos corrieron los 2400s
   completos, y **cero archivos en `fuzz/artifacts/{point_from_bytes,
   scalar_from_bytes}/`** -- ningún crash guardado en ninguno de los
   dos (esta parte del resultado SÍ es confiable: `-artifact_prefix`
   es una ruta distinta por target, no colisiona).

## Hallazgo real de tooling (no del código de sBTC/wsts)

Al querer sumar el total de ejecuciones reales de los 9 workers de
cada target, encontré que **los dos archivos de log
(`wsts_point_from_bytes.log` y `wsts_scalar_from_bytes.log`) contienen
exactamente las mismas líneas "Done N runs"**, byte por byte. Mismo
problema ya afectó (sin que lo notara en su momento) al reporte de
`tofn::ecdsa::verify`/`ed25519::verify`: sus dos logs también
comparten el mismo conjunto de 18 líneas "Done".

Causa real: `cargo-fuzz` en modo `-jobs=N` escribe un log por worker
(`fuzz-0.log`...`fuzz-{N-1}.log`) relativo al directorio de trabajo
del proceso (`fuzz/`), y al terminar arma su resumen final releyendo
esos archivos. Cuando dos targets del MISMO crate (`fuzz/` compartido)
corren en paralelo, sus workers pisan/leen los mismos nombres de
archivo -- para `tofn` sobrevivieron por suerte las 18 entradas
distintas (mezcladas entre ambos resúmenes, pero sin pérdida real de
datos), para `wsts` se perdieron 2 de las 18 esperadas (16 únicas en
vez de 18) por una colisión de escritura real.

**Conclusión honesta:** los números exactos de ejecuciones totales que
reporté para la campaña completa de `tofn` (22,349,843 /
21,641,653) y cualquier número agregado que hubiera reportado acá para
`wsts` a partir de esos logs **no son confiables** -- son producto de
esta colisión, no una medición real por-target. Lo que SÍ es confiable
sin ambigüedad: ambos procesos corrieron la duración completa
(confirmado por monitoreo de proceso en vivo durante la sesión), y
**cero crashes** en ninguno de los dos targets (los directorios de
artifacts no colisionan, son rutas distintas por target). Como
estimación honesta de orden de magnitud (no medición exacta): al ritmo
medido en el smoke test de un solo core, 9 workers durante 2400s
darían aproximadamente 10-11 mil millones de ejecuciones
(`point_from_bytes`) y 16-18 mil millones (`scalar_from_bytes`) --
coherente con que no hubo crash, pero sin la precisión que aparentaban
tener los números que reporté antes.

**Fix pendiente para el orchestrator:** correr campañas paralelas de
distintos targets del mismo crate desde directorios de trabajo
separados (o copias del `fuzz/` crate), o simplemente serializar
campañas que compartan el mismo `fuzz/` en vez de lanzarlas
concurrentemente con `&`. No se tocó el orchestrator todavía -- queda
como deuda técnica real, documentada acá para la próxima sesión.

## Conclusión

Sin crashes en ninguno de los dos targets tras una campaña real de 40
minutos cada uno (conclusión confiable pese al problema de logging).
El pipeline bytes->curva de wsts, incluyendo las llamadas a funciones
internas de libsecp256k1 vía bindgen, sobrevivió miles de millones de
ejecuciones sin un panic ni una señal de ASan.
