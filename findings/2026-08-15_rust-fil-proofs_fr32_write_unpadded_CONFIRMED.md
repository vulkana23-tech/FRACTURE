# filecoin-project/rust-fil-proofs (fr32) -- quinto target no-HackerOne, hallazgo real confirmado

## Resumen

`fr32::write_unpadded()` (`fr32/src/padding.rs:566`), función pública
de la librería `fr32` (parte de `filecoin-project/rust-fil-proofs`,
en scope de Immunefi para Filecoin) tiene una resta sin chequear que
puede hacer underflow de `usize`:

```rust
// fr32/src/padding.rs:579 (dentro de write_unpadded)
let raw_data_size = BitByte::from_bits(
    FR32_PADDING_MAP.transform_bit_offset(source.len() * 8 - read_pos.total_bits(), false),
)
.bytes_needed();
```

Si `source` es más corto de lo que `offset` (en bytes sin padding)
requeriría, `read_pos.total_bits()` (derivado de `offset`) supera a
`source.len() * 8`, y la resta hace underflow.

**CWE-190: Integer Underflow.**

## Reachability -- confirmado con un caso concreto, sin datos inventados

`write_unpadded(source: &[u8], target: &mut W, offset: usize, len: usize)`
es la función real que "des-empaqueta" datos con el padding Fr32 que
usa Filecoin para todo dato sellado -- según su propio doc-comment
(`fr32/src/padding.rs:558-562`), un caso de uso normal y documentado
es pedir un rango arbitrario (`offset`, `len`) de los datos crudos
codificados dentro de `source`. Encontrado por fuzzing puro (no lectura
de código): con `cargo-fuzz` (libFuzzer + `arbitrary`), el **smoke
test de 60 segundos** (no hizo falta campaña larga) encontró de
entrada:

```
Input { source: [], offset: 2599, len: 10 }
```

Repro directo contra el binario compilado (con debug-assertions, como
compila `cargo fuzz build` incluso en release):

```
thread '<unnamed>' panicked at fr32/src/padding.rs:579:47:
attempt to subtract with overflow
```

100% determinístico, reproducido con el mismo input las veces que se
quiera.

## Impacto real -- distinto según el perfil de compilación (verificado, no supuesto)

Se armó un binario mínimo aparte que llama a `fr32::write_unpadded`
directo, una vez en modo `debug` (con overflow-checks, el default de
Rust en debug) y otra en modo `--release` genuino (sin
`[profile.release] overflow-checks = true` en el `Cargo.toml` de
`rust-fil-proofs` -- confirmado que no está seteado), para no asumir
el comportamiento en producción:

- **Con overflow-checks (debug, o cualquier pipeline de testing/CI que
  compile así, o un consumidor downstream que opte por
  `overflow-checks = true` en su propio release)**: panic real,
  determinístico -- **denial of service** en cualquier proceso que
  llame `write_unpadded` con un `offset` mayor a lo que `source`
  contiene.
- **En release genuino (el modo en que corren la mayoría de los
  demonios de storage providers de Filecoin en producción)**: la
  resta hace wraparound silencioso (comportamiento default de Rust en
  release, no panic) -- el chequeo de "hay suficientes datos"
  (`if raw_data_size < len { return Err(...) }`) queda **baipaseado**
  porque `raw_data_size` wrappea a un número absurdamente grande, pero
  se confirmó empíricamente (no asumido) que el código que sigue
  (`write_unpadded_aux`) no llega a hacer una lectura fuera de rango
  real -- en los 5 casos de borde probados (`source` vacío o corto,
  `offset`/`len` mayores a lo disponible), la función devuelve
  **`Ok(0 bytes escritos)`** en vez de un error, sin panic. Es decir:
  en producción esto no es (según lo verificado) un crash/RCE, es un
  **bug de integridad de datos silencioso** -- un caller que pide `len`
  bytes de datos ya "des-sellados" recibe 0 bytes con un resultado
  `Ok`, sin ninguna señal de que algo salió mal.

No se armó un PoC completo contra un sector sellado real (el flujo
completo de sellado/unsealing de Filecoin es pesado de reproducir
localmente) -- esto es honesto: el hallazgo está confirmado a nivel de
la función pública de la librería con datos reales, no se demostró
todavía un escenario end-to-end contra un storage provider real. El
único caller conocido dentro de este mismo repo
(`filecoin-proofs/src/api/mod.rs:318`, dentro de `unseal_range_mapped`)
pasa `offset=0` siempre en su llamada a `write_unpadded`, lo cual
evita el underflow en ESE call site específico (con offset=0,
`read_pos.total_bits()` también es 0, la resta nunca underflowea) --
pero `write_unpadded` es API pública exportada de la librería `fr32`
(`pub fn`, re-exportada en `fr32/src/lib.rs`), documentada
explícitamente para aceptar cualquier `offset`, así que cualquier otro
consumidor de la librería (herramientas de terceros, otro código
dentro del propio ecosistema Filecoin no revisado en este clon
sparse) que la use como está documentada queda expuesto.

## Reachability real -- investigación completa (2026-08-15, post-hoc)

Antes de armar un reporte se leyó la policy completa de Immunefi para
Filecoin (no solo el resumen de scope): el programa exige
explícitamente PoC contra un devnet real y excluye por policy propia
**"Fuzzer crash outputs without a devnet reproduction showing the
crash is reachable from an external input on a running node"**.
Se instaló el [Filecoin Audit Kit](https://github.com/FilecoinFoundationWeb/filecoin-audit-kit)
(devnet Lotus 2k) con esa intención, pero antes de terminar el setup
se rastreó a mano la cadena real desde una RPC externa hasta
`write_unpadded` -- y se encontró que **no hace falta el devnet para
responder la pregunta de reachability, el código mismo ya la
responde**:

- `storage/sealer/piece_provider.go` (Lotus) -- `ReadPiece`, el path
  real de retrieval, usa un paquete **Go propio**
  (`storage/sealer/fr32`, reimplementación nativa, NO la crate Rust
  `fr32` de `rust-fil-proofs`) para la mayoría de las lecturas. Ese
  código Go nunca toca la función Rust fuzzeada.
- El único camino que sí llega a la crate Rust es vía
  `filecoin-ffi`'s `UnsealRange` (`cgo/proofs.go`) -> Rust
  `filecoin_proofs::api::unseal_range_inner`
  (`filecoin-proofs/src/api/mod.rs:282`) -- y ahí está la razón real
  por la que este bug no es explotable hoy: **las tres funciones
  públicas del crate que exponen unsealing**
  (`get_unsealed_range`, `unseal_range`, `unseal_range_mapped`)
  delegan todas al mismo helper privado `unseal_range_inner`, que
  aplica el `offset` externo **cortando el slice** (`data[start..end]`)
  ANTES de desempaquetar, y llama a `write_unpadded(unsealed, &mut
  out, 0, num_bytes)` con **offset hardcodeado en 0, siempre**, sin
  importar qué offset haya pedido el caller original. El parámetro
  `offset` de `write_unpadded` -- el que dispara el underflow -- no
  recibe nunca un valor real proveniente de una RPC externa por este
  camino.
- Se revisó también **Boost** (`filecoin-project/boost`, el daemon de
  storage deals): no tiene ninguna referencia directa a
  `fr32`/`write_unpadded` en su código Go, y depende de
  `filecoin-ffi` de la misma forma que Lotus (mismo camino, mismo
  resultado).

**Conclusión honesta:** el bug es real, reproducible, y confirmado a
nivel de la función pública de la librería `fr32` -- pero, tras
revisar las dos implementaciones de producción más relevantes del
ecosistema (Lotus y Boost), **no se encontró ningún camino externo que
lo dispare hoy**. El parámetro `offset` de `write_unpadded` parece
vestigial en la práctica: existe en la firma pública, documentado
para aceptar cualquier valor, pero ningún consumidor real conocido lo
usa con un valor distinto de cero -- los propios desarrolladores de
Filecoin evitan la ruta vulnerable aplicando el offset de otra forma
en su propio código. No se descarta que exista algún otro consumidor
de la librería (herramientas de terceros no revisadas) que sí la use
como está documentada, pero no se encontró uno concreto. El setup del
devnet se abandonó a mitad de la descarga de parámetros (~625MB a
~50KB/s, iba a tardar horas) una vez que quedó claro que terminar el
devnet no iba a cambiar esta conclusión -- no hay un input externo
real que probar contra un nodo corriendo.

## Harness

`fr32/fuzz/fuzz_targets/write_unpadded.rs`
(`orchestrator/fuzz_harnesses/rust_fil_proofs_fr32_write_unpadded_harness.rs`),
usando `arbitrary` para estructurar `{source: Vec<u8>, offset: u16,
len: u16}` en vez de bytes crudos sin estructura -- primera vez en
esta sesión usando `arbitrary-derive` para un target Rust (los
anteriores pasaban bytes crudos directo). El input que crasheó queda
en `fuzz/artifacts/write_unpadded/crash-c9aa8ff85806233842d62eb71758f904fd68c006`.

## Suggested Fix

Reemplazar la resta directa por `checked_sub`, devolviendo un
`io::Error` explícito ("offset beyond source data") cuando
`read_pos.total_bits()` exceda `source.len() * 8`, en vez de dejar que
la aritmética falle en silencio (release) o entre en pánico (debug).
Dado que en release el bug ya se manifiesta como "devuelve éxito con 0
bytes" en vez de propagar el error real, el fix también corrige una
regresión de corrección de datos, no solo el panic.

## Próximo paso

No se lanzó la campaña completa de 40 min para este target -- el
smoke test ya encontró y confirmó el hallazgo real, y el tiempo se
priorizó en la investigación de reachability/impacto en vez de correr
más fuzzing sobre el mismo crash ya encontrado. Si se quiere seguir
invirtiendo en `rust-fil-proofs`, el corpus que sobrevivió el smoke
test (`fuzz/corpus/write_unpadded/`) es un buen punto de partida para
una campaña larga apuntando a otras funciones del mismo crate.

## Decisión final (2026-08-15)

**No se reporta a Immunefi.** Dado que la policy del programa exige
explícitamente reachability demostrada contra un devnet real, y la
investigación de este mismo documento no encontró un camino externo
que dispare el bug (ni en Lotus ni en Boost, las dos implementaciones
de producción revisadas), el hallazgo queda documentado acá como
registro de FRACTURE -- bug real, confirmado, con causa raíz e impacto
por perfil de compilación completamente entendidos -- pero sin enviar
como reporte de bug bounty. Si en el futuro aparece evidencia de un
consumidor real de `fr32::write_unpadded` con `offset != 0` (otra
herramienta, otra versión de Boost/Lotus, un fork), vale la pena
retomarlo con esa reachability nueva en mano.
