# axelarnetwork/tofn -- primer target no-HackerOne (Immunefi), verify_ecdsa + verify_ed25519

## Por qué este target

H1 dejó de aceptar reportes nuevos por un tiempo (todos los programas
que veníamos siguiendo son de H1), así que hubo que buscar objetivos
en otra plataforma. Fuente nueva: mirror público de programas de
Immunefi (`infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial`,
`projects.json`), cruzado con el mismo criterio de siempre
(`targets/select_targets.py`): lenguaje memory-unsafe, sin cobertura
de OSS-Fuzz, scope real con payout confirmado.

`axelarnetwork/tofn` (+ `tofnd`, el daemon gRPC que lo envuelve) quedó
arriba de la lista por encajar directo con la experiencia ya ganada
fuzzeando ZK/threshold crypto en `coinbase/cb-mpc`: es una librería
de criptografía Rust standalone, explícitamente en scope del programa
de Axelar en Immunefi (`tofn/blob/main/src/ecdsa/mod.rs` listado a
mano en los assets del programa), con techo de Critical de $500,000
para el asset `blockchain_dlt`.

Antes de descartarlo por nombre, se confirmó que `cometbft/cometbft`
(otro candidato fuerte del mismo batch) SÍ está cubierto por OSS-Fuzz
bajo el nombre legado "tendermint" -- el `main_repo` del
`project.yaml` real apunta a `cometbft/cometbft` aunque el directorio
en `google/oss-fuzz/projects/` se llame distinto. El chequeo actual de
`select_targets.py` (`_check_oss_fuzz_coverage`) solo compara nombre
de repo exacto, así que un caso como este pasaría desapercibido --
queda pendiente arreglarlo ahí, se filtró a mano por esta vez.

## Hallazgo honesto antes de fuzzear: el bounty grande no aplica hoy

Leyendo el código antes de escribir el harness: la versión actual de
`tofn` (v1.1.0, la que usa `tofnd`/Axelar en producción) **ya no tiene**
la implementación del protocolo threshold-ECDSA (GG20). El propio
README lo dice: se sacó del crate porque tenía vulnerabilidades
conocidas contra el ataque [TSSHock](https://www.verichains.io/tsshock/)
y no se usa en el protocolo de Axelar. Lo que queda en `src/` son
utilidades de firma de una sola parte (ECDSA secp256k1 + Ed25519) y
helpers de serde para puntos/firmas -- 1189 líneas totales, nada de
lógica de ronda multi-parte.

Esto importa porque el bounty Critical de $500k del programa está
pensado sobre todo para ese tipo de bug de protocolo multi-parte
(robo de clave privada compartida entre firmantes honestos), que ya
no existe en el código actual. Lo fuzzeable real hoy es la capa de
serialización/verificación de firmas -- todavía in-scope y con
historial de payout real (Medium $2,500 fijo, High $5,000-$25,000),
solo que con expectativa de impacto más acotada.

## Candidatos elegidos

Dos funciones, mismo shape, en `tofn::ecdsa::mod` y `tofn::ed25519::mod`:

```rust
pub fn verify(
    encoded_verifying_key: &[u8; N],   // 33 bytes SEC1 (ecdsa) / 32 bytes (ed25519)
    message_digest: &MessageDigest,
    encoded_signature: &[u8],
) -> TofnResult<bool>
```

Ambas toman DOS buffers de bytes 100% controlados por quien llama
(clave pública + firma) y los decodifican con código propio de la
crate (`k256_serde::ProjectivePoint::from_bytes` sobre
`k256::EncodedPoint`, `k256::ecdsa::Signature::from_der`,
`ed25519_dalek::VerifyingKey::from_bytes`/`Signature::from_slice`)
antes de llegar a las librerías `k256`/`ed25519-dalek`, bien
auditadas pero igual wrapeadas por lógica propia no auditada. No hace
falta reachability adicional para justificarlo -- es API pública de
una librería de firmas standalone, cualquier consumidor externo de
`tofn` (no solo `tofnd`) puede invocarla con datos no confiables.

Revisado también `k256_serde.rs` completo a mano antes de fuzzear:
todos los `from_bytes`/`Deserialize` devuelven `Option`/`Result` sin
ningún `.unwrap()` sobre datos externos -- código defensivo, ninguna
señal obvia de panic solo leyendo. Justo el tipo de caso donde vale
la pena fuzzear en vez de confiar en la lectura manual.

## Harness

`cargo-fuzz` (primera vez en esta sesión -- requirió instalar el
toolchain `nightly`, `cargo-fuzz` necesita flags de sanitizer que
`stable` rechaza). Harnesses reales en
`orchestrator/fuzz_harnesses/tofn_verify_ecdsa_harness.rs` y
`tofn_verify_ed25519_harness.rs`. Layout del input: primeros N bytes
-> clave pública, siguientes 32 -> digest, resto -> firma (bytes
crudos, sin structs `Arbitrary` de por medio, para dejarle al fuzzer
control total sobre encodings inválidos).

## Corridas

1. Smoke test, 60s cada uno: `verify_ecdsa` 2,167,892 ejecuciones,
   `verify_ed25519` 1,716,646 ejecuciones -- ambos limpios, arrancando
   ya.
2. Campaña completa, 40 min (2400s), 18 cores (`-jobs=9 -workers=9`
   por target, corridos en paralelo): **limpia, `PASS` en los dos**.
   Cero archivos en `fuzz/artifacts/{verify_ecdsa,verify_ed25519}/` --
   ningún crash guardado (esto sí es confiable, ver corrección abajo).

## Corrección (2026-08-14, post-hoc): los conteos de ejecuciones de arriba no son confiables

Al revisar el target siguiente (`wsts`, ver
`2026-08-14_wsts_point_scalar_from_bytes.md`) descubrí que
`verify_ecdsa.log` y `verify_ed25519.log` contienen **exactamente las
mismas 18 líneas "Done N runs"**, byte por byte -- `cargo-fuzz` escribe
un log por worker (`fuzz-0.log`...`fuzz-8.log`) relativo al directorio
`fuzz/` compartido, y al correr dos targets del mismo crate en
paralelo desde ese mismo directorio, sus resúmenes finales se leen
mezclados entre sí. Los números "22,349,843 ejecuciones" / "21,641,653
ejecuciones" que puse arriba en el momento eran simplemente una línea
cualquiera sacada de ese log mezclado, no el total real de cada
target -- no debieron presentarse con esa precisión.

Lo que sigue siendo confiable sin ambigüedad: ambos procesos corrieron
los 2400s completos (monitoreado en vivo durante la sesión), y **cero
crashes** en ninguno de los dos (los directorios de `artifacts/` sí
son por-target, no colisionan). Al ritmo del smoke test de un solo
core (2,167,892 y 1,716,646 ejecuciones en 60s respectivamente), 9
workers durante 2400s dan un orden de magnitud estimado de ~780M-870M
ejecuciones por target -- coherente con "sin crashes tras una campaña
larga", pero sin pretender ser una medición exacta.

## Conclusión

Sin panic ni problema de memoria en ninguno de los dos targets tras
una campaña real de 40 minutos cada uno (conclusión confiable pese al
problema de logging documentado arriba). Cada ejecución hace una
verificación de firma real (operaciones de curva elíptica), más pesada
por iteración que un `proto.Unmarshal` -- de ahí el throughput menor
que targets Go livianos como `fabric-gateway` (171M ejecuciones en el
mismo tiempo, en un solo core).

Primer target no-H1 de FRACTURE, y primer uso de `cargo-fuzz`/Rust en
el proyecto -- ambos quedan como infraestructura reusable para el
próximo candidato Rust (`serai-dex/serai`, `stacks-sbtc/sbtc/wsts`,
`filecoin-project/bellperson`, todos identificados en el mismo batch
de Immunefi, ver CHANGELOG.md).
