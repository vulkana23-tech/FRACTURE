#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use fr32::write_unpadded;

// fr32::write_unpadded() -- el proceso real de "unpadding" que recupera
// datos crudos a partir de datos con padding Fr32 (el formato interno
// que usa Filecoin para todo dato sellado/almacenado). `source` en la
// firma real es literalmente el contenido leido de vuelta de un sector
// sellado -- en un flujo real de retrieval/unsealing, ese contenido
// puede venir de un storage provider potencialmente bizantino/con
// datos corruptos, exactamente el modelo de amenaza de un fuzz target.
// En scope real de Immunefi (`filecoin-project/rust-fil-proofs`).
//
// La implementacion real hace aritmetica manual a nivel de bits
// (`BitByte`, `transform_bit_offset`) para saltar los bits de padding
// -- incluye una resta (`source.len() * 8 - read_pos.total_bits()`)
// que underflowearia en usize si `read_pos` quedara mas alla del final
// de `source`, exactamente el tipo de aritmetica manual sin chequeo
// explicito que ya encontro bugs reales en esta sesion (fabric-sdk-go
// extractConfig, besu-native gnark).
//
// `offset`/`len` como u16 (no el input completo) para mantener una
// proporcion realista con `source` (inputs de fuzzing de unos pocos
// KB como mucho) sin que el espacio de busqueda quede dominado por
// combinaciones fuera de rango de entrada.
#[derive(Debug, Arbitrary)]
struct Input {
    source: Vec<u8>,
    offset: u16,
    len: u16,
}

fuzz_target!(|input: Input| {
    let mut out = Vec::new();
    let _ = write_unpadded(&input.source, &mut out, input.offset as usize, input.len as usize);
});
