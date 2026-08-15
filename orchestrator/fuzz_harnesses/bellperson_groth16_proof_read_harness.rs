#![no_main]
use libfuzzer_sys::fuzz_target;

use bellperson::groth16::Proof;
use blstrs::Bls12;

// bellperson::groth16::Proof::<Bls12>::read() -- el parseo real de un
// proof Groth16 (A: G1, B: G2, C: G1 sobre BLS12-381, la curva real
// que usa Filecoin) que cualquier verificador invoca sobre bytes
// enviados por un prover NO CONFIABLE. En scope real de Immunefi
// (`filecoin-project/bellperson`, listado a mano en los assets DLT de
// Filecoin, Critical $25k-$50k).
//
// La funcion real (src/groth16/proof.rs) decodifica cada punto via
// `GroupEncoding::from_bytes` (blstrs/blst -- blst es C real de
// supranational, bien auditado, pero el codigo de bellperson ALREDEDOR
// de esa llamada -- el manejo de offsets/tamanos fijos, el chequeo de
// "not on curve"/"point at infinity" propio -- es codigo de bellperson,
// no de blst) y rechaza explicitamente puntos invalidos o en el
// infinito. `Proof::read` exige exactamente `Self::size()` bytes
// (2*G1_comprimido + G2_comprimido = 2*48 + 96 = 192 bytes para
// BLS12-381) -- se deja que sea el propio fuzzer quien explore
// longitudes invalidas ademas de contenido invalido, sin forzar el
// tamano de antemano en el harness.
fuzz_target!(|data: &[u8]| {
    let _ = Proof::<Bls12>::read(data);
});
