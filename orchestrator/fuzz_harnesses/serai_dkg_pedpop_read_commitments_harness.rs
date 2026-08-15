#![no_main]
use libfuzzer_sys::fuzz_target;

use dalek_ff_group::Ristretto;
use dkg_pedpop::{fuzz_read_commitments, Participant, ThresholdParams};

// dkg-pedpop::Commitments::read() (via el shim fuzz_read_commitments,
// ver lib.rs -- el metodo real esta detras de un trait sellado no
// invocable desde afuera del crate) -- el mensaje de "commitments" que
// PedPoP (protocolo real de DKG que usa Serai hoy, a diferencia del
// GG20 ya removido de axelarnetwork/tofn) espera recibir de CUALQUIER
// otro participante durante la ronda 1. El propio doc-comment de la
// struct en pedpop/src/lib.rs lo dice explicito: "If any participant
// sends multiple sets of commitments, they are faulty and should be
// presumed malicious" -- el modelo de amenaza de esta libreria YA
// asume participantes maliciosos enviando mensajes crafteados,
// exactamente el escenario que fuzzing simula. En scope real de
// Immunefi (crypto/dkg/src listado a mano en los assets de Serai).
//
// Params de threshold fijos (t=2, n=3, nosotros=participante 1) -- no
// son bytes que lleguen por red en esta firma, son config local del
// que recibe. Todo el input del fuzzer va al reader (el mensaje en si).
fuzz_target!(|data: &[u8]| {
    let params = match ThresholdParams::new(2, 3, Participant::new(1).unwrap()) {
        Ok(p) => p,
        Err(_) => return,
    };

    let _ = fuzz_read_commitments::<Ristretto>(data, params);
});
