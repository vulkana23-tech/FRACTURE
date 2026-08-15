#![no_main]
use libfuzzer_sys::fuzz_target;

use wsts::curve::scalar::Scalar;

// Mismo criterio que point_from_bytes.rs, para el otro lado del
// pipeline: wsts/src/state_machine/signer/mod.rs:859 hace
// `Scalar::try_from(&plain[..])` sobre bytes ya DESENCRIPTADOS de un
// DKG private share recibido de otro signer -- si ese signer es
// malicioso (o el share esta corrupto), el contenido desencriptado es
// arbitrario antes de llegar a este parseo.
fuzz_target!(|data: &[u8]| {
    let _ = Scalar::try_from(data);
});
