#![no_main]
use libfuzzer_sys::fuzz_target;
use tofn::ecdsa;

// tofn::ecdsa::verify() -- en scope explicito del programa de Immunefi de
// Axelar Network (tofn/blob/main/src/ecdsa/mod.rs). Toma DOS buffers de
// bytes 100% controlados por quien llama: una clave publica SEC1-encoded
// (33 bytes fijos) y una firma ASN.1 DER (longitud variable) -- ambos
// decodificados por codigo propio de la crate (k256_serde::ProjectivePoint,
// via k256::EncodedPoint) antes de llegar a la libreria k256 bien auditada.
// No hace falta reachability adicional para justificar esto: es API publica
// de una libreria de firmas standalone, cualquier consumidor externo de
// tofn (no solo tofnd) puede invocarla con datos no confiables.
//
// Layout del input: primeros 33 bytes -> encoded_verifying_key,
// siguientes 32 bytes -> message_digest, resto -> encoded_signature (DER).
fuzz_target!(|data: &[u8]| {
    if data.len() < 33 + 32 {
        return;
    }

    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&data[0..33]);

    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&data[33..65]);
    let digest = digest_bytes.into();

    let sig = &data[65..];

    let _ = ecdsa::verify(&pubkey, &digest, sig);
});
