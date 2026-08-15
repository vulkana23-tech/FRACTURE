#![no_main]
use libfuzzer_sys::fuzz_target;
use tofn::ed25519;

// Mismo criterio que verify_ecdsa.rs, pero para el otro esquema de firma
// que expone tofn (ed25519_dalek::VerifyingKey::from_bytes +
// Signature::from_slice, ambos con bytes no confiables). Immunefi lista
// todo tofn/src, no solo ecdsa/mod.rs, asi que esto tambien es scope real.
//
// Layout del input: primeros 32 bytes -> encoded_verifying_key,
// siguientes 32 bytes -> message_digest, resto -> encoded_signature
// (64 bytes raw R||S segun RFC 8032, pero se deja libre para que el
// fuzzer explore longitudes invalidas tambien).
fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 32 {
        return;
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[0..32]);

    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&data[32..64]);
    let digest = digest_bytes.into();

    let sig = &data[64..];

    let _ = ed25519::verify(&pubkey, &digest, sig);
});
