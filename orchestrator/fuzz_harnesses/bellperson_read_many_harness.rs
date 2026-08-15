#![no_main]
use libfuzzer_sys::fuzz_target;
use bellperson::groth16::Proof;
use blstrs::Bls12;

fuzz_target!(|data: &[u8]| {
    let num_proofs = 1.max(data.len() / Proof::<Bls12>::size());
    if data.len() < num_proofs * Proof::<Bls12>::size() {
        return;
    }
    let _ = Proof::<Bls12>::read_many(data, num_proofs);
});