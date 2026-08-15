#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use blstrs::Scalar as Fr;
use ff::PrimeField;
use generic_array::typenum::U2;
use neptune::poseidon::{Poseidon, PoseidonConstants};

// PoseidonConstants::new() recalcula las round constants/matriz MDS
// desde cero (no es gratis) -- memoizado con OnceLock para que el
// costo se pague una sola vez por proceso, no en cada ejecucion del
// fuzzer. Sin esto el smoke test daba ~180 exec/s con RSS creciendo
// sin limite (cada iteracion alocaba una matriz nueva) -- con el fix
// el costo por iteracion es solo el hash en si.
static CONSTANTS: OnceLock<PoseidonConstants<Fr, U2>> = OnceLock::new();

// neptune::poseidon::Poseidon::hash() -- el permutation/hash de
// Poseidon real que usa Filecoin (sobre BLS12-381) en varios de sus
// circuitos ZK. A diferencia de los targets anteriores (parsear bytes
// no confiables en un tipo), esto testea otra invariante: Poseidon,
// como funcion hash, NUNCA deberia entrar en panic para NINGUN
// elemento de campo VALIDO de la aridad correcta -- no es un parser
// que deba rechazar input invalido, cualquier Fr valido es un input
// legitimo (ej. un leaf de un Merkle tree armado a partir de datos de
// un sector, datos que en la practica puede influenciar quien sea
// due;o de esos datos). En scope real de Immunefi
// (`filecoin-project` -> `lurk-lab/neptune`, listado en el asset de
// Filecoin, Critical $25k-$50k).
//
// bytes -> intento de Fr valido via `PrimeField::from_repr` (CtOption,
// rechaza de forma segura cualquier codificacion >= modulo, sin
// panic) -- solo se llama a Poseidon::hash() si ambos elementos del
// preimage (aridad U2, la default del crate) se decodificaron bien.
// El campo escalar de BLS12-381 es de ~255 bits (el modulo esta entre
// 2^254 y 2^253), asi que una fraccion real (no despreciable) de
// bytes aleatorios de 32 bytes ya caen dentro del campo sin necesitar
// diccionario/corpus especial.
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let mut repr_a = <Fr as PrimeField>::Repr::default();
    repr_a.as_mut().copy_from_slice(&data[0..32]);
    let a = match Option::<Fr>::from(Fr::from_repr(repr_a)) {
        Some(f) => f,
        None => return,
    };

    let mut repr_b = <Fr as PrimeField>::Repr::default();
    repr_b.as_mut().copy_from_slice(&data[32..64]);
    let b = match Option::<Fr>::from(Fr::from_repr(repr_b)) {
        Some(f) => f,
        None => return,
    };

    let constants = CONSTANTS.get_or_init(PoseidonConstants::<Fr, U2>::new);
    let mut poseidon = Poseidon::<Fr, U2>::new_with_preimage(&[a, b], constants);
    let _ = poseidon.hash();
});
