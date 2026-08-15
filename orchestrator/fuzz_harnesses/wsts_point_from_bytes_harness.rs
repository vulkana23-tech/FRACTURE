#![no_main]
use libfuzzer_sys::fuzz_target;

use wsts::curve::point::{Compressed, Point};

// wsts::curve = p256k1 (re-exportado directo en wsts/src/lib.rs). Este
// es el pipeline real bytes->punto de curva que wsts usa en todo el
// protocolo para parsear claves publicas/commitments que llegan de
// OTROS participantes (ver
// wsts/src/state_machine/signer/mod.rs:754 y :850,
// `Point::try_from(&compressed)` sobre bytes de mensajes de red).
//
// `Point::try_from(&Compressed)` (p256k1 crate, point.rs) hace el
// parseo real dentro de un bloque `unsafe`, llamando funciones
// INTERNAS de libsecp256k1 (secp256k1_fe_set_b32,
// secp256k1_ge_set_xo_var -- no son parte de la API publica estable de
// libsecp256k1) con structs armados a mano en el stack. Al ser API
// interna via bindings propios, es mucho menos probable que estas
// rutas especificas ya esten cubiertas por el fuzzing propio de
// bitcoin-core/OSS-Fuzz sobre libsecp256k1 (que apunta a la API
// publica). Compressed::try_from no valida el contenido en absoluto,
// solo la longitud (33 bytes) -- todo el trabajo de validacion real
// pasa a Point::try_from.
fuzz_target!(|data: &[u8]| {
    if data.len() != 33 {
        return;
    }

    if let Ok(compressed) = Compressed::try_from(data) {
        let _ = Point::try_from(&compressed);
    }
});
