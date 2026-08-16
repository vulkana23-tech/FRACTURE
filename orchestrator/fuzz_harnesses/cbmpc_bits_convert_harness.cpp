// Harness real de libFuzzer para bits_t::convert() (coinbase/cb-mpc,
// src/cbmpc/core/buf.cpp) -- el commit real ec9a818f74 ("fix: Prevent
// buffer overflow in converter (#54)") agrego un chequeo de limites
// justo antes del memmove real del lado de lectura de esta funcion
// ("Add a bounds check in bits_t::convert to ensure there is
// sufficient data in the source buffer before deserializing"). Este
// harness ejercita la funcion COMPLETA post-fix (convert_len real +
// el memmove real) con bytes de fuzzer directos -- variante/regresion
// real sobre la misma familia de bug que este proyecto ya encontro y
// documento a mano en converter_t (ver findings/2026-08-13_cb-mpc_converter.md).
//
// Reachability real: converter_t deserializa mensajes del protocolo
// MPC -- el propio codigo documenta el modelo de amenaza
// (MAX_CONVERT_LEN/MAX_CONTAINER_ELEMENTS "protect against
// attacker-controlled allocations... if a malicious peer supplies an
// oversized length prefix").
#include <cbmpc/core/buf.h>
#include <cbmpc/internal/core/convert.h>
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0x7fffffff) return 0;
    coinbase::mem_t src(data, (int)size);
    coinbase::converter_t conv(src);
    coinbase::bits_t bits;
    bits.convert(conv);
    return 0;
}
