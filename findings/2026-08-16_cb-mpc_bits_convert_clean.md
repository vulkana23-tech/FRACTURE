# cb-mpc — `bits_t::convert()` (variante del fix real de buffer overflow) — resultado limpio

**Estado**: campaña real corrida (7.7M ejecuciones en 30s con 4
workers), **sin crash**. Resultado honesto, no un bug.

## Cómo se encontró el candidato

Vía `targets/find_patch_directed_candidates.py`: el commit real
`ec9a818f74` ("fix: Prevent buffer overflow in converter (#54)",
2025-10-09) agregó un chequeo de límites real en `bits_t::convert`
(`src/cbmpc/core/buf.cpp`) -- "Add a bounds check in bits_t::convert
to ensure there is sufficient data in the source buffer before
deserializing". Es la MISMA familia de código (`converter_t`) que este
proyecto ya revisó a mano una vez (ver
`findings/2026-08-13_cb-mpc_converter.md`, resultado limpio en
`convert(std::string&)`/`convert_len`) -- pero `bits_t::convert` es
una función DISTINTA de esa misma familia que no había sido parte de
esa revisión manual.

## El harness

Escrito a mano (`orchestrator/fuzz_harnesses/cbmpc_bits_convert_harness.cpp`)
-- el contexto ya estaba completamente investigado (diff real leído,
firma real de `mem_t`/`converter_t`/`bits_t` confirmada en el header
real), generar con IA hubiera sido más lento que escribirlo directo.
Ejercita la función COMPLETA post-fix con bytes de fuzzer directos:

```c++
coinbase::mem_t src(data, (int)size);
coinbase::converter_t conv(src);
coinbase::bits_t bits;
bits.convert(conv);
```

## Resultado real

Campaña real de 30s, 4 workers: **7,771,518 ejecuciones reales, sin
crash**. El fix real (`converter.at_least(size)` antes del `memmove`)
parece sólido para esta función específica. Registrado como target 25
real del registro (`cbmpc_bits_convert`) para exploración continua de
más tiempo vía el daemon 24/7 -- una campaña corta no descarta un
crash real que necesite más profundidad de cobertura.

## Reachability real (documentada, no repetida de cero)

`converter_t` deserializa mensajes del protocolo MPC -- el propio
código documenta el modelo de amenaza (`MAX_CONVERT_LEN`/
`MAX_CONTAINER_ELEMENTS`, "protect against attacker-controlled
allocations and loops if a malicious peer supplies an oversized length
prefix"), mismo argumento de reachability ya usado en el finding
anterior de `converter_t`.
