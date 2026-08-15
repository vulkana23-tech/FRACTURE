# triage/

Clasificación de crashes: dedup por stack hash, análisis de salida de
sanitizers (ASAN/UBSAN/MSAN) para separar severidad real de ruido,
antes de que un humano revise nada.

## Estado real (2026-08-15)

- `classify_go_panic.py` — clasifica panics de `go test -fuzz` (ya
  existía).
- `classify_sanitizer_crash.py` — la pieza que faltaba: ASAN, UBSAN,
  MemorySanitizer, LeakSanitizer y panics de Rust (cargo-fuzz), mismo
  criterio que el de Go (filtra frames de plomeria del
  sanitizer/libc/std, hash de dedup a partir de tipo de bug + frames
  reales, nunca de direcciones de memoria crudas porque ASLR las
  cambia entre corridas del MISMO bug).
- `triage_alerts.py` — conecta lo anterior con
  `orchestrator/alerts/` (lo que escribe `scheduler.py` en cuanto hay
  un crash real): clasifica cada alerta sin triar, escribe
  `triage.json` al lado, y mantiene `dedup_index.json` para no contar
  el mismo bug reportado 50 veces como 50 hallazgos.

Todos los fixtures de test en `testdata/` son capturas reales -- se
compilaron y corrieron binarios de verdad con
`clang -fsanitize=address|undefined` y `rustc` hasta crashear, no texto
escrito a mano. Un hallazgo real saliendo de armar estos fixtures:
`clang -O0` sin darle un argumento no-constante convierte un
`memcpy` con string literal en `global-buffer-overflow` en vez de
`heap-buffer-overflow` (el compilador mueve el string a un global) --
el fixture real usa `argv[0]` para forzar el heap real.

**Limitación real, no un bug**: un `abort()`/SIGSEGV sin sanitizer
encima puede no dejar NINGÚN texto reconocible en la salida capturada
(`Aborted (core dumped)` es un mensaje del *job control de una shell
interactiva*, nunca aparece en lo que `subprocess.run()` captura de un
proceso hijo real -- confirmado generando ese fixture exacto).
`extract_crash_info()` por eso acepta un `returncode` opcional: sin
texto reconocible pero con exit code != 0, igual se marca
`needs_review` en vez de perderse como si fuera una corrida limpia.
`scheduler.py` ya guarda el returncode real en `summary.json` para
esto.

## Uso

```
venv/bin/python3 triage/triage_alerts.py
# corridas de prueba con otro directorio de alertas:
venv/bin/python3 triage/triage_alerts.py --alerts-dir /ruta --dedup-index /ruta/dedup_index.json

venv/bin/python3 -m pytest triage/ -v
```

`orchestrator/scheduler.py` ya llama a `triage_all()` al final de cada
sweep (import directo, mismo patrón de resiliencia que el resto del
scheduler -- si triage/ se rompe, se loguea y el fuzzing sigue, no se
cae todo el proceso). Un humano abriendo `orchestrator/alerts/` ya
encuentra `triage.json` al lado de cada alerta, no solo los bytes
crudos del crash.

## Lo que falta (honesto)

- ~~MemorySanitizer no tiene fixture real todavía~~ **cerrado
  (2026-08-15), y encontró un bug real en el camino**: resultó NO
  hacer falta recompilar libc++ instrumentada (el uso sin inicializar
  real que se encontró es sobre un array local, no algo dentro de la
  STL) -- pero el fixture real reveló que MemorySanitizer imprime
  **`WARNING: MemorySanitizer: ...`** por default, nunca `ERROR:`
  (confirmado además que `MSAN_OPTIONS=halt_on_error=1` NO cambia el
  prefijo, solo si el proceso aborta después). El código viejo solo
  reconocía `ERROR:` -- cualquier hallazgo real de MSan se hubiera
  perdido en silencio (`extract_crash_info` devolvía `None`, indistinguible
  de una corrida limpia) hasta que se generó este fixture y se probó
  de verdad. Corregido, con test de regresión real
  (`msan_base64_decode_uninitialized_real.txt`, capturado compilando
  `common/base64/base64.cpp` con `-fsanitize=memory` de verdad contra
  el uso sin inicializar ya anotado en
  `findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md`).
- ~~LeakSanitizer tampoco tiene fixture real~~ **cerrado (2026-08-15)**:
  el leak real de `fpc_unmarshal_values` (ver
  `findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md`)
  dio un fixture real (`lsan_unmarshal_values_leak_real.txt`) --
  confirmó severidad `low` (leak real, no corrupción de memoria) y
  extracción correcta de frames.
