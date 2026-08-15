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

- MemorySanitizer no tiene fixture real todavía (haría falta
  recompilar libc++ instrumentada, más esfuerzo del que se justificaba
  en esta ronda) -- el parseo de MSAN reusa el mismo patrón que ASAN
  (`ERROR: MemorySanitizer: <tipo>`), pero sin un fixture real
  corriendo no hay confirmación en vivo de que el formato coincida
  100%.
- LeakSanitizer tampoco tiene fixture real -- mismo motivo.
