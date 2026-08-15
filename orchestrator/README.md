# orchestrator/

Corridas de fuzzing 24/7 en paralelo (18 cores disponibles en este
VPS), gestión de corpus persistente, rotación de objetivos.

## Estado real (2026-08-15)

Implementado y probado en vivo:

- `run_rust_fuzzer.py` / `run_go_fuzzer.py` — corren UNA campaña
  puntual contra un target ya preparado (compilan, ejecutan, devuelven
  runs/crashes reales). Ya existían antes de esta ronda.
- `scheduler.py` — la pieza que faltaba: loop real de sweeps sobre
  `targets.json` (15 targets reales: 8 Rust vía cargo-fuzz, 7 Go vía
  `go test -fuzz`), con:
  - **Concurrencia acotada a los cores reales** (`--max-concurrent`,
    default 2 targets a la vez con `cores/max_concurrent` workers c/u
    — evita repartir 18 cores en migajas entre muchos targets a la
    vez).
  - **Corpus persistente — ya lo resuelve cada engine, confirmado en
    vivo, no hacía falta tocar nada**: Rust guarda en
    `<crate>/fuzz/corpus/<target>/` (directorio real, no un tmpdir);
    Go usa su cache nativa (`$GOCACHE/fuzz/<import path>/`,
    confirmado con `go env GOCACHE` que ya tenía entradas de corridas
    de sesiones anteriores) — sobrevive aunque `run_go_fuzzer.py`
    borre el clon temporal del repo al terminar, porque el corpus
    real nunca vivió ahí.
  - **Rotación real**: parsea `cov:` (Rust, de la línea `DONE` de
    libFuzzer) o `new interesting:` (Go, del reporter nativo) por
    ciclo. Un target sin cobertura nueva en 3 ciclos seguidos queda
    "estancado" y corre 1 de cada 3 sweeps en vez de todas — nunca se
    excluye del todo (no hay garantía real de que "estancado ahora"
    signifique "agotado para siempre").
  - **Resiliente**: una excepción en un target (build roto, timeout,
    repo caído) se loguea y el resto de la sweep sigue — probado
    forzando el escenario, no solo leído en el código.
  - **Alertas a disco** en `orchestrator/alerts/<target_id>/<ts>/` con
    los bytes/contenido real del crash + `summary.json`, e índice en
    `orchestrator/alerts/ALERTS.md` — el punto de entrada real para
    `triage/` (todavía sin terminar, ver roadmap) o revisión manual.
  - Registro (`targets.json`) con escritura atómica (`.tmp` +
    `os.replace`) para no corromper el estado de TODOS los targets si
    el proceso muere a mitad de un guardado.

- `fracture-orchestrator.service` (systemd, `/etc/systemd/system/`) —
  `Restart=always`, sobrevive reboots igual que el resto de los
  servicios de este VPS. `Nice=10` + ioprio best-effort a propósito:
  este mismo VPS corre SPECTRE contra targets web en vivo, fuzzing es
  100% CPU-bound y no debería robarle prioridad a eso.

Probado en vivo (no solo leído): sweep real de 4 targets (2 Rust + 2
Go) con concurrencia 2, ciclos de 20s — confirmó ejecuciones reales
contadas (1.9M/83M runs), parseo de cobertura real, y el mecanismo de
alerta de crash con un crash sintético inyectado a mano (bytes
preservados, `summary.json` + `ALERTS.md` generados correctamente). La
lógica de rotación por estancamiento también se validó por separado
(4 sweeps simuladas, target estancado corrió en la sweep #3 como se
esperaba, no en 1/2/4).

## Uso

```
# modo real, 24/7 (lo que corre el systemd service):
venv/bin/python3 orchestrator/scheduler.py --cycle-duration 2400 --max-concurrent 2

# prueba corta, una sola sweep:
venv/bin/python3 orchestrator/scheduler.py --cycle-duration 30 --max-concurrent 3 --sweeps 1

# como servicio real:
systemctl enable --now fracture-orchestrator
journalctl -u fracture-orchestrator -f
```

## Lo que falta (honesto)

- El total de ejecuciones para targets Go queda en 0 en el registro —
  a diferencia de Rust, `go test -fuzz` no imprime un contador de runs
  simple y estable en stdout entre versiones de Go; se podría instrumentar
  parseando `execs: N` de las líneas `fuzz: elapsed:...`, no se hizo
  todavía porque no bloquea nada funcional (el resto del estado sí es
  real).
- La detección de "estancado" es una heurística simple (cobertura
  plana N ciclos seguidos) — no sabe distinguir "este target ya no da
  más" de "esta seed particular tuvo mala suerte 3 veces seguidas".
  Suficiente para no gastar los mismos cores infinitamente en algo
  chato, no es ciencia exacta.
