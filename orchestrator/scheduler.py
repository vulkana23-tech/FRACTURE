#!/usr/bin/env python3
"""Orquestador real: loop 24/7 sin supervision sobre orchestrator/targets.json.

Antes de esto, orchestrator/ tenia dos scripts que corren UNA campana
puntual (run_rust_fuzzer.py, run_go_fuzzer.py) pero nada que decida
CUANDO correr que, ni que trackee progreso entre corridas, ni que
sobreviva un reboot. Este modulo es esa capa -- reusa esos dos scripts
tal cual estan (import directo de sus funciones, no reimplementa nada
de compilacion/ejecucion), y agrega:

  - Un registro persistente (targets.json) con el estado real de cada
    target: ejecuciones acumuladas, ultima corrida, ultimo crash,
    señal de "cobertura estancada".
  - Concurrencia acotada a los cores reales del VPS (--max-concurrent
    targets a la vez, cada uno con cores/max_concurrent workers).
  - Rotacion real: un target cuya cobertura no crecio en las ultimas
    _PLATEAU_CYCLES corridas se sigue fuzzeando (fuzzing con mas tiempo
    SI puede seguir encontrando cosas -- no hay garantia real de que
    "estancado" signifique "agotado"), pero con 1/3 de la frecuencia
    de un target que todavia esta dando señal nueva, para no gastar
    los mismos cores en algo que ya dejo de rendir tanto como en algo
    que recien empezo.
  - Resiliencia real: una excepcion en UN target (build roto, timeout,
    repo caido) se loguea y el resto de la sweep sigue -- un solo
    target roto no puede tirar abajo un proceso pensado para correr
    sin supervision.
  - Alertas a disco apenas hay un crash real (orchestrator/alerts/),
    y triage automatico al final de cada sweep (triage/triage_alerts.py)
    -- para cuando un humano abre orchestrator/alerts/ALERTS.md, cada
    alerta ya tiene su triage.json (severidad real + dedup) al lado,
    no solo los bytes crudos del crash.

Uso:
  venv/bin/python3 orchestrator/scheduler.py \\
    --cycle-duration 2400 --max-concurrent 2 --sweeps 0   # 0 = infinito

  # corrida de prueba corta, una sola sweep:
  venv/bin/python3 orchestrator/scheduler.py \\
    --cycle-duration 30 --max-concurrent 3 --sweeps 1
"""

import argparse
import json
import logging
import os
import re
import shutil
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_rust_fuzzer import run_rust_fuzzer  # noqa: E402
from run_go_fuzzer import run_go_fuzzer  # noqa: E402
from run_c_fuzzer import run_c_fuzzer  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "triage"))
from triage_alerts import triage_all  # noqa: E402

_ROOT = os.path.dirname(os.path.abspath(__file__))
_REGISTRY_PATH = os.path.join(_ROOT, "targets.json")
_ALERTS_DIR = os.path.join(_ROOT, "alerts")
_LOG_PATH = os.path.join(_ROOT, "scheduler.log")

# Cuantas sweeps seguidas sin cobertura nueva antes de considerar un
# target "estancado" (baja su frecuencia, nunca lo saca del todo --
# ver docstring del modulo).
_PLATEAU_CYCLES = 3
# De cada 3 sweeps, un target estancado corre solo 1 -- las otras 2 se
# saltan (sweep_number % 3 != 0).
_PLATEAU_SKIP_MODULO = 3

_RUST_COV_RE = re.compile(r"cov:\s*(\d+)")
_GO_NEW_INTERESTING_RE = re.compile(r"new interesting:\s*(\d+)")

_shutdown_requested = False


def _handle_shutdown(signum, frame):
    global _shutdown_requested
    logging.info("Señal %s recibida -- termino la sweep actual y salgo (no arranco una nueva).", signum)
    _shutdown_requested = True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _setup_logging() -> None:
    handlers = [logging.StreamHandler(sys.stdout), logging.FileHandler(_LOG_PATH)]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


def load_registry(path: str = _REGISTRY_PATH) -> list:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_registry(targets: list, path: str = _REGISTRY_PATH) -> None:
    # Escritura atomica -- si el proceso muere a mitad de un dump directo
    # al archivo real, el registro queda corrupto y se pierde estado de
    # TODOS los targets, no solo del que se estaba actualizando.
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(targets, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp_path, path)


def _parse_rust_coverage(outcome: dict) -> "int | None":
    text = outcome.get("stderr_tail", "") or ""
    matches = _RUST_COV_RE.findall(text)
    return int(matches[-1]) if matches else None


def _parse_go_new_interesting(outcome: dict) -> "int | None":
    text = (outcome.get("stdout_tail", "") or "") + (outcome.get("stderr_tail", "") or "")
    matches = _GO_NEW_INTERESTING_RE.findall(text)
    if not matches:
        return None
    return sum(int(m) for m in matches)


def _write_alert(target: dict, outcome: dict, crashes: list) -> None:
    os.makedirs(_ALERTS_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    alert_dir = os.path.join(_ALERTS_DIR, target["id"], ts)
    os.makedirs(alert_dir, exist_ok=True)

    saved_files = []
    for c in crashes:
        fname = c.get("file", "crash")
        fpath = os.path.join(alert_dir, fname)
        if "bytes" in c:
            with open(fpath, "wb") as fh:
                fh.write(c["bytes"])
        else:
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(c.get("content", ""))
        saved_files.append(fname)

    # Texto crudo (stderr para Rust -- ahi vive el reporte real de ASAN;
    # stdout para Go -- ahi vive el panic real) -- sin esto triage/ no
    # tiene nada que parsear, solo los bytes crudos del input que
    # crasheo, no el reporte del sanitizer/panic en si.
    raw_output = (outcome.get("stderr_tail", "") or "") + (outcome.get("stdout_tail", "") or "")
    if raw_output.strip():
        with open(os.path.join(alert_dir, "raw_output.txt"), "w", encoding="utf-8") as fh:
            fh.write(raw_output)

    summary = {
        "target_id": target["id"],
        "engine": target["engine"],
        "detected_at": ts,
        "crash_files": saved_files,
        "known_finding_target": target.get("known_finding", False),
        # triage/triage_alerts.py lo necesita: un abort/SEGV real puede
        # no dejar NINGUN texto reconocible en raw_output.txt (ver
        # docstring de extract_crash_info en classify_sanitizer_crash.py)
        # -- sin el returncode, ese caso es indistinguible de una
        # corrida limpia.
        "returncode": outcome.get("returncode"),
    }
    with open(os.path.join(alert_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    index_path = os.path.join(_ALERTS_DIR, "ALERTS.md")
    is_new = not os.path.exists(index_path)
    with open(index_path, "a", encoding="utf-8") as fh:
        if is_new:
            fh.write("# Alertas de crash reales (sin triar todavia)\n\n"
                      "Cada linea es una corrida real que termino con al menos\n"
                      "un crash. `triage/` (ver tarea pendiente en el roadmap)\n"
                      "todavia no clasifica esto automaticamente -- revision\n"
                      "manual por ahora, igual que los hallazgos ya confirmados\n"
                      "en findings/.\n\n")
        fh.write(f"- {ts} `{target['id']}` ({target['engine']}) -- "
                 f"{len(saved_files)} archivo(s) en `alerts/{target['id']}/{ts}/`\n")

    logging.warning("⚠️  CRASH real en %s -- %d archivo(s) guardados en %s",
                     target["id"], len(saved_files), alert_dir)


def _is_plateaued(state: dict) -> bool:
    return state.get("plateau_streak", 0) >= _PLATEAU_CYCLES


def run_one_cycle(target: dict, duration_seconds: int, workers: int) -> dict:
    """Corre UNA campana real para un target y devuelve el outcome crudo
    del runner correspondiente (run_rust_fuzzer/run_go_fuzzer) -- no
    actualiza el registro, eso lo hace el caller (mas facil de testear
    cada mitad por separado).

    Bug real encontrado en produccion (2026-08-15, primer arranque bajo
    systemd): `go test -fuzz` sin $HOME seteado falla instantaneo
    ("module cache not found: neither GOMODCACHE nor GOPATH is set",
    returncode 1) -- pero run_go_fuzzer.py devuelve igual un outcome
    valido con crashes=[] (nunca llego a fuzzear, no es que fuzzeo y no
    encontro nada). Sin este chequeo, el scheduler lo contaba como un
    ciclo limpio real -- silenciosamente no fuzzeaba nada y lo reportaba
    como si hubiera funcionado. Igual aplica a Rust en teoria (build
    fallido ya levanta excepcion antes de esto, pero un binario que
    aborta antes de arrancar libFuzzer con returncode!=0 y sin crashes
    seria el mismo caso)."""
    if target["engine"] == "rust":
        outcome = run_rust_fuzzer(
            crate_dir=target["crate_dir"],
            target=target["target"],
            duration_seconds=duration_seconds,
            workers=workers,
        )
    elif target["engine"] == "go":
        outcome = run_go_fuzzer(
            repo_url=target["repo"],
            package_path=target["package_path"],
            fuzz_test_file=target["fuzz_test_file"],
            fuzz_func=target["fuzz_func"],
            duration_seconds=duration_seconds,
            parallel=workers,
        )
    elif target["engine"] == "c":
        outcome = run_c_fuzzer(
            binary=target["binary"],
            corpus_dir=target["corpus_dir"],
            artifact_dir=target["artifact_dir"],
            duration_seconds=duration_seconds,
            workers=workers,
            extra_asan_options=target.get("extra_asan_options", ""),
        )
    else:
        raise ValueError(f"engine desconocido: {target['engine']!r}")

    if outcome.get("returncode", 0) != 0 and not outcome.get("crashes"):
        raise RuntimeError(
            f"returncode={outcome.get('returncode')} sin crashes -- no fuzzeo de verdad, "
            f"fallo antes de arrancar. stderr: {outcome.get('stderr_tail', '')[-500:]}"
        )
    return outcome


def _update_state_after_cycle(target: dict, outcome: dict) -> None:
    state = target.setdefault("state", {})
    state["cycles_completed"] = state.get("cycles_completed", 0) + 1
    state["last_cycle_at"] = _now_iso()

    if target["engine"] in ("rust", "c"):
        # Mismo runtime de libFuzzer para ambos (compiler-rt) -- el
        # formato de las lineas "cov:"/"Done N runs" es identico sea
        # cual sea el lenguaje que se compilo, no es especifico de Rust.
        total_runs = outcome.get("total_runs", 0)
        cov = _parse_rust_coverage(outcome)
        prev_cov = state.get("last_cov")
        if cov is not None and prev_cov is not None and cov <= prev_cov:
            state["plateau_streak"] = state.get("plateau_streak", 0) + 1
        elif cov is not None:
            state["plateau_streak"] = 0
        if cov is not None:
            state["last_cov"] = cov
        crashes = outcome.get("crashes", [])
    else:  # go
        total_runs = 0  # go test -fuzz no reporta un total de execs simple y estable en stdout
        new_interesting = _parse_go_new_interesting(outcome)
        if new_interesting is not None and new_interesting == 0:
            state["plateau_streak"] = state.get("plateau_streak", 0) + 1
        elif new_interesting is not None:
            state["plateau_streak"] = 0
        crashes = outcome.get("crashes", [])

    state["lifetime_runs"] = state.get("lifetime_runs", 0) + total_runs

    if crashes:
        state["last_crash_at"] = _now_iso()
        state["known_crash_count"] = state.get("known_crash_count", 0) + len(crashes)
        _write_alert(target, outcome, crashes)
    state["plateaued"] = _is_plateaued(state)


def _run_target_safely(target: dict, duration_seconds: int, workers: int) -> None:
    logging.info("-> arrancando %s (%s, %ds, %d workers)",
                 target["id"], target["engine"], duration_seconds, workers)
    try:
        outcome = run_one_cycle(target, duration_seconds, workers)
    except Exception as exc:  # noqa: BLE001 -- resiliencia real: un target roto no puede tirar la sweep
        logging.error("Target %s fallo esta sweep (%s: %s) -- sigo con el resto.",
                      target["id"], type(exc).__name__, exc)
        state = target.setdefault("state", {})
        state["last_error"] = f"{type(exc).__name__}: {exc}"
        state["last_error_at"] = _now_iso()
        return
    _update_state_after_cycle(target, outcome)
    n_crashes = len(outcome.get("crashes", []))
    logging.info("<- %s terminado (crashes=%d, plateau_streak=%d)",
                 target["id"], n_crashes, target["state"].get("plateau_streak", 0))


def run_sweep(targets: list, sweep_number: int, duration_seconds: int,
              max_concurrent: int, cores: int) -> None:
    workers = max(1, cores // max_concurrent)
    scheduled = []
    for t in targets:
        state = t.get("state", {})
        if _is_plateaued(state) and sweep_number % _PLATEAU_SKIP_MODULO != 0:
            logging.info("Salteo %s esta sweep (estancado, corre 1 de cada %d sweeps)",
                         t["id"], _PLATEAU_SKIP_MODULO)
            continue
        scheduled.append(t)

    logging.info("=== Sweep #%d: %d/%d targets, %d en paralelo, %d workers c/u, %ds c/u ===",
                 sweep_number, len(scheduled), len(targets), max_concurrent, workers, duration_seconds)

    with ThreadPoolExecutor(max_workers=max_concurrent) as pool:
        futures = {pool.submit(_run_target_safely, t, duration_seconds, workers): t for t in scheduled}
        for fut in as_completed(futures):
            fut.result()  # _run_target_safely ya atrapa sus propias excepciones -- esto solo re-lanza bugs del scheduler mismo


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", default=_REGISTRY_PATH)
    parser.add_argument("--cycle-duration", type=int, default=2400, help="segundos de fuzzing por target por sweep (default 2400 = 40min)")
    parser.add_argument("--max-concurrent", type=int, default=2, help="targets corriendo en paralelo (default 2)")
    parser.add_argument("--cores", type=int, default=os.cpu_count() or 18)
    parser.add_argument("--sweeps", type=int, default=0, help="cuantas sweeps completas correr (0 = infinito, 24/7)")
    parser.add_argument("--sweep-pause", type=int, default=10, help="segundos de pausa entre sweeps")
    args = parser.parse_args()

    _setup_logging()
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    targets = load_registry(args.registry)
    logging.info("Registro cargado: %d targets (%s)", len(targets), args.registry)

    sweep_number = 0
    while not _shutdown_requested:
        sweep_number += 1
        run_sweep(targets, sweep_number, args.cycle_duration, args.max_concurrent, args.cores)
        save_registry(targets, args.registry)
        logging.info("Sweep #%d guardada en %s", sweep_number, args.registry)

        try:
            triage_stats = triage_all()
            if triage_stats["newly_triaged"]:
                logging.info(
                    "Triage: %d alerta(s) nueva(s) clasificada(s), %d bug(s) unico(s) nuevo(s).",
                    triage_stats["newly_triaged"], triage_stats["new_unique_bugs"],
                )
        except Exception as exc:  # noqa: BLE001 -- triage roto no puede tirar abajo el fuzzing en si
            logging.error("triage_all() fallo esta sweep (%s: %s) -- sigo, las alertas quedan sin triar.",
                          type(exc).__name__, exc)

        if args.sweeps and sweep_number >= args.sweeps:
            logging.info("Llegue a --sweeps %d, corto (no es el modo 24/7).", args.sweeps)
            break
        if _shutdown_requested:
            break
        time.sleep(args.sweep_pause)

    logging.info("Orquestador terminado (sweeps completas: %d).", sweep_number)


if __name__ == "__main__":
    main()
