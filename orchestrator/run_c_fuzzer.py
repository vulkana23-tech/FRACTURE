#!/usr/bin/env python3
"""Corre una campana real de un binario de libFuzzer/C YA COMPILADO
(a diferencia de run_rust_fuzzer.py, ac'a compilar es inherentemente
especifico de cada target -- cada uno de C tiene su propia receta real
de build, ver orchestrator/fuzz_harnesses/*_build.sh, no hay un
"cargo fuzz build" generico para C -- este script solo generaliza la
parte que SI es identica sea cual sea el target: correr el binario,
aislar los logs por corrida, juntar crashes reales).

Mismo bug real ya documentado en run_rust_fuzzer.py (y que aplica
identico ac'a porque es un comportamiento de libFuzzer/compiler-rt, no
de Rust): `-jobs=N -workers=N` escribe fuzz-N.log en el cwd actual del
proceso, sin ser configurable -- se usa el mismo fix (cwd aislado por
corrida via tempfile.mkdtemp).

Uso:
  venv/bin/python3 orchestrator/run_c_fuzzer.py \\
    --binary /opt/fracture/build/fpc_parson/fuzz_parson \\
    --corpus-dir /opt/fracture/build/fpc_parson/corpus \\
    --artifact-dir /opt/fracture/build/fpc_parson/crashes \\
    --duration 2400 --workers 9
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import tempfile

_DONE_RE = re.compile(r"^Done (\d+) runs in \d+ second\(s\)", re.MULTILINE)


def run_c_fuzzer(
    binary: str,
    corpus_dir: str,
    artifact_dir: str,
    duration_seconds: int,
    workers: int,
    extra_asan_options: str = "",
) -> dict:
    if not os.path.isfile(binary):
        raise FileNotFoundError(f"binario no encontrado: {binary} (compilarlo es especifico de cada target, ver build_script del registro)")

    os.makedirs(corpus_dir, exist_ok=True)
    artifact_prefix = artifact_dir.rstrip("/") + os.sep
    os.makedirs(artifact_dir, exist_ok=True)

    isolated_run_dir = tempfile.mkdtemp(prefix=f"fracture_cfuzz_{os.path.basename(binary)}_")

    env = dict(os.environ)
    asan_options = "detect_odr_violation=0"
    # Opt-in por target, nunca global -- un leak YA CONOCIDO y de baja
    # severidad en un target especifico (ver findings/, unmarshal_values)
    # no deberia apagar deteccion de leaks para el resto de los targets
    # de C, que siguen queriendo esa señal real.
    if extra_asan_options:
        asan_options += ":" + extra_asan_options
    env["ASAN_OPTIONS"] = asan_options

    print(f"Corriendo {binary} por {duration_seconds}s ({workers} workers, cwd aislado {isolated_run_dir})...")
    try:
        result = subprocess.run(
            [
                os.path.abspath(binary),
                f"-artifact_prefix={artifact_prefix}",
                f"-max_total_time={duration_seconds}",
                f"-jobs={workers}",
                f"-workers={workers}",
                corpus_dir,
            ],
            cwd=isolated_run_dir,
            env=env,
            capture_output=True,
            text=True,
            # Bug real encontrado en produccion (2026-08-17): cbmpc_bits_convert
            # timeoutea de forma consistente con el margen viejo de +120s.
            # Reproducido en vivo: converter_t::set_error() (codigo real y sin
            # modificar de cb-mpc, src/cbmpc/core/convert.cpp) loguea a stderr
            # en CADA ejecucion que falla el parseo -- con la mayoria de los
            # inputs random de fuzzing fallando el parseo y ~250k execs/seg,
            # eso es un volumen real de I/O (los mismos ~14GB/worker que
            # llenaron el disco, ver el fix de isolated_run_dir mas arriba)
            # que con -jobs=9 -workers=9 en paralelo parece genera contencion
            # de disco real y corre mas alla del +120s viejo. No se toca el
            # codigo real de la libreria (es logging de aplicacion legitimo,
            # solo incompatible con la tasa de ejecuciones de libFuzzer) --
            # se le da mas margen real en vez.
            timeout=duration_seconds + 300,
        )

        total_runs = 0
        per_worker_logs = sorted(glob.glob(os.path.join(isolated_run_dir, "fuzz-*.log")))
        for log_path in per_worker_logs:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            matches = _DONE_RE.findall(content)
            if matches:
                total_runs += int(matches[-1])
        if not per_worker_logs:
            combined = result.stdout + result.stderr
            matches = _DONE_RE.findall(combined)
            if matches:
                total_runs = int(matches[-1])

        crashes = []
        for fname in sorted(os.listdir(artifact_dir)):
            fpath = os.path.join(artifact_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as fh:
                    crashes.append({"file": fname, "bytes": fh.read()})

        outcome = {
            "binary": binary,
            "returncode": result.returncode,
            "total_runs": total_runs,
            "workers": workers,
            "duration_seconds": duration_seconds,
            "crashes": crashes,
            "stderr_tail": result.stderr[-3000:],
            "stdout_tail": result.stdout[-3000:],
        }
        return outcome
    finally:
        # Bug real encontrado en produccion (2026-08-17): si subprocess.run
        # revienta con TimeoutExpired (target que se cuelga mas alla de su
        # presupuesto real), el rmtree de mas abajo nunca se ejecutaba --
        # isolated_run_dir (con los fuzz-N.log de libFuzzer, que pueden
        # crecer a varios GB por worker sin limite) quedaba huerfano para
        # siempre. Esto lleno el disco entero del VPS (194GB en dos
        # corridas huerfanas de cbmpc_bits_convert) y tumbo Redis/Celery
        # de SPECTRE en el mismo host. finally garantiza la limpieza pase
        # lo que pase, timeout incluido.
        shutil.rmtree(isolated_run_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Campana real contra un binario de libFuzzer/C ya compilado")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--corpus-dir", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--duration", type=int, default=2400)
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    parser.add_argument("--extra-asan-options", default="", help="ej. detect_leaks=0 -- opt-in por target, ver docstring de run_c_fuzzer")
    args = parser.parse_args()

    outcome = run_c_fuzzer(args.binary, args.corpus_dir, args.artifact_dir, args.duration, args.workers, args.extra_asan_options)

    print(f"\nTotal de ejecuciones reales: {outcome['total_runs']:,}")
    if outcome["crashes"]:
        print(f"\n⚠️  {len(outcome['crashes'])} crash(es) real(es) en {args.artifact_dir}/:")
        for c in outcome["crashes"]:
            print(f"  - {c['file']} ({len(c['bytes'])} bytes)")
    else:
        print("\nSin crashes en esta corrida.")
        if outcome["returncode"] != 0:
            print("stderr:", outcome["stderr_tail"])


if __name__ == "__main__":
    main()
