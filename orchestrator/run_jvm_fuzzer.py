#!/usr/bin/env python3
"""Corre una campana real de Jazzer (fuzzing JVM/Java) contra una clase
de target YA COMPILADA -- mismo patron que run_c_fuzzer.py: compilar
(via Gradle/Maven real del proyecto) es especifico de cada target, ver
build/jvm_targets/<target>/ para la receta real de cada uno, esto solo
orquesta la CORRIDA contra clases + classpath ya preparados.

Uso:
  venv/bin/python3 orchestrator/run_jvm_fuzzer.py \\
    --classes-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/classes \\
    --lib-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/lib \\
    --target-class FuzzParseAttributes \\
    --corpus-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/corpus \\
    --artifact-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/crashes \\
    --duration 2400
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import tempfile

_DONE_RE = re.compile(r"^Done (\d+) runs in \d+ second\(s\)", re.MULTILINE)
# Jazzer envuelve libFuzzer -- mismo formato real de stats que run_c_fuzzer.py/
# run_rust_fuzzer.py ya parsean, se reusa el mismo regex.


def run_jvm_fuzzer(
    classes_dir: str,
    lib_dir: str,
    target_class: str,
    corpus_dir: str,
    artifact_dir: str,
    duration_seconds: int,
    workers: int,
) -> dict:
    if not os.path.isdir(classes_dir):
        raise FileNotFoundError(f"classes-dir no encontrado: {classes_dir} (compilar es especifico de cada target)")

    jars = sorted(glob.glob(os.path.join(lib_dir, "*.jar")))
    classpath = ":".join([classes_dir] + jars)

    os.makedirs(corpus_dir, exist_ok=True)
    artifact_prefix = artifact_dir.rstrip("/") + os.sep
    os.makedirs(artifact_dir, exist_ok=True)

    # Mismo bug real ya documentado en run_rust_fuzzer.py/run_c_fuzzer.py
    # (libFuzzer/compiler-rt escribe fuzz-N.log en el cwd actual, no
    # configurable) -- Jazzer corre libFuzzer por debajo, mismo
    # comportamiento, mismo fix (cwd aislado por corrida).
    isolated_run_dir = tempfile.mkdtemp(prefix=f"fracture_jvmfuzz_{target_class}_")

    print(f"Corriendo {target_class} por {duration_seconds}s ({workers} workers, cwd aislado {isolated_run_dir})...")
    result = subprocess.run(
        [
            "jazzer",
            f"--cp={classpath}",
            f"--target_class={target_class}",
            # Bug real encontrado en produccion (2026-08-16, primer
            # smoke test real via el scheduler): las flags PROPIAS de
            # Jazzer (--cp, --target_class) usan doble guion, pero las
            # que pasan directo a libFuzzer por debajo (artifact_prefix,
            # max_total_time, jobs, workers) usan UN solo guion -- con
            # doble guion ac'a, Jazzer fallaba con "Unknown arguments"
            # y la corrida nunca arrancaba de verdad. El bug quedo
            # escondido en el primer smoke test porque ya habia un
            # crash viejo (copiado a mano durante la investigacion) en
            # artifact_dir, asi que "crashes=1" parecia una corrida
            # real exitosa cuando en realidad nunca fuzzeo nada.
            f"-artifact_prefix={artifact_prefix}",
            f"-max_total_time={duration_seconds}",
            f"-jobs={workers}",
            f"-workers={workers}",
            corpus_dir,
        ],
        cwd=isolated_run_dir,
        capture_output=True,
        text=True,
        timeout=duration_seconds + 180,  # JVM tarda mas en levantar que un binario nativo -- margen extra real
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
        if os.path.isfile(fpath) and fname.startswith("crash-"):
            with open(fpath, "rb") as fh:
                crashes.append({"file": fname, "bytes": fh.read()})

    # Bug real encontrado en produccion (2026-08-16, primer smoke test
    # correcto via el scheduler despues de arreglar el flag de arriba):
    # Jazzer imprime una linea "INFO: Instrumented <Clase>" por CADA
    # clase que instrumenta (cientos, a veces miles, segun el tamaño
    # real del classpath) -- con el mismo recorte de 3000 caracteres
    # que usan run_c_fuzzer.py/run_rust_fuzzer.py (donde el reporte de
    # ASAN/panic es compacto y esto nunca fue un problema), ese ruido
    # real enterro el "== Java Exception: ..." real en 1 de 2 corridas
    # de prueba -- triage/ lo clasifico como "abort-sin-reporte" en vez
    # de extraer la excepcion real. JVM necesita una ventana mucho mas
    # grande que los demas engines, no es un problema de los otros.
    outcome = {
        "target_class": target_class,
        "returncode": result.returncode,
        "total_runs": total_runs,
        "workers": workers,
        "duration_seconds": duration_seconds,
        "crashes": crashes,
        "stderr_tail": result.stderr[-50000:],
        "stdout_tail": result.stdout[-50000:],
    }

    shutil.rmtree(isolated_run_dir, ignore_errors=True)
    return outcome


def main():
    parser = argparse.ArgumentParser(description="Campana real de Jazzer (JVM) contra una clase ya compilada")
    parser.add_argument("--classes-dir", required=True)
    parser.add_argument("--lib-dir", required=True, help="directorio con los .jar de dependencias reales")
    parser.add_argument("--target-class", required=True)
    parser.add_argument("--corpus-dir", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--duration", type=int, default=2400)
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    args = parser.parse_args()

    outcome = run_jvm_fuzzer(
        args.classes_dir, args.lib_dir, args.target_class,
        args.corpus_dir, args.artifact_dir, args.duration, args.workers,
    )

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
