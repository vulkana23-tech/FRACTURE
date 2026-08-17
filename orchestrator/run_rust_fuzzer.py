#!/usr/bin/env python3
"""Corre una campana real de cargo-fuzz (libFuzzer + ASan) contra un
target ya generado con `cargo +nightly fuzz init`/`fuzz_targets/*.rs`
dentro de un crate real (clonado a mano, no lo hace este script --
a diferencia de run_go_fuzzer.py, ac'a el harness y el clon del repo
ya existen de antes, esto solo orquesta la CORRIDA).

Bug real encontrado en produccion (2026-08-14): `cargo fuzz run
<target> -- -jobs=N -workers=N` deja que libFuzzer escriba un log por
worker (`fuzz-0.log`...`fuzz-{N-1}.log`) en el directorio de trabajo
ACTUAL del proceso (el `fuzz/` del crate) -- no es configurable via
flag, es un comportamiento fijo de libFuzzer (compiler-rt), no de
cargo-fuzz. Confirmado en vivo contra tofn (verify_ecdsa +
verify_ed25519) y wsts (point_from_bytes + scalar_from_bytes): correr
dos targets del MISMO crate en paralelo desde el mismo `fuzz/` hace
que sus workers pisen/lean los mismos nombres de archivo, mezclando
el resumen final de ejecuciones entre ambos targets -- la cuenta total
de ejecuciones reportada para ambos casos termino siendo no confiable
(documentado en findings/2026-08-14_axelar-tofn_verify_ecdsa_ed25519.md
y findings/2026-08-14_wsts_point_scalar_from_bytes.md). Los crashes en
si NO se vieron afectados (el artifact_prefix es una ruta absoluta
distinta por target, nunca colisiona) -- solo el conteo de ejecuciones.

Fix: en vez de `cargo fuzz run` (que siempre usa el `fuzz/` del crate
como cwd), este script (1) compila con `cargo +nightly fuzz build`
--eso es seguro correrlo concurrentemente para distintos targets del
mismo crate, Cargo tiene su propio locking real-- y (2) invoca el
binario YA COMPILADO directo, con `cwd` seteado a un directorio
temporal nuevo y unico por corrida (`tempfile.mkdtemp`). Los
fuzz-N.log de esa corrida quedan ahi, aislados de cualquier otra
corrida paralela del mismo crate, y se pueden sumar con confianza real
al terminar. El corpus y los artifacts (crashes) siguen apuntando a
las rutas reales del crate (`fuzz/corpus/<target>`,
`fuzz/artifacts/<target>`) via argumentos absolutos, nunca al
directorio temporal -- solo el log de stats se aisla.

Uso:
  venv/bin/python3 orchestrator/run_rust_fuzzer.py \\
    --crate-dir /opt/fracture/build/rust_targets/tofn \\
    --target verify_ecdsa \\
    --duration 2400 \\
    --workers 9
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import tempfile

_BUILD_TIMEOUT = 300
_DONE_RE = re.compile(r"^Done (\d+) runs in \d+ second\(s\)", re.MULTILINE)


def _build(crate_dir: str, target: str) -> None:
    print(f"Compilando target {target} (cargo +nightly fuzz build)...")
    result = subprocess.run(
        ["cargo", "+nightly", "fuzz", "build", target],
        cwd=crate_dir, capture_output=True, text=True, timeout=_BUILD_TIMEOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"build fallo para {target}:\n{result.stderr[-4000:]}")


def _binary_path(crate_dir: str, target: str) -> str:
    path = os.path.join(
        crate_dir, "fuzz", "target", "x86_64-unknown-linux-gnu", "release", target
    )
    if not os.path.isfile(path):
        raise FileNotFoundError(f"binario no encontrado tras build: {path}")
    return path


def run_rust_fuzzer(
    crate_dir: str,
    target: str,
    duration_seconds: int,
    workers: int,
) -> dict:
    _build(crate_dir, target)
    binary = _binary_path(crate_dir, target)

    corpus_dir = os.path.join(crate_dir, "fuzz", "corpus", target)
    os.makedirs(corpus_dir, exist_ok=True)
    artifact_prefix = os.path.join(crate_dir, "fuzz", "artifacts", target) + os.sep
    os.makedirs(artifact_prefix, exist_ok=True)

    # cwd aislado unicamente para que los fuzz-N.log de ESTA corrida no
    # colisionen con los de otro target del mismo crate corriendo en
    # paralelo -- ver docstring del modulo.
    isolated_run_dir = tempfile.mkdtemp(prefix=f"fracture_rustfuzz_{target}_")

    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_odr_violation=0"

    print(
        f"Corriendo {target} por {duration_seconds}s "
        f"({workers} workers, cwd aislado {isolated_run_dir})..."
    )
    try:
        result = subprocess.run(
            [
                binary,
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
            timeout=duration_seconds + 120,
        )

        # Sumar los fuzz-N.log reales de ESTA corrida (aislados, sin
        # colision posible) en vez de confiar en el resumen que cargo-fuzz
        # imprime a stdout -- ese es justo el que se corrompia.
        total_runs = 0
        per_worker_logs = sorted(glob.glob(os.path.join(isolated_run_dir, "fuzz-*.log")))
        for log_path in per_worker_logs:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            matches = _DONE_RE.findall(content)
            if matches:
                total_runs += int(matches[-1])

        # Si -jobs=1 (o el binario corre en foreground sin child workers),
        # no hay fuzz-N.log -- el propio stdout/stderr del proceso trae la
        # linea "Done N runs" directamente.
        if not per_worker_logs:
            combined = result.stdout + result.stderr
            matches = _DONE_RE.findall(combined)
            if matches:
                total_runs = int(matches[-1])

        crashes = []
        for fname in sorted(os.listdir(artifact_prefix)):
            fpath = os.path.join(artifact_prefix, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as fh:
                    crashes.append({"file": fname, "bytes": fh.read()})

        outcome = {
            "target": target,
            "returncode": result.returncode,
            "total_runs": total_runs,
            "workers": workers,
            "duration_seconds": duration_seconds,
            "crashes": crashes,
            "stderr_tail": result.stderr[-3000:],
        }
        return outcome
    finally:
        # Mismo bug real y mismo fix que run_c_fuzzer.py (2026-08-17):
        # TimeoutExpired saltaba el rmtree de mas abajo y dejaba
        # isolated_run_dir huerfano para siempre -- ver ese docstring
        # para el incidente real que esto causo.
        shutil.rmtree(isolated_run_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Campana real de cargo-fuzz, sin colision de logs entre targets paralelos")
    parser.add_argument("--crate-dir", required=True, help="raiz del crate con fuzz/ ya inicializado")
    parser.add_argument("--target", required=True, help="nombre del fuzz target (bin en fuzz/Cargo.toml)")
    parser.add_argument("--duration", type=int, default=2400, help="segundos de fuzzing (default 2400 = 40min)")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    args = parser.parse_args()

    outcome = run_rust_fuzzer(args.crate_dir, args.target, args.duration, args.workers)

    print(f"\nTotal de ejecuciones reales (confiable, sin colision): {outcome['total_runs']:,}")
    if outcome["crashes"]:
        print(f"\n⚠️  {len(outcome['crashes'])} crash(es) real(es) en fuzz/artifacts/{args.target}/:")
        for c in outcome["crashes"]:
            print(f"  - {c['file']} ({len(c['bytes'])} bytes)")
    else:
        print("\nSin crashes en esta corrida.")
        if outcome["returncode"] != 0:
            print("stderr:", outcome["stderr_tail"])


if __name__ == "__main__":
    main()
