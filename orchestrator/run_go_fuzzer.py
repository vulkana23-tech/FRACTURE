#!/usr/bin/env python3
"""Corre fuzzing NATIVO de Go (`go test -fuzz`, sin libFuzzer/AFL++ --
Go trae su propio motor de fuzzing desde 1.18) contra un paquete real de
un repo clonado. Clona, inyecta un archivo _test.go con la funcion
Fuzz ya escrita, corre con paralelismo real (los cores disponibles), y
reporta si encontro un crash real (Go guarda el input que crashea en
testdata/fuzz/<FuzzFunc>/ automaticamente).

Uso:
  venv/bin/python3 orchestrator/run_go_fuzzer.py \\
    --repo https://github.com/hyperledger/fabric-amcl \\
    --package-path core \\
    --fuzz-test-file fuzz_tests/dilithium_verify_test.go \\
    --fuzz-func FuzzDLVerify2 \\
    --duration 60
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

_CLONE_TIMEOUT = 60


def _clone_shallow(repo_url: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="fracture_fuzz_")
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, tmpdir],
        capture_output=True, timeout=_CLONE_TIMEOUT, check=True,
    )
    return tmpdir


def _ensure_go_module(repo_dir: str, repo_url: str) -> None:
    """Bug real encontrado en produccion (2026-08-09): fabric-amcl (y
    seguramente otros repos viejos de la lista de candidatos, es codigo
    de mas de 10 anios) no tiene go.mod en absoluto -- es estilo GOPATH,
    de antes de que existieran los modulos de Go. `go test -fuzz`
    requiere estar dentro de un modulo real. Fix: si no hay go.mod en la
    raiz del clon, generar uno local (`go mod init`) -- nunca toca el
    repo real en GitHub, solo la copia temporal clonada. El nombre del
    modulo se deriva de la URL real para que los imports internos del
    propio repo (si los hay) seaan consistentes."""
    if os.path.exists(os.path.join(repo_dir, "go.mod")):
        return
    module_path = repo_url.replace("https://", "").rstrip("/")
    subprocess.run(
        ["go", "mod", "init", module_path],
        cwd=repo_dir, capture_output=True, timeout=30,
    )
    # Repos viejos sin go.mod tampoco tienen go.sum -- go mod tidy
    # resuelve las dependencias reales que el codigo importa. Fail-open
    # real: si tidy falla (ej. una dependencia vieja ya no resuelve),
    # se sigue igual -- go test fallara mas adelante con un error mas
    # claro en ese caso, no hace falta abortar aca.
    subprocess.run(
        ["go", "mod", "tidy"],
        cwd=repo_dir, capture_output=True, timeout=120,
    )


def run_go_fuzzer(
    repo_url: str,
    package_path: str,
    fuzz_test_file: str,
    fuzz_func: str,
    duration_seconds: int,
    parallel: int,
) -> dict:
    repo_dir = _clone_shallow(repo_url)
    _ensure_go_module(repo_dir, repo_url)
    target_dir = os.path.join(repo_dir, package_path)
    if not os.path.isdir(target_dir):
        shutil.rmtree(repo_dir, ignore_errors=True)
        raise FileNotFoundError(f"{package_path} no existe en el repo clonado")

    injected_path = os.path.join(target_dir, os.path.basename(fuzz_test_file))
    shutil.copy(fuzz_test_file, injected_path)

    print(f"Corriendo `go test -fuzz={fuzz_func}` en {package_path}/ "
          f"por {duration_seconds}s (parallel={parallel})...")
    result = subprocess.run(
        [
            "go", "test",
            f"-fuzz={fuzz_func}",
            f"-fuzztime={duration_seconds}s",
            f"-parallel={parallel}",
            "-run", "^$",  # nunca correr los tests normales, solo fuzzing
        ],
        cwd=target_dir,
        capture_output=True,
        text=True,
        timeout=duration_seconds + 60,  # margen real por encima del fuzztime pedido
    )

    # Go guarda automaticamente cualquier input que crashea en
    # testdata/fuzz/<fuzz_func>/ -- confirmar ahi en vez de parsear texto
    # de stdout, que puede cambiar de formato entre versiones de Go.
    corpus_dir = os.path.join(target_dir, "testdata", "fuzz", fuzz_func)
    crashes = []
    if os.path.isdir(corpus_dir):
        for fname in os.listdir(corpus_dir):
            with open(os.path.join(corpus_dir, fname), "r", encoding="utf-8", errors="ignore") as fh:
                crashes.append({"file": fname, "content": fh.read()})

    outcome = {
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-3000:],
        "stderr_tail": result.stderr[-3000:],
        "crashes": crashes,
        "repo_url": repo_url,
        "fuzz_func": fuzz_func,
    }

    shutil.rmtree(repo_dir, ignore_errors=True)
    return outcome


def main():
    parser = argparse.ArgumentParser(description="Fuzzing nativo de Go contra un repo real")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--package-path", required=True, help="path relativo del paquete dentro del repo (ej. core)")
    parser.add_argument("--fuzz-test-file", required=True, help="archivo _test.go local con la funcion Fuzz ya escrita")
    parser.add_argument("--fuzz-func", required=True, help="nombre de la funcion Fuzz (ej. FuzzDLVerify2)")
    parser.add_argument("--duration", type=int, default=60, help="segundos de fuzzing (default 60)")
    parser.add_argument("--parallel", type=int, default=os.cpu_count() or 4)
    args = parser.parse_args()

    outcome = run_go_fuzzer(
        args.repo, args.package_path, args.fuzz_test_file,
        args.fuzz_func, args.duration, args.parallel,
    )

    if outcome["crashes"]:
        print(f"\n⚠️  {len(outcome['crashes'])} crash(es) real(es) encontrado(s):")
        for c in outcome["crashes"]:
            print(f"\n--- {c['file']} ---")
            print(c["content"])
    else:
        print(f"\nSin crashes en esta corrida (returncode={outcome['returncode']}).")
        if outcome["returncode"] != 0:
            print("stderr:", outcome["stderr_tail"])


if __name__ == "__main__":
    main()
