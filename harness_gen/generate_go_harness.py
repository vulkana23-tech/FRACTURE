#!/usr/bin/env python3
"""Genera Y VALIDA un harness de fuzzing nativo de Go (`go test -fuzz`)
para una funcion real de un paquete real, usando qwen3-coder (Ollama,
ya corriendo en este VPS para SPECTRE) -- a diferencia de
generate_harness.py (C/libFuzzer, borrador sin validar, requiere ojo
humano antes de compilar), esto SI intenta compilar y correr el
harness generado contra el repo real, y si falla, le pasa el error
REAL del compilador de vuelta al modelo para que se corrija (hasta
_MAX_ATTEMPTS veces) -- mismo criterio de "iterar contra el error real
del toolchain, no adivinar" que ya se uso en el piloto de CodeQL
(targets/codeql_queries/README.md).

Reusa _clone_shallow/_ensure_go_module de orchestrator/run_go_fuzzer.py
(el mismo codigo que despues va a correr esto de verdad en produccion,
no una reimplementacion aparte que podria divergir).

Uso:
  venv/bin/python3 harness_gen/generate_go_harness.py \\
    --repo https://github.com/hyperledger/fabric-chaincode-go \\
    --package-path pkg/attrmgr \\
    --function GetAttributesFromIdemix \\
    --out orchestrator/fuzz_tests/fabric_chaincode_go_attrmgr_idemix_test.go
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Optional, Tuple

import requests

from config import OLLAMA_MODEL, OLLAMA_URL

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "orchestrator"))
from run_go_fuzzer import _clone_shallow, _ensure_go_module  # noqa: E402 -- reuso real, no reimplementacion

# Bug real encontrado en produccion (2026-08-15): este VPS no tiene GPU
# (confirmado, `nvidia-smi` ni siquiera esta instalado) -- qwen3-coder:30b
# corre 100% en CPU. Medido en vivo sin contencion (orchestrator/
# scheduler.py detenido): ~0.8 tokens/seg (17 tokens reales en 24.8s
# reales). Un harness completo son unos cientos de tokens -- varios
# minutos por intento SOLO, sin contar que el scheduler normalmente
# esta usando la mayoria de los 18 cores para fuzzing real las 24/7 (el
# primer intento real con el scheduler corriendo dio timeout a los 240s
# que tenia antes). 1200s todavia puede no alcanzar bajo contencion
# fuerte -- si vuelve a pasar, la opcion real es correr harness_gen con
# el scheduler pausado (`systemctl stop fracture-orchestrator`), no
# subir el timeout indefinidamente.
_GENERATE_TIMEOUT = 1200
_VALIDATE_DURATION = 3  # segundos reales de fuzzing -- confirma que compila Y CORRE, no solo que compila
_MAX_ATTEMPTS = 3

_GO_FUZZ_RULES = """Reglas del fuzzing nativo de Go (obligatorias, romperlas hace que no compile):
- La funcion tiene que llamarse Fuzz<Algo> (con F mayuscula) y tener firma `func FuzzXxx(f *testing.F)`.
- Adentro, UNA sola llamada a `f.Fuzz(func(t *testing.T, <params>) { ... })`.
- Los <params> de esa funcion interna SOLO pueden ser de estos tipos (nunca structs, nunca punteros, nunca slices que no sean []byte): []byte, string, bool, byte, rune, float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64.
- Agregá al menos un `f.Add(...)` con un seed realista ANTES de `f.Fuzz(...)`.
- Si la funcion objetivo espera un tipo que no es fuzzeable directamente (ej. un struct armado a partir de bytes), construilo DENTRO de la funcion interna a partir de los parametros fuzzeables (ej. []byte crudo, o encodealo vos mismo).
- Nunca falles el test con `t.Fatal`/`panic` por un error ESPERADO de la funcion (ej. `Unmarshal` fallando con input invalido) -- eso es tráfico normal de fuzzing, no un bug. Solo dejá que un panic REAL del codigo bajo test se propague solo (no lo atajes con recover)."""

_PROMPT_TEMPLATE = """Sos un experto en fuzzing nativo de Go (`go test -fuzz`, Go 1.18+). Te doy el contenido real de un archivo .go de un proyecto real, y el nombre de una funcion/metodo publico de ese archivo para fuzzear.

{rules}

Contexto: esto se inyecta como archivo ADENTRO del mismo paquete real ({package_name}) -- podés usar directamente cualquier tipo/funcion no exportada de ese paquete, no hace falta importarlo.

Archivo real ({filename}, paquete {package_name}):
```go
{file_content}
```

Funcion/metodo objetivo: {function_name}
Nombre exacto que tiene que tener la funcion Fuzz: {fuzz_func_name}

Devolvé SOLO el codigo Go completo del archivo de test (package {package_name}, imports incluidos, la funcion {fuzz_func_name}), sin explicacion antes o despues, sin markdown code fences."""

_RETRY_TEMPLATE = """El harness anterior no compilo/corrio. Este es el error REAL de `go test`:

{error}

Harness anterior:
```go
{previous_harness}
```

{rules}

Corregilo antes esto. Devolvé SOLO el codigo Go completo corregido, sin explicacion, sin markdown."""


def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def _call_ollama(prompt: str) -> str:
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=_GENERATE_TIMEOUT,
    )
    resp.raise_for_status()
    return _strip_markdown_fences(resp.json().get("response", ""))


def _find_function_file(repo_dir: str, package_path: str, function_name: str) -> Tuple[str, str, str]:
    """Busca el archivo .go REAL (nunca _test.go) que define function_name
    dentro de package_path -- devuelve (filename, contenido, package real
    leido del propio archivo, nunca adivinado)."""
    pkg_dir = os.path.join(repo_dir, package_path)
    if not os.path.isdir(pkg_dir):
        raise FileNotFoundError(f"{package_path} no existe en el repo clonado")

    func_re = re.compile(
        rf"^func\s+(?:\([^)]*\)\s+)?{re.escape(function_name)}\s*\(", re.MULTILINE
    )
    package_re = re.compile(r"^package\s+(\S+)", re.MULTILINE)

    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".go") or fname.endswith("_test.go"):
            continue
        fpath = os.path.join(pkg_dir, fname)
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        if func_re.search(content):
            pkg_match = package_re.search(content)
            if not pkg_match:
                raise RuntimeError(f"{fname} no tiene declaracion 'package' -- archivo Go invalido")
            return fname, content, pkg_match.group(1)

    raise FileNotFoundError(f"{function_name} no encontrado en ningun .go real (no-test) de {package_path}")


def _try_compile_and_run(repo_dir: str, package_path: str, harness_code: str, fuzz_func_name: str) -> Tuple[bool, str]:
    pkg_dir = os.path.join(repo_dir, package_path)
    # Bug real encontrado en produccion (2026-08-15): un nombre de archivo
    # que EMPIEZA con "_" (o ".") es ignorado en silencio por el propio
    # `go` tool (regla real y documentada: "Directory and file names that
    # begin with '.' or '_' are ignored by the go tool") -- con
    # "_harness_gen_candidate_test.go", `go test` nunca vio el archivo,
    # asi que CUALQUIER contenido (incluso invalido) daba `returncode=0`
    # + "PASS" porque no habia nada real que compilar. Confirmado
    # reproduciendo el bug en vivo: un harness real con imports sin usar
    # (que `go vet` rechaza de verdad) paso la validacion igual. Nombre
    # sin underscore inicial arregla esto de raiz.
    injected_path = os.path.join(pkg_dir, "harness_gen_candidate_test.go")
    with open(injected_path, "w", encoding="utf-8") as fh:
        fh.write(harness_code)
    try:
        result = subprocess.run(
            ["go", "test", f"-fuzz={fuzz_func_name}", f"-fuzztime={_VALIDATE_DURATION}s",
             "-parallel=1", "-run", "^$"],
            cwd=pkg_dir, capture_output=True, text=True, timeout=_VALIDATE_DURATION + 60,
        )
    finally:
        os.remove(injected_path)

    combined = result.stdout + result.stderr
    # Chequeo estricto: returncode Y "PASS" real de `go test` -- ya no
    # "ok" suelto (substring demasiado debil, aparece en cualquier lado).
    if result.returncode == 0 and "PASS" in combined:
        return True, ""
    return False, combined[-4000:]


def generate_and_validate_go_harness(
    repo_url: str, package_path: str, function_name: str, fuzz_func_name: Optional[str] = None,
    max_attempts: int = _MAX_ATTEMPTS,
) -> dict:
    if fuzz_func_name is None:
        fuzz_func_name = "Fuzz" + function_name[0].upper() + function_name[1:]

    repo_dir = _clone_shallow(repo_url)
    try:
        _ensure_go_module(repo_dir, repo_url)
        filename, file_content, package_name = _find_function_file(repo_dir, package_path, function_name)

        prompt = _PROMPT_TEMPLATE.format(
            rules=_GO_FUZZ_RULES, package_name=package_name, filename=filename,
            file_content=file_content, function_name=function_name, fuzz_func_name=fuzz_func_name,
        )
        harness = _call_ollama(prompt)

        attempts_log = []
        for attempt in range(1, max_attempts + 1):
            ok, error = _try_compile_and_run(repo_dir, package_path, harness, fuzz_func_name)
            attempts_log.append({"attempt": attempt, "ok": ok, "error": error if not ok else ""})
            if ok:
                return {
                    "success": True, "harness": harness, "fuzz_func_name": fuzz_func_name,
                    "package_name": package_name, "source_file": filename,
                    "attempts": attempts_log,
                }
            if attempt == max_attempts:
                return {
                    "success": False, "harness": harness, "fuzz_func_name": fuzz_func_name,
                    "package_name": package_name, "source_file": filename,
                    "attempts": attempts_log,
                }
            retry_prompt = _RETRY_TEMPLATE.format(error=error, previous_harness=harness, rules=_GO_FUZZ_RULES)
            harness = _call_ollama(retry_prompt)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--package-path", required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--fuzz-func-name", default=None)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-attempts", type=int, default=_MAX_ATTEMPTS)
    args = parser.parse_args()

    print(f"Generando y validando harness para {args.function}() en {args.package_path} "
          f"({args.repo})...")
    result = generate_and_validate_go_harness(
        args.repo, args.package_path, args.function, args.fuzz_func_name, args.max_attempts,
    )

    for a in result["attempts"]:
        status = "OK" if a["ok"] else "FALLO"
        print(f"  intento {a['attempt']}: {status}")
        if not a["ok"]:
            print(f"    {a['error'][-600:]}")

    if result["success"]:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["harness"])
        print(f"\nHarness VALIDADO (compila y corre de verdad, {_VALIDATE_DURATION}s) -- escrito en {args.out}")
        print(f"fuzz_func: {result['fuzz_func_name']} (package {result['package_name']}, "
              f"basado en {result['source_file']})")
    else:
        print(f"\nNo se pudo validar en {args.max_attempts} intentos -- NO se escribe {args.out}. "
              f"Ultimo error arriba, revision humana necesaria.")
        sys.exit(1)


if __name__ == "__main__":
    main()
