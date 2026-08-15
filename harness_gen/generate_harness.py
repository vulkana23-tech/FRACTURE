#!/usr/bin/env python3
"""Genera Y VALIDA un harness de libFuzzer para una funcion real de un
repo C, usando qwen3-coder (Ollama) -- mismo criterio que
generate_go_harness.py/generate_rust_harness.py: compila y CORRE de
verdad lo que genera el modelo, y si falla, le pasa el error REAL del
compilador/linker de vuelta para que se corrija (hasta 3 intentos).

A diferencia de Go/Rust, C no tiene un comando de build universal
(no hay "cargo fuzz build"/"go test -fuzz") -- compilar sigue siendo
especifico de cada proyecto (ver orchestrator/run_c_fuzzer.py, mismo
motivo real documentado ahi). Este generador cubre el caso real mas
comun de los targets de C que ya tiene este proyecto (cJSON, parson,
zbxjson): una libreria chica, amalgamada en (o cerca de) un solo
archivo .c junto a su .h. Por default busca un .c con el MISMO nombre
base que el header en el mismo directorio real del repo clonado; si
la libreria real necesita mas archivos (como zbxjson, que necesita
zbxalgo/zbxstr/zbxcommon/zbxnum ademas de zbxjson.c), hay que pasarlos
a mano con --extra-source -- no hay forma barata de resolver
dependencias de C automaticamente sin un build system real.

Uso:
  venv/bin/python3 harness_gen/generate_harness.py \\
    --repo https://github.com/DaveGamble/cJSON \\
    --header cJSON.h \\
    --function cJSON_Parse \\
    --out orchestrator/fuzz_harnesses/nuevo.c
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional, Tuple

import requests

from config import OLLAMA_MODEL, OLLAMA_URL

_CLONE_TIMEOUT = 60
_GENERATE_TIMEOUT = 1200  # mismo motivo real que Go/Rust: 30B en CPU pura, sin GPU, ~0.8 tok/seg medido
_VALIDATE_DURATION = 5
_VALIDATE_WORKERS = 2
_MAX_ATTEMPTS = 3

_C_HARNESS_RULES = """Reglas del harness (obligatorias):
- Incluí el include real del header ({header_name}).
- La función tiene que ser exactamente `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.
- Si la función objetivo espera un `const char*` null-terminated, copiá `data` a un buffer local (malloc) y agregá el null terminator vos mismo -- nunca asumas que `data` ya viene null-terminated.
- Si la función devuelve un puntero a memoria que hay que liberar (mirá el header para pistas, ej. nombres tipo `_Delete`/`_Free`/`free`), liberalo al final del harness para evitar que cada iteración pierda memoria real.
- Devolvé SOLO el código C del harness, sin explicación antes o después, sin markdown code fences."""

_PROMPT_TEMPLATE = """Sos un experto en fuzzing con libFuzzer. Te doy el contenido real de un header de C de un proyecto real, y el nombre de una función pública de ese header.

{rules}

Header real ({header_name}):
```c
{header_content}
```

Función objetivo: {function_name}

Harness:"""

_RETRY_TEMPLATE = """El harness anterior no compiló/linkeó. Este es el error REAL del compilador:

{error}

Harness anterior:
```c
{previous_harness}
```

{rules}

Corregilo en base a ese error real (si el error es un símbolo indefinido de OTRO archivo fuente que no se está compilando, no hay nada que el harness pueda arreglar solo -- en ese caso devolvé el mismo código sin cambios). Devolvé SOLO el código C completo corregido, sin explicación, sin markdown."""


def _clone_shallow(repo_url: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="fracture_harness_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, tmpdir],
            capture_output=True, timeout=_CLONE_TIMEOUT, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"clone fallo para {repo_url}: {e}") from e
    return tmpdir


def _find_header(repo_dir: str, header_name: str) -> str:
    for root, _, files in os.walk(repo_dir):
        if header_name in files:
            return os.path.join(root, header_name)
    raise FileNotFoundError(f"{header_name} no encontrado en el repo clonado")


def _read_header(header_path: str) -> str:
    with open(header_path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def _find_matching_source_file(header_path: str) -> Optional[str]:
    """Busca un .c con el MISMO nombre base que el header, en el mismo
    directorio real -- caso real mas comun (cJSON.c junto a cJSON.h,
    parson.c junto a parson.h). None si no existe (repos con
    fuentes/headers en directorios separados necesitan --extra-source
    a mano, no hay heuristica barata confiable para eso)."""
    base = os.path.splitext(header_path)[0]
    candidate = base + ".c"
    return candidate if os.path.isfile(candidate) else None


def _fix_common_issues(harness: str, header_name: str) -> str:
    """Post-procesamiento DETERMINISTICO (nunca otra llamada a IA) contra
    2 bugs reales encontrados probando esto en vivo (cJSON_Parse,
    2026-08-09): (1) el modelo a veces escribe el nombre del include en
    minuscula aunque el archivo real tenga mayusculas (Linux es
    case-sensitive, "cjson.h" vs "cJSON.h" no compila) -- se reemplaza
    cualquier include que coincida con el nombre SIN case por el nombre
    real exacto. (2) el modelo a veces omite <stdint.h> pese a usar
    uint8_t en la firma de LLVMFuzzerTestOneInput -- se agrega si falta
    y la firma lo usa."""
    fixed = re.sub(
        rf'#include\s*"{re.escape(header_name)}"',
        f'#include "{header_name}"',
        harness,
        flags=re.IGNORECASE,
    )
    if "uint8_t" in fixed and "#include <stdint.h>" not in fixed:
        # Se inserta despues del primer #include real (si hay alguno) o
        # al principio del archivo -- nunca en medio del codigo.
        lines = fixed.split("\n")
        insert_at = 0
        for i, line in enumerate(lines):
            if line.strip().startswith("#include"):
                insert_at = i + 1
        lines.insert(insert_at, "#include <stdint.h>")
        fixed = "\n".join(lines)
    return fixed


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


def generate_harness(header_content: str, header_name: str, function_name: str) -> str:
    prompt = _PROMPT_TEMPLATE.format(
        rules=_C_HARNESS_RULES.format(header_name=header_name),
        header_name=header_name, header_content=header_content, function_name=function_name,
    )
    text = _call_ollama(prompt)
    return _fix_common_issues(text, header_name)


def _try_compile_and_run(
    harness_code: str, header_dir: str, source_files: List[str], include_dirs: List[str],
) -> Tuple[bool, str]:
    build_dir = tempfile.mkdtemp(prefix="fracture_cgen_build_")
    try:
        harness_path = os.path.join(build_dir, "harness.c")
        with open(harness_path, "w", encoding="utf-8") as fh:
            fh.write(harness_code)

        binary_path = os.path.join(build_dir, "fuzz_bin")
        include_flags = [f"-I{header_dir}"] + [f"-I{d}" for d in include_dirs]
        compile_cmd = (
            ["clang", "-fsanitize=fuzzer,address", "-g", "-O1"]
            + include_flags + [harness_path] + source_files + ["-o", binary_path]
        )
        compile_result = subprocess.run(
            compile_cmd, capture_output=True, text=True, timeout=120,
        )
        if compile_result.returncode != 0:
            return False, compile_result.stderr[-4000:]

        run_dir = tempfile.mkdtemp(prefix="fracture_cgen_run_")
        try:
            run_result = subprocess.run(
                [binary_path, f"-max_total_time={_VALIDATE_DURATION}",
                 f"-jobs={_VALIDATE_WORKERS}", f"-workers={_VALIDATE_WORKERS}"],
                cwd=run_dir, capture_output=True, text=True,
                timeout=_VALIDATE_DURATION + 60,
            )
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

        combined = run_result.stdout + run_result.stderr
        if run_result.returncode != 0:
            return False, combined[-4000:]
        return True, ""
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)


def generate_and_validate_harness(
    repo_url: str, header_name: str, function_name: str,
    extra_source: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None,
    max_attempts: int = _MAX_ATTEMPTS,
) -> dict:
    extra_source = extra_source or []
    include_dirs = include_dirs or []

    repo_dir = _clone_shallow(repo_url)
    try:
        header_path = _find_header(repo_dir, header_name)
        header_content = _read_header(header_path)
        header_dir = os.path.dirname(header_path)

        source_files = list(extra_source)
        auto_source = _find_matching_source_file(header_path)
        if auto_source and auto_source not in source_files:
            source_files.append(auto_source)

        if not source_files:
            return {
                "success": False, "harness": None, "attempts": [],
                "error": (
                    f"no se encontro ningun .c real para linkear (ni {os.path.splitext(header_name)[0]}.c "
                    f"junto al header, ni --extra-source) -- este generador solo valida librerias chicas "
                    f"amalgamadas en 1-2 archivos, no resuelve dependencias de C solo."
                ),
            }

        harness = generate_harness(header_content, header_name, function_name)

        attempts_log = []
        for attempt in range(1, max_attempts + 1):
            ok, error = _try_compile_and_run(harness, header_dir, source_files, include_dirs)
            attempts_log.append({"attempt": attempt, "ok": ok, "error": error if not ok else ""})
            if ok:
                return {"success": True, "harness": harness, "source_files": source_files,
                        "attempts": attempts_log}
            if attempt == max_attempts:
                return {"success": False, "harness": harness, "source_files": source_files,
                        "attempts": attempts_log}
            retry_prompt = _RETRY_TEMPLATE.format(
                error=error, previous_harness=harness,
                rules=_C_HARNESS_RULES.format(header_name=header_name),
            )
            harness = _strip_markdown_fences(_call_ollama(retry_prompt))
            harness = _fix_common_issues(harness, header_name)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--header", required=True, help="nombre del archivo header (ej. cJSON.h)")
    parser.add_argument("--function", required=True, help="funcion publica objetivo")
    parser.add_argument("--out", required=True)
    parser.add_argument("--extra-source", nargs="*", default=None,
                        help="archivos .c adicionales para linkear (rutas dentro del repo clonado -- avanzado, ver docstring)")
    parser.add_argument("--max-attempts", type=int, default=_MAX_ATTEMPTS)
    args = parser.parse_args()

    print(f"Clonando {args.repo} y generando+validando harness para {args.function}()...")
    result = generate_and_validate_harness(
        args.repo, args.header, args.function, args.extra_source, None, args.max_attempts,
    )

    if result.get("harness") is None:
        print(f"\n{result['error']}")
        sys.exit(1)

    for a in result["attempts"]:
        status = "OK" if a["ok"] else "FALLO"
        print(f"  intento {a['attempt']}: {status}")
        if not a["ok"]:
            print(f"    {a['error'][-600:]}")

    if result["success"]:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["harness"])
        print(f"\nHarness VALIDADO (compila y corre de verdad, linkeado con "
              f"{', '.join(os.path.basename(f) for f in result['source_files'])}) -- escrito en {args.out}")
    else:
        print(f"\nNo se pudo validar en {args.max_attempts} intentos -- NO se escribe {args.out}. "
              f"Ultimo error arriba, revision humana necesaria.")
        sys.exit(1)


if __name__ == "__main__":
    main()
