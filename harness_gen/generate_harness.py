#!/usr/bin/env python3
"""Genera un primer borrador de harness de libFuzzer para una funcion
real de un repo C/C++, usando qwen3-coder (Ollama, ya corriendo para
SPECTRE) para leer el header real y redactar el harness -- SIEMPRE
requiere revision humana antes de compilar/correr contra algo real,
esto es un borrador, no un harness confiable a ciegas.

Uso:
  venv/bin/python3 harness_gen/generate_harness.py \\
    --repo https://github.com/DaveGamble/cJSON \\
    --header cJSON.h \\
    --function cJSON_Parse \\
    --out /tmp/harness_cjson.c
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

import requests

from config import OLLAMA_MODEL, OLLAMA_URL

_CLONE_TIMEOUT = 60
_GENERATE_TIMEOUT = 180

_PROMPT_TEMPLATE = """Sos un experto en fuzzing con libFuzzer. Te doy el contenido real de un header de C/C++ de un proyecto real, y el nombre de una funcion publica de ese header.

Tu tarea: escribir un harness de libFuzzer COMPLETO Y COMPILABLE (funcion `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`) que llame a esa funcion con datos derivados del input de fuzzing, de la forma mas directa y realista posible (nunca inventes una API que no este en el header).

Reglas:
- Incluí el include real del header ({header_name}).
- Si la funcion espera un `const char*` null-terminated, copiá `data` a un buffer local y agregá el null terminator vos mismo (nunca asumas que `data` ya viene null-terminated).
- Si la funcion devuelve un puntero a memoria que hay que liberar (mirá el header para pistas, ej. nombres tipo `_Delete`/`_Free`/`free`), liberalo al final del harness para evitar que cada iteracion pierda memoria real.
- Devolvé SOLO el codigo C/C++ del harness, sin explicacion antes o despues, sin markdown code fences.

Header real ({header_name}):
```
{header_content}
```

Funcion objetivo: {function_name}

Harness:"""


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


def _read_header(repo_dir: str, header_name: str) -> str:
    for root, _, files in os.walk(repo_dir):
        if header_name in files:
            with open(os.path.join(root, header_name), "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
    raise FileNotFoundError(f"{header_name} no encontrado en el repo clonado")


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


def generate_harness(header_content: str, header_name: str, function_name: str) -> str:
    prompt = _PROMPT_TEMPLATE.format(
        header_name=header_name, header_content=header_content, function_name=function_name
    )
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=_GENERATE_TIMEOUT,
    )
    resp.raise_for_status()
    text = resp.json().get("response", "")
    # El modelo a veces envuelve la respuesta en ```c ... ``` pese a la
    # instruccion -- pelarlo si aparece, nunca dejarlo en el archivo final.
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    text = text.strip()
    return _fix_common_issues(text, header_name)


def main():
    parser = argparse.ArgumentParser(description="Genera un borrador de harness de libFuzzer con IA")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--header", required=True, help="nombre del archivo header (ej. cJSON.h)")
    parser.add_argument("--function", required=True, help="funcion publica objetivo")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    print(f"Clonando {args.repo}...")
    repo_dir = _clone_shallow(args.repo)
    try:
        print(f"Leyendo {args.header}...")
        header_content = _read_header(repo_dir, args.header)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)

    print(f"Generando harness con {OLLAMA_MODEL} para {args.function}()...")
    harness = generate_harness(header_content, args.header, args.function)

    with open(args.out, "w") as fh:
        fh.write(harness)

    print(f"\nHarness escrito en {args.out} -- BORRADOR, revisar a mano antes de compilar:\n")
    print(harness)


if __name__ == "__main__":
    main()
