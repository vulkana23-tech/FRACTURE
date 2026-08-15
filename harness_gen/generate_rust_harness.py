#!/usr/bin/env python3
"""Genera Y VALIDA un harness de cargo-fuzz (libFuzzer, Rust) para una
funcion real de un crate real, usando qwen3-coder (Ollama) -- mismo
criterio que generate_go_harness.py: compila y CORRE de verdad lo que
genera el modelo, y si falla, le pasa el error REAL del compilador de
vuelta para que se corrija (hasta 3 intentos).

A diferencia de Go (run_go_fuzzer.py clona un tmpdir fresco cada vez),
en este proyecto los crates de Rust son clones PERSISTENTES bajo
build/rust_targets/<crate>/ (mismo patron ya establecido por
run_rust_fuzzer.py -- "el clon del repo ya existe de antes, esto solo
orquesta"). Este script sigue esa misma convencion: --crate-dir apunta
a un clon YA HECHO (a mano o por otro paso), nunca clona nada solo.

Reusa run_rust_fuzzer() de orchestrator/run_rust_fuzzer.py para la
validacion real -- el MISMO codigo que despues corre esto en
produccion, no una reimplementacion aparte.

Uso:
  venv/bin/python3 harness_gen/generate_rust_harness.py \\
    --crate-dir /opt/fracture/build/rust_targets/tofn \\
    --function verify_ed25519 \\
    --out orchestrator/fuzz_harnesses/nuevo.rs
"""

import argparse
import os
import re
import sys
from typing import Optional, Tuple

import requests

from config import OLLAMA_MODEL, OLLAMA_URL

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "orchestrator"))
from run_rust_fuzzer import run_rust_fuzzer  # noqa: E402 -- reuso real, no reimplementacion

_GENERATE_TIMEOUT = 1200  # mismo motivo real que generate_go_harness.py: 30B en CPU pura, sin GPU, medido ~0.8 tok/seg
_VALIDATE_DURATION = 5
_VALIDATE_WORKERS = 2
_MAX_ATTEMPTS = 3

_RUST_FUZZ_RULES = """Reglas de un harness de cargo-fuzz (libFuzzer, obligatorias):
- Primera linea SIEMPRE `#![no_main]`, despues `use libfuzzer_sys::fuzz_target;`.
- Un solo `fuzz_target!(|data: &[u8]| { ... });` -- la firma del closure es SIEMPRE `|data: &[u8]|`, nunca otra cosa.
- Si la funcion objetivo necesita otro tipo (struct, string, multiples buffers), construilo DENTRO del closure a partir de `data` (slicing manual, nunca asumas un layout que no justifiques con un comentario).
- Si `data` es mas corto de lo que la funcion necesita, hace `return;` temprano -- nunca panic por index out of bounds del propio harness (eso es ruido, no un bug real del codigo bajo test).
- Nunca falles el fuzz target con `.unwrap()`/`.expect()` sobre un `Result`/`Option` que la funcion objetivo devuelve como parte de su operacion normal (input invalido = Err/None esperado, no un bug) -- usa `let _ = ...` o `if let Ok(...) = ...`. Un panic REAL del codigo bajo test (no del harness) tiene que propagarse solo, nunca se atrapa con catch_unwind.
- Importa el crate real con `use <crate>::...;` -- el nombre del crate es el mismo `[lib] name` de su Cargo.toml real (ya en el `use` de ejemplo mas abajo si el archivo real lo tiene)."""

_PROMPT_TEMPLATE = """Sos un experto en fuzzing con cargo-fuzz (libFuzzer, Rust). Te doy el contenido real de un archivo .rs de un crate real, y el nombre de una funcion publica de ese archivo para fuzzear.

{rules}

Archivo real ({filename}, crate `{crate_name}`):
```rust
{file_content}
```

Funcion objetivo: {function_name}

Devolvé SOLO el codigo Rust completo del harness (`#![no_main]` hasta el cierre de `fuzz_target!`), sin explicacion antes o despues, sin markdown code fences."""

_RETRY_TEMPLATE = """El harness anterior no compilo/corrio. Este es el error REAL de `cargo fuzz build`:

{error}

Harness anterior:
```rust
{previous_harness}
```

{rules}

Corregilo en base a ese error real. Devolvé SOLO el codigo Rust completo corregido, sin explicacion, sin markdown."""

_RUST_FUNC_RE_TEMPLATE = r"^\s*pub\s+fn\s+{name}\s*(?:<[^>]*>)?\s*\("


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


def _crate_name(crate_dir: str) -> str:
    """Lee el nombre real del crate desde su Cargo.toml -- nunca se
    adivina desde el nombre del directorio (puede no coincidir, ej. un
    fork clonado con otro nombre de carpeta)."""
    cargo_toml = os.path.join(crate_dir, "Cargo.toml")
    with open(cargo_toml, "r", encoding="utf-8", errors="ignore") as fh:
        content = fh.read()
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not m:
        raise RuntimeError(f"no se pudo leer [package] name real de {cargo_toml}")
    return m.group(1)


def _find_function_file(crate_dir: str, function_name: str) -> Tuple[str, str]:
    """Busca el archivo .rs real (bajo src/) que define function_name
    como funcion PUBLICA -- devuelve (path relativo a crate_dir,
    contenido real). Nunca inventa un archivo."""
    src_dir = os.path.join(crate_dir, "src")
    func_re = re.compile(_RUST_FUNC_RE_TEMPLATE.format(name=re.escape(function_name)), re.MULTILINE)

    for root, _, files in os.walk(src_dir):
        for fname in sorted(files):
            if not fname.endswith(".rs"):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            if func_re.search(content):
                return os.path.relpath(fpath, crate_dir), content

    raise FileNotFoundError(f"pub fn {function_name} no encontrada en ningun .rs real de {src_dir}")


def _ensure_fuzz_scaffolding(crate_dir: str) -> bool:
    """Corre `cargo +nightly fuzz init` si fuzz/ todavia no existe --
    bootstrap real, no simulado (crea fuzz/Cargo.toml con el
    `[dependencies.<crate>] path = ".."` ya armado correcto por la
    propia herramienta de cargo-fuzz). Devuelve True si lo tuvo que
    crear (para saber si hay que limpiar el target placeholder
    despues), False si fuzz/ ya existia de antes -- en ese caso nunca
    se toca nada existente."""
    fuzz_dir = os.path.join(crate_dir, "fuzz")
    if os.path.isdir(fuzz_dir):
        return False

    import subprocess
    result = subprocess.run(
        ["cargo", "+nightly", "fuzz", "init"],
        cwd=crate_dir, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cargo fuzz init fallo en {crate_dir}:\n{result.stderr[-2000:]}")
    return True


def _remove_placeholder_target(crate_dir: str) -> None:
    """Solo se llama si ESTE script fue el que corrio `cargo fuzz
    init` recien -- borra el target de ejemplo (`fuzz_target_1`, sin
    ningun fuzzing real adentro) que la herramienta genera sola, para
    no dejar scaffolding inutil mezclado con el harness real."""
    placeholder_rs = os.path.join(crate_dir, "fuzz", "fuzz_targets", "fuzz_target_1.rs")
    if os.path.isfile(placeholder_rs):
        os.remove(placeholder_rs)
    cargo_toml_path = os.path.join(crate_dir, "fuzz", "Cargo.toml")
    with open(cargo_toml_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    # Bug real encontrado en produccion (2026-08-16): un regex no-greedy
    # generico (`.*?\n\n?`) paraba de matchear en la PRIMERA linea en
    # blanco/casi-en-blanco que encontraba, dejando "test = false\ndoc
    # = false\nbench = false" huerfanos (sin su [[bin]]/name/path) en
    # el Cargo.toml real -- TOML invalido. `cargo +nightly fuzz init`
    # genera SIEMPRE este bloque exacto (confirmado corriendolo en
    # vivo) -- match literal del bloque completo en vez de un patron
    # generico que puede parar antes de tiempo.
    placeholder_block = (
        '\n[[bin]]\nname = "fuzz_target_1"\n'
        'path = "fuzz_targets/fuzz_target_1.rs"\ntest = false\ndoc = false\nbench = false\n'
    )
    content = content.replace(placeholder_block, "\n")
    with open(cargo_toml_path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _register_fuzz_target(crate_dir: str, target_name: str) -> None:
    """Agrega el bloque [[bin]] real al fuzz/Cargo.toml existente --
    nunca reemplaza entradas ya presentes, solo agrega la nueva al
    final (mismo formato exacto que ya usan los targets reales de este
    proyecto, ver build/rust_targets/tofn/fuzz/Cargo.toml)."""
    cargo_toml_path = os.path.join(crate_dir, "fuzz", "Cargo.toml")
    with open(cargo_toml_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    if f'name = "{target_name}"' in content:
        return  # ya registrado (reintento sobre el mismo target), no duplicar
    block = (
        f'\n[[bin]]\nname = "{target_name}"\n'
        f'path = "fuzz_targets/{target_name}.rs"\ntest = false\ndoc = false\nbench = false\n'
    )
    with open(cargo_toml_path, "a", encoding="utf-8") as fh:
        fh.write(block)


def generate_and_validate_rust_harness(
    crate_dir: str, function_name: str, target_name: Optional[str] = None,
    max_attempts: int = _MAX_ATTEMPTS,
) -> dict:
    if target_name is None:
        target_name = function_name

    crate_name = _crate_name(crate_dir)
    filename, file_content = _find_function_file(crate_dir, function_name)
    created_scaffolding = _ensure_fuzz_scaffolding(crate_dir)
    if created_scaffolding:
        _remove_placeholder_target(crate_dir)

    fuzz_target_path = os.path.join(crate_dir, "fuzz", "fuzz_targets", f"{target_name}.rs")

    prompt = _PROMPT_TEMPLATE.format(
        rules=_RUST_FUZZ_RULES, filename=filename, crate_name=crate_name,
        file_content=file_content, function_name=function_name,
    )
    harness = _call_ollama(prompt)

    attempts_log = []
    for attempt in range(1, max_attempts + 1):
        with open(fuzz_target_path, "w", encoding="utf-8") as fh:
            fh.write(harness)
        _register_fuzz_target(crate_dir, target_name)

        try:
            outcome = run_rust_fuzzer(crate_dir, target_name, _VALIDATE_DURATION, _VALIDATE_WORKERS)
            ok, error = True, ""
        except Exception as exc:  # noqa: BLE001 -- error real de build/corrida, se retroalimenta al modelo
            ok, error = False, f"{type(exc).__name__}: {exc}"

        attempts_log.append({"attempt": attempt, "ok": ok, "error": error})
        if ok:
            return {
                "success": True, "harness": harness, "target_name": target_name,
                "crate_name": crate_name, "source_file": filename, "attempts": attempts_log,
            }
        if attempt == max_attempts:
            return {
                "success": False, "harness": harness, "target_name": target_name,
                "crate_name": crate_name, "source_file": filename, "attempts": attempts_log,
            }
        retry_prompt = _RETRY_TEMPLATE.format(error=error[-3000:], previous_harness=harness, rules=_RUST_FUZZ_RULES)
        harness = _call_ollama(retry_prompt)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--crate-dir", required=True, help="clon YA HECHO del crate (no se clona nada solo)")
    parser.add_argument("--function", required=True)
    parser.add_argument("--target-name", default=None)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-attempts", type=int, default=_MAX_ATTEMPTS)
    args = parser.parse_args()

    print(f"Generando y validando harness para {args.function}() en {args.crate_dir}...")
    result = generate_and_validate_rust_harness(args.crate_dir, args.function, args.target_name, args.max_attempts)

    for a in result["attempts"]:
        status = "OK" if a["ok"] else "FALLO"
        print(f"  intento {a['attempt']}: {status}")
        if not a["ok"]:
            print(f"    {a['error'][-600:]}")

    if result["success"]:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["harness"])
        print(f"\nHarness VALIDADO (compila y corre de verdad) -- escrito en {args.out}")
        print(f"target: {result['target_name']} (crate {result['crate_name']}, "
              f"basado en {result['source_file']})")
        print(f"Registrado en {args.crate_dir}/fuzz/Cargo.toml y "
              f"{args.crate_dir}/fuzz/fuzz_targets/{result['target_name']}.rs")
    else:
        print(f"\nNo se pudo validar en {args.max_attempts} intentos -- NO se escribe {args.out}. "
              f"Ultimo error arriba, revision humana necesaria.")
        sys.exit(1)


if __name__ == "__main__":
    main()
