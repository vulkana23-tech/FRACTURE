#!/usr/bin/env python3
"""Conecta find_patch_directed_candidates.py con
harness_gen/generate_harness.py (C): busca commits de seguridad reales
en un repo C/C++, descarta los marcados como ciclo de vida de V8/JS, y
genera+valida un harness real para el primer par (header, funcion) que
sobrevive todos los filtros -- sin copiar/pegar nombres a mano entre
los dos scripts. Ultimo lenguaje que faltaba conectar (Go, Rust y JVM
ya lo estaban, ver targets/README.md).

Limitacion real heredada de generate_harness.py, no de este pipeline:
solo cubre librerias chicas amalgamadas en 1-2 archivos (header +
.c del mismo nombre base) -- un candidato de un proyecto grande y
multi-archivo (workerd, cb-mpc) va a fallar la validacion real (source
files no encontrados) y se descarta, resultado honesto, no un bug.

Uso:
  venv/bin/python3 targets/patch_directed_c_harness.py \\
    --repo https://github.com/DaveGamble/cJSON --since-days 365 \\
    --out orchestrator/fuzz_harnesses/nuevo.c
"""

import argparse
import os
import re
import sys
from typing import Dict, List, Optional

from find_patch_directed_candidates import find_patch_directed_candidates

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness_gen"))
from generate_harness import generate_and_validate_harness  # noqa: E402

# Firma real de C/C++: identificador seguido de "(" -- a diferencia de
# Go (palabra clave "func" real, sin ambiguedad), C no tiene marcador
# sintactico propio, asi que hay que filtrar palabras clave de control
# de flujo que tambien matchean "identificador(" (if/for/while/switch)
# para no confundir un `if (condicion)` con una funcion real.
_C_FUNC_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_C_CONTROL_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "defined",
    "catch", "static_assert", "assert", "typedef",
}

# Igual criterio que _LOOKS_LIKE_BYTE_INPUT_RE de Go/Rust: preferir
# candidatos cuya firma sugiere que toma bytes/strings no confiables
# como parametro -- superficie de fuzzing real, no un getter/setter
# sin entrada externa.
_LOOKS_LIKE_BYTE_INPUT_RE = re.compile(
    r"const\s+char\s*\*|char\s*\*|uint8_t\s*\*|unsigned\s+char\s*\*|const\s+void\s*\*|size_t"
)

# Bug real encontrado corriendo esto en vivo contra DaveGamble/cJSON
# (commit b2890c8d76, "prevent NULL pointer dereference in
# cJSON_SetNumberHelper"): el commit tambien toca tests/misc_tests.c
# (convencion real de cJSON, tests en el mismo commit que el fix), y
# el contexto de un hunk ahi ("static void
# cjson_functions_should_not_crash_with_null_pointers(void)") se coló
# como candidato -- func_touched_guess no distingue de que ARCHIVO vino
# cada contexto (misma limitacion que Go ya documenta, ahi se resuelve
# filtrando _test.go completo ANTES de extraer nombres; en C no hay
# convencion de sufijo tan uniforme). El modelo, con buen criterio,
# ignoro el nombre de funcion inexistente en el header y genero un
# harness igual (VALIDO -- compila y corre) pero fuzzeando cJSON_Parse
# en general, no la funcion real del fix. Filtro barato, igual espiritu
# que _JS_ENGINE_LIFECYCLE_MARKER_RE: nunca perfecto, pero descarta el
# caso real encontrado sin tener que resolver atribucion por archivo.
_LOOKS_LIKE_TEST_FUNCTION_RE = re.compile(r"test|should", re.IGNORECASE)

_SOURCE_EXT_RE = re.compile(r"\.(c|cc|cpp|cxx)$")
_HEADER_EXT_RE = re.compile(r"\.(h|hpp|hxx)$")


def _c_function_name_from_context(context: str) -> Optional[str]:
    """Nunca inventa un nombre -- toma el ULTIMO identificador real
    seguido de '(' que no sea una palabra clave de control de flujo, o
    None si no hay ninguno (linea de contexto que no es una firma de
    funcion real, ej. "typedef struct {").

    Bug real encontrado escribiendo el test (no en produccion, pero
    real): cJSON envuelve el tipo de retorno en un macro real,
    `CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value)` -- tomar el
    PRIMER match agarraba `CJSON_PUBLIC` (el macro), no `cJSON_Parse`
    (la funcion real). En una declaracion de C real, calificadores y
    macros de atributos van ANTES del nombre declarado -- el ULTIMO
    identificador-seguido-de-'(' es casi siempre el nombre real."""
    name = None
    for m in _C_FUNC_CALL_RE.finditer(context):
        candidate = m.group(1)
        if candidate not in _C_CONTROL_KEYWORDS:
            name = candidate
    return name


def _header_name_for_source(path: str) -> Optional[str]:
    """cJSON.c -> cJSON.h (misma convencion real que
    _find_matching_source_file en generate_harness.py, en la direccion
    inversa: de codigo fuente tocado a que header buscarle)."""
    base, ext = os.path.splitext(os.path.basename(path))
    if _SOURCE_EXT_RE.search(path):
        return base + ".h"
    if _HEADER_EXT_RE.search(path):
        return os.path.basename(path)
    return None


def _extract_c_candidates(candidate: Dict) -> List[Dict]:
    """Para UN commit ya filtrado, devuelve (funcion, header real) por
    cada combinacion de nombre de funcion real (extraido del contexto
    de hunk, git O AST -- ver find_patch_directed_candidates.py) y
    nombre de header real derivado de los archivos .c/.h que este
    commit tocó. Prioriza los candidatos cuya firma sugiere que toma
    bytes/strings reales."""
    c_files = [
        f for f in candidate["files_changed"]
        if (_SOURCE_EXT_RE.search(f) or _HEADER_EXT_RE.search(f))
    ]
    if not c_files:
        return []

    header_names = []
    for f in c_files:
        h = _header_name_for_source(f)
        if h and h not in header_names:
            header_names.append(h)
    if not header_names:
        return []

    likely_fuzzable = []
    fallback = []
    seen_names = set()
    for context in candidate["functions_touched_guess"]:
        name = _c_function_name_from_context(context)
        if not name or name in seen_names:
            continue
        if _LOOKS_LIKE_TEST_FUNCTION_RE.search(name):
            continue
        seen_names.add(name)
        bucket = likely_fuzzable if _LOOKS_LIKE_BYTE_INPUT_RE.search(context) else fallback
        for header_name in header_names:
            bucket.append({"function_name": name, "header_name": header_name})
    return likely_fuzzable + fallback


def find_and_generate(
    repo_url: str, since_days: int = 365, max_commits: int = 20, out_path: Optional[str] = None,
) -> dict:
    candidates = find_patch_directed_candidates(repo_url, since_days, max_commits)
    fuzzable_commits = [c for c in candidates if not c["js_engine_lifecycle_bound"]]

    attempted = []
    for commit in fuzzable_commits:
        for c_candidate in _extract_c_candidates(commit):
            print(f"Probando {c_candidate['function_name']}() en {c_candidate['header_name']} "
                  f"(commit {commit['hash'][:10]} -- {commit['subject']})...")
            try:
                result = generate_and_validate_harness(
                    repo_url, c_candidate["header_name"], c_candidate["function_name"],
                )
            except Exception as exc:  # noqa: BLE001 -- un candidato malo no debe abortar el resto
                attempted.append({**c_candidate, "commit": commit["hash"], "success": False,
                                  "error": f"{type(exc).__name__}: {exc}"})
                continue

            attempted.append({**c_candidate, "commit": commit["hash"], "success": result["success"],
                              "error": result.get("error", "")})
            if result["success"]:
                if out_path:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(result["harness"])
                return {"found": True, "candidate": c_candidate, "commit": commit,
                        "harness_result": result, "attempted": attempted}

    return {"found": False, "attempted": attempted}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--since-days", type=int, default=365)
    parser.add_argument("--max-commits", type=int, default=20)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    print(f"Buscando candidatos dirigidos por parche en {args.repo}...")
    result = find_and_generate(args.repo, args.since_days, args.max_commits, args.out)

    print(f"\n{len(result['attempted'])} candidato(s) real(es) de funcion C probado(s):")
    for a in result["attempted"]:
        status = "OK" if a["success"] else f"fallo ({a.get('error', 'no valido')[:200]})"
        print(f"  - {a['function_name']}() en {a['header_name']} (commit {a['commit'][:10]}): {status}")

    if result["found"]:
        c = result["candidate"]
        print(f"\nHarness real generado y validado para {c['function_name']}() "
              f"({'guardado en ' + args.out if args.out else 'no guardado, usa --out'})")
    else:
        print("\nNingun candidato real sobrevivió (sin commits de seguridad C fuzzeables "
              "en esta ventana, ninguno con header+.c amalgamados, o ninguno compiló) "
              "-- resultado honesto, no un error.")


if __name__ == "__main__":
    main()
