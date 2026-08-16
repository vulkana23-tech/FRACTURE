#!/usr/bin/env python3
"""Conecta find_patch_directed_candidates.py con
harness_gen/generate_race_test.py: busca commits reales de
race-condition/data-race/deadlock en un repo Go, y genera+valida un
test de estrés de concurrencia real (`go test -race`) para el primer
candidato que sobrevive todos los filtros.

Por qué existe un pipeline SEPARADO de patch_directed_go_harness.py:
un commit de race condition no tiene ninguna superficie de bytes de
entrada que fuzzear (`go test -fuzz`/libFuzzer no sirven para esto,
ver harness_gen/generate_race_test.py) -- necesita ejercitar el código
real bajo CONCURRENCIA, con el detector de razas nativo de Go
(`-race`), no con datos aleatorios.

Uso:
  venv/bin/python3 targets/patch_directed_race_harness.py \\
    --repo https://github.com/hyperledger/fabric-lib-go --since-days 400 \\
    --out orchestrator/fuzz_tests/nuevo_race_test.go
"""

import argparse
import os
import re
import sys
from typing import Dict, List, Optional

from find_patch_directed_candidates import find_patch_directed_candidates

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness_gen"))
from generate_race_test import generate_and_validate_race_test  # noqa: E402

# Subconjunto de _SECURITY_KEYWORDS (find_patch_directed_candidates.py)
# especifico de concurrencia -- un commit de "buffer overflow" o
# "null pointer" tambien matchea el filtro general de seguridad, pero
# NO es candidato para este pipeline (esos van a
# patch_directed_go_harness.py, que SI fuzzea bytes).
_RACE_KEYWORDS_RE = re.compile(r"race condition|data race|\brace\b|deadlock", re.IGNORECASE)

# Bug real encontrado corriendo esto en vivo contra
# hyperledger/fabric-lib-go (commit 8fe16c9967): el commit real toca
# factory_test.go en el MISMO commit que el fix (convencion real, ya
# vista tambien en el pipeline de C con cJSON) -- sin filtrar, se
# colaron 11 nombres en un solo prompt (incluyendo TestMain,
# TestBootBCCSPConcurrent -- ironicamente el propio test de regresion
# que el repo real escribio para esta carrera), y el modelo no logro
# compilar nada coherente en 3 intentos. A diferencia de C (sin
# convencion de nombre confiable, se uso una regex heuristica), Go
# GARANTIZA que una funcion de test empieza con "Test" -- es requisito
# real de `go test` para reconocerla, no una heuristica.
_GO_TEST_FUNC_RE = re.compile(r"^Test")

_GO_FUNC_NAME_RE = re.compile(r"^func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(")


def _extract_race_candidates(candidate: Dict) -> List[Dict]:
    """Para UN commit ya filtrado por palabra clave de concurrencia,
    agrupa las funciones Go reales tocadas por paquete (directorio) --
    un stress test de race necesita ver TODAS las funciones
    involucradas en el mismo test, a diferencia de los otros pipelines
    que prueban una funcion a la vez."""
    go_files = [f for f in candidate["files_changed"] if f.endswith(".go") and not f.endswith("_test.go")]
    if not go_files:
        return []

    names = []
    seen = set()
    for context in candidate["functions_touched_guess"]:
        m = _GO_FUNC_NAME_RE.match(context)
        if m and _GO_TEST_FUNC_RE.match(m.group(1)):
            continue
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            names.append(m.group(1))
    if not names:
        return []

    # Un solo directorio por commit en el caso real mas comun (el fix
    # de una race vive en un paquete chico) -- si el commit toca varios
    # paquetes, se prueba cada uno con las mismas funciones (el
    # generador real descarta rapido el que no aplica via el error de
    # compilacion).
    package_paths = []
    for f in go_files:
        d = os.path.dirname(f)
        if d not in package_paths:
            package_paths.append(d)

    return [{"functions": names, "package_path": p} for p in package_paths]


def find_and_generate(
    repo_url: str, since_days: int = 365, max_commits: int = 20, out_path: Optional[str] = None,
) -> dict:
    candidates = find_patch_directed_candidates(repo_url, since_days, max_commits)
    race_commits = [c for c in candidates if _RACE_KEYWORDS_RE.search(c["subject"])]

    attempted = []
    for commit in race_commits:
        for race_candidate in _extract_race_candidates(commit):
            print(f"Probando {', '.join(race_candidate['functions'])} en {race_candidate['package_path']}/ "
                  f"(commit {commit['hash'][:10]} -- {commit['subject']})...")
            try:
                result = generate_and_validate_race_test(
                    repo_url, race_candidate["package_path"], race_candidate["functions"],
                )
            except Exception as exc:  # noqa: BLE001 -- un candidato malo no debe abortar el resto
                attempted.append({**race_candidate, "commit": commit["hash"], "success": False,
                                  "race_detected": False, "error": f"{type(exc).__name__}: {exc}"})
                continue

            attempted.append({**race_candidate, "commit": commit["hash"], "success": result["success"],
                              "race_detected": result.get("race_detected", False)})
            if result["success"]:
                if out_path:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(result["test_code"])
                return {"found": True, "candidate": race_candidate, "commit": commit,
                        "test_result": result, "attempted": attempted}

    return {"found": False, "attempted": attempted}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--since-days", type=int, default=365)
    parser.add_argument("--max-commits", type=int, default=20)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    print(f"Buscando candidatos de race condition en {args.repo}...")
    result = find_and_generate(args.repo, args.since_days, args.max_commits, args.out)

    print(f"\n{len(result['attempted'])} candidato(s) real(es) de race condition probado(s):")
    for a in result["attempted"]:
        marker = " -- CARRERA REAL DETECTADA" if a.get("race_detected") else ""
        status = "OK" if a["success"] else f"fallo ({a.get('error', 'no valido')})"
        print(f"  - {', '.join(a['functions'])} en {a['package_path']}/ (commit {a['commit'][:10]}): {status}{marker}")

    if result["found"]:
        c = result["candidate"]
        marker = " *** CARRERA REAL DETECTADA ***" if result["test_result"]["race_detected"] else " (limpio, sin carrera)"
        print(f"\nTest real generado y validado para {', '.join(c['functions'])}{marker} "
              f"({'guardado en ' + args.out if args.out else 'no guardado, usa --out'})")
    else:
        print("\nNingun candidato real sobrevivió (sin commits de race condition Go en esta ventana, "
              "o ninguno compiló) -- resultado honesto, no un error.")


if __name__ == "__main__":
    main()
