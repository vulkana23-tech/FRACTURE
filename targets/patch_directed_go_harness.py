#!/usr/bin/env python3
"""Conecta find_patch_directed_candidates.py con
harness_gen/generate_go_harness.py: busca commits de seguridad reales
en un repo Go, descarta los marcados como ciclo de vida de V8/JS (no
aplica muy seguido a repos Go, pero la funcion ya existe y es gratis
reusarla) y los que no tienen ninguna funcion Go real identificable en
el diff, y genera+valida un harness real para el primer candidato que
sobrevive todos los filtros -- sin copiar/pegar nombres de funcion a
mano entre los dos scripts.

Uso:
  venv/bin/python3 targets/patch_directed_go_harness.py \\
    --repo https://github.com/hyperledger/fabric-gateway --since-days 365 \\
    --out orchestrator/fuzz_tests/nuevo_test.go
"""

import argparse
import os
import re
import sys
from typing import Dict, List, Optional

from find_patch_directed_candidates import find_patch_directed_candidates

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness_gen"))
from generate_go_harness import generate_and_validate_go_harness  # noqa: E402

# "func (mgr *Mgr) ProcessAttributeRequestsForCert(requests []AttributeRequest..."
# -> "ProcessAttributeRequestsForCert". Metodo o funcion libre, ambos
# formatos reales de Go.
_GO_FUNC_NAME_RE = re.compile(r"^func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(")

# Bug real encontrado corriendo esto en vivo contra hyperledger/fabric
# (2026-08-15): sin este filtro, el primer candidato real que salio fue
# `Ready() chan struct{}` -- compila y corre de verdad (harness VALIDO),
# pero no toma NINGUN parametro real, asi que el harness generado solo
# fuzzeaba un uint64 arbitrario sin ningun valor real de fuzzing (no
# hay superficie de bytes no confiables que ejercitar). Preferir
# candidatos cuya firma menciona []byte/string -- imperfecto (puede
# ser un tipo de RETORNO, no de parametro, si el contexto que git
# infirio esta truncado o incluye el return type) pero mejor que nada.
_LOOKS_LIKE_BYTE_INPUT_RE = re.compile(r"\[\]byte|\bstring\b")


def _extract_go_candidates(candidate: Dict) -> List[Dict]:
    """Para UN commit ya filtrado, devuelve (funcion, archivo .go real)
    por cada contexto de hunk que matchea una firma de funcion Go real
    -- nunca inventa un nombre que git no haya anclado el mismo. Prioriza
    primero los candidatos cuya firma sugiere que toma bytes/strings
    reales como parametro (ver _LOOKS_LIKE_BYTE_INPUT_RE) -- el resto
    se devuelve despues, como fallback, no se descarta del todo."""
    go_files = [f for f in candidate["files_changed"] if f.endswith(".go") and not f.endswith("_test.go")]
    if not go_files:
        return []

    likely_fuzzable = []
    fallback = []
    for context in candidate["functions_touched_guess"]:
        m = _GO_FUNC_NAME_RE.match(context)
        if not m:
            continue
        # No hay forma barata de saber a CUAL archivo de los tocados
        # pertenece este contexto puntual sin re-parsear el diff por
        # hunk -- si el commit toca un solo archivo .go real, es
        # inambiguo; si toca varios, se prueban todos como candidatos
        # (el compilador real descarta rapido el que no aplica).
        bucket = likely_fuzzable if _LOOKS_LIKE_BYTE_INPUT_RE.search(context) else fallback
        for f in go_files:
            bucket.append({
                "function_name": m.group(1),
                "file_path": f,
                "package_path": os.path.dirname(f),
            })
    return likely_fuzzable + fallback


def find_and_generate(
    repo_url: str, since_days: int = 365, max_commits: int = 20, out_path: Optional[str] = None,
) -> dict:
    candidates = find_patch_directed_candidates(repo_url, since_days, max_commits)
    fuzzable_commits = [c for c in candidates if not c["js_engine_lifecycle_bound"]]

    attempted = []
    for commit in fuzzable_commits:
        for go_candidate in _extract_go_candidates(commit):
            print(f"Probando {go_candidate['function_name']}() en {go_candidate['package_path']}/ "
                  f"(commit {commit['hash'][:10]} -- {commit['subject']})...")
            try:
                result = generate_and_validate_go_harness(
                    repo_url, go_candidate["package_path"], go_candidate["function_name"],
                )
            except Exception as exc:  # noqa: BLE001 -- un candidato malo (funcion no encontrada, etc.) no debe abortar el resto
                attempted.append({**go_candidate, "commit": commit["hash"], "success": False,
                                  "error": f"{type(exc).__name__}: {exc}"})
                continue

            attempted.append({**go_candidate, "commit": commit["hash"], "success": result["success"]})
            if result["success"]:
                if out_path:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(result["harness"])
                return {"found": True, "candidate": go_candidate, "commit": commit,
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

    print(f"\n{len(result['attempted'])} candidato(s) real(es) de funcion Go probado(s):")
    for a in result["attempted"]:
        status = "OK" if a["success"] else f"fallo ({a.get('error', 'no valido')})"
        print(f"  - {a['function_name']}() en {a['package_path']}/ (commit {a['commit'][:10]}): {status}")

    if result["found"]:
        c = result["candidate"]
        print(f"\nHarness real generado y validado para {c['function_name']}() "
              f"({'guardado en ' + args.out if args.out else 'no guardado, usa --out'})")
    else:
        print("\nNingun candidato real sobrevivió (sin commits de seguridad Go fuzzeables "
              "en esta ventana, o ninguno compiló) -- resultado honesto, no un error.")


if __name__ == "__main__":
    main()
