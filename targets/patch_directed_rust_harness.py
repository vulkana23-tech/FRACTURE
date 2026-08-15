#!/usr/bin/env python3
"""Conecta find_patch_directed_candidates.py con
harness_gen/generate_rust_harness.py: busca commits de seguridad
reales en un repo Rust, descarta los marcados como ciclo de vida de
V8/JS, extrae nombres de funcion Rust publica real, y genera+valida un
harness real para el primer candidato que sobrevive todos los filtros.

A diferencia de la version para Go (targets/patch_directed_go_harness.py,
que clona el repo fresco cada vez), acá el crate ya tiene que estar
clonado de forma PERSISTENTE bajo build/rust_targets/<crate> (mismo
patrón que generate_rust_harness.py/run_rust_fuzzer.py ya establecen
para Rust en este proyecto) -- --repo se usa SOLO para escanear
historial de commits (clon temporal aparte, se descarta), --crate-dir
es el clon real que se usa para generar/compilar/correr.

Uso:
  venv/bin/python3 targets/patch_directed_rust_harness.py \\
    --repo https://github.com/filecoin-project/bellperson \\
    --crate-dir /opt/fracture/build/rust_targets/bellperson --since-days 1460 \\
    --out orchestrator/fuzz_harnesses/nuevo.rs
"""

import argparse
import os
import re
import sys
from typing import Dict, List, Optional

from find_patch_directed_candidates import find_patch_directed_candidates

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness_gen"))
from generate_rust_harness import generate_and_validate_rust_harness  # noqa: E402

# "pub fn read_many(proof_bytes: &[u8], num_proofs: usize) -> ..." -> "read_many"
_RUST_FUNC_NAME_RE = re.compile(r"pub\s+fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(")

# Mismo motivo real que _LOOKS_LIKE_BYTE_INPUT_RE de
# patch_directed_go_harness.py: preferir candidatos cuya firma sugiere
# que toma bytes/strings reales.
_LOOKS_LIKE_BYTE_INPUT_RE = re.compile(r"&\s*\[\s*u8\s*\]|Vec\s*<\s*u8\s*>|&\s*str\b|\bString\b")


def _extract_rust_candidates(candidate: Dict) -> List[Dict]:
    """Bug real encontrado en produccion (2026-08-16, ver
    harness_gen/README.md): el contexto de hunk que infiere `git show`
    frecuentemente ancla en el bloque `impl<...> Tipo {` que CONTIENE
    la funcion nueva, no en la firma `pub fn` real (mismo patron ya
    visto con metodos C++ definidos inline) -- confirmado en vivo
    contra el commit real de bellperson (`read_many`, "proof_bytes is
    untrusted, user input" en el propio mensaje del commit, pero el
    contexto de git solo decia "impl<E: Engine> Proof<E> {"). Por eso
    ademas de mirar functions_touched_guess (como hace la version de
    Go), ESTE extractor tambien escanea el cuerpo crudo del diff
    (diff_excerpt) por firmas `pub fn` reales -- ahi SI aparece la
    firma completa como linea de contexto normal del hunk, aunque git
    no la haya elegido como el header `@@ @@`."""
    rust_files = [f for f in candidate["files_changed"]
                  if f.endswith(".rs") and "/tests/" not in f and not f.endswith("_test.rs")]
    if not rust_files:
        return []

    names_found = set()
    for context in candidate["functions_touched_guess"]:
        m = _RUST_FUNC_NAME_RE.search(context)
        if m:
            names_found.add(m.group(1))
    for m in _RUST_FUNC_NAME_RE.finditer(candidate.get("diff_excerpt", "")):
        names_found.add(m.group(1))

    likely_fuzzable = []
    fallback = []
    for name in names_found:
        # Prioridad real: si el nombre aparece cerca de "&[u8]"/etc en
        # el excerpt del diff, es candidato fuerte.
        context_snippet_re = re.compile(rf"pub\s+fn\s+{re.escape(name)}[^\n]*")
        m = context_snippet_re.search(candidate.get("diff_excerpt", ""))
        signature = m.group(0) if m else ""
        bucket = likely_fuzzable if _LOOKS_LIKE_BYTE_INPUT_RE.search(signature) else fallback
        for f in rust_files:
            bucket.append({"function_name": name, "file_path": f})
    return likely_fuzzable + fallback


def find_and_generate(
    repo_url: str, crate_dir: str, since_days: int = 365, max_commits: int = 20,
    out_path: Optional[str] = None,
) -> dict:
    candidates = find_patch_directed_candidates(repo_url, since_days, max_commits)
    fuzzable_commits = [c for c in candidates if not c["js_engine_lifecycle_bound"]]

    attempted = []
    for commit in fuzzable_commits:
        for rust_candidate in _extract_rust_candidates(commit):
            print(f"Probando {rust_candidate['function_name']}() (archivo {rust_candidate['file_path']}, "
                  f"commit {commit['hash'][:10]} -- {commit['subject']})...")
            try:
                result = generate_and_validate_rust_harness(crate_dir, rust_candidate["function_name"])
            except Exception as exc:  # noqa: BLE001 -- un candidato malo no debe abortar el resto
                attempted.append({**rust_candidate, "commit": commit["hash"], "success": False,
                                  "error": f"{type(exc).__name__}: {exc}"})
                continue

            attempted.append({**rust_candidate, "commit": commit["hash"], "success": result["success"]})
            if result["success"]:
                if out_path:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(result["harness"])
                return {"found": True, "candidate": rust_candidate, "commit": commit,
                        "harness_result": result, "attempted": attempted}

    return {"found": False, "attempted": attempted}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="para escanear historial -- clon temporal aparte")
    parser.add_argument("--crate-dir", required=True, help="clon persistente real (build/rust_targets/<crate>)")
    parser.add_argument("--since-days", type=int, default=365)
    parser.add_argument("--max-commits", type=int, default=20)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    print(f"Buscando candidatos dirigidos por parche en {args.repo}...")
    result = find_and_generate(args.repo, args.crate_dir, args.since_days, args.max_commits, args.out)

    print(f"\n{len(result['attempted'])} candidato(s) real(es) de funcion Rust probado(s):")
    for a in result["attempted"]:
        status = "OK" if a["success"] else f"fallo ({a.get('error', 'no valido')})"
        print(f"  - {a['function_name']}() ({a['file_path']}, commit {a['commit'][:10]}): {status}")

    if result["found"]:
        c = result["candidate"]
        print(f"\nHarness real generado y validado para {c['function_name']}() "
              f"({'guardado en ' + args.out if args.out else 'no guardado, usa --out'})")
    else:
        print("\nNingun candidato real sobrevivió -- resultado honesto, no un error.")


if __name__ == "__main__":
    main()
