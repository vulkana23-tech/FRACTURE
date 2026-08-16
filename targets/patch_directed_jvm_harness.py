#!/usr/bin/env python3
"""Conecta find_patch_directed_candidates.py con
harness_gen/generate_jvm_harness.py: busca commits de seguridad reales
en un repo Java, descarta los marcados como ciclo de vida de V8/JS
(irrelevante para JVM en la practica, pero la funcion ya existe y es
gratis reusarla), extrae nombres de clase/metodo Java reales, y
genera+valida un harness real para el primer candidato que sobrevive.

Mismo patron que la version Rust (targets/patch_directed_rust_harness.py):
el classpath real (--classes-dir/--lib-dir) tiene que estar YA
PREPARADO de forma PERSISTENTE (ver build/jvm_targets/<target>/) --
--repo se usa solo para escanear historial, un clon temporal aparte.

Uso:
  venv/bin/python3 targets/patch_directed_jvm_harness.py \\
    --repo https://github.com/hyperledger/fabric-chaincode-java \\
    --classes-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/classes \\
    --lib-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/lib \\
    --since-days 730 --out orchestrator/fuzz_harnesses/nuevo.java
"""

import argparse
import os
import re
import sys
from typing import Dict, List, Optional

from find_patch_directed_candidates import find_patch_directed_candidates

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness_gen"))
from generate_jvm_harness import generate_and_validate_jvm_harness  # noqa: E402

# "public byte[] toBuffer(final Object o, ..." -> "toBuffer". Cubre
# public/private/protected, static/final opcionales, cualquier tipo de
# retorno (incluso generics/arrays) -- ultimo identificador antes del
# parentesis de argumentos.
_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w.<>\[\],\s]+?\s+(\w+)\s*\([^)]*\)"
    r"(?:\s+throws\s+[\w.,\s]+)?\s*\{?\s*$",
    re.MULTILINE,
)
_LOOKS_LIKE_BYTE_INPUT_RE = re.compile(r"byte\s*\[\s*\]|\bString\b")


def _class_fqn_from_file(file_path: str) -> Optional[str]:
    """"src/main/java/org/x/Y.java" -> "org.x.Y" (asume el layout
    Maven/Gradle estandar src/main/java/... -- si no matchea, None."""
    m = re.search(r"src/main/java/(.+)\.java$", file_path)
    if not m:
        return None
    return m.group(1).replace("/", ".")


def _extract_jvm_candidates(candidate: Dict) -> List[Dict]:
    java_files = [f for f in candidate["files_changed"]
                  if f.endswith(".java") and "/test/" not in f and not f.endswith("Test.java")]
    if not java_files:
        return []

    names_found = set()
    for context in candidate["functions_touched_guess"]:
        m = _JAVA_METHOD_RE.match(context)
        if m:
            names_found.add(m.group(1))
    # Mismo motivo real ya documentado en la version Rust: git ancla el
    # contexto del hunk a la clase contenedora, no siempre al metodo --
    # escanear el cuerpo crudo del diff encuentra lo que el header se
    # perdio.
    for m in _JAVA_METHOD_RE.finditer(candidate.get("diff_excerpt", "")):
        names_found.add(m.group(1))

    likely_fuzzable = []
    fallback = []
    for name in names_found:
        sig_re = re.compile(rf"\b{re.escape(name)}\s*\([^)]*\)")
        m = sig_re.search(candidate.get("diff_excerpt", ""))
        signature = m.group(0) if m else ""
        bucket = likely_fuzzable if _LOOKS_LIKE_BYTE_INPUT_RE.search(signature) else fallback
        for f in java_files:
            class_fqn = _class_fqn_from_file(f)
            if class_fqn is None:
                continue
            bucket.append({"function_name": name, "class_fqn": class_fqn, "file_path": f})
    return likely_fuzzable + fallback


def find_and_generate(
    repo_url: str, classes_dir: str, lib_dir: str, since_days: int = 365, max_commits: int = 20,
    out_path: Optional[str] = None,
) -> dict:
    candidates = find_patch_directed_candidates(repo_url, since_days, max_commits)
    fuzzable_commits = [c for c in candidates if not c["js_engine_lifecycle_bound"]]

    attempted = []
    for commit in fuzzable_commits:
        for jvm_candidate in _extract_jvm_candidates(commit):
            print(f"Probando {jvm_candidate['class_fqn']}#{jvm_candidate['function_name']}() "
                  f"(commit {commit['hash'][:10]} -- {commit['subject']})...")
            try:
                result = generate_and_validate_jvm_harness(
                    repo_url, classes_dir, lib_dir,
                    jvm_candidate["class_fqn"], jvm_candidate["function_name"],
                )
            except Exception as exc:  # noqa: BLE001 -- un candidato malo no debe abortar el resto
                attempted.append({**jvm_candidate, "commit": commit["hash"], "success": False,
                                  "error": f"{type(exc).__name__}: {exc}"})
                continue

            attempted.append({**jvm_candidate, "commit": commit["hash"], "success": result["success"]})
            if result["success"]:
                if out_path:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(result["harness"])
                return {"found": True, "candidate": jvm_candidate, "commit": commit,
                        "harness_result": result, "attempted": attempted}

    return {"found": False, "attempted": attempted}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--classes-dir", required=True)
    parser.add_argument("--lib-dir", required=True)
    parser.add_argument("--since-days", type=int, default=365)
    parser.add_argument("--max-commits", type=int, default=20)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    print(f"Buscando candidatos dirigidos por parche en {args.repo}...")
    result = find_and_generate(args.repo, args.classes_dir, args.lib_dir, args.since_days, args.max_commits, args.out)

    print(f"\n{len(result['attempted'])} candidato(s) real(es) de metodo Java probado(s):")
    for a in result["attempted"]:
        status = "OK" if a["success"] else f"fallo ({a.get('error', 'no valido')})"
        print(f"  - {a['class_fqn']}#{a['function_name']}() (commit {a['commit'][:10]}): {status}")

    if result["found"]:
        c = result["candidate"]
        print(f"\nHarness real generado y validado para {c['class_fqn']}#{c['function_name']}() "
              f"({'guardado en ' + args.out if args.out else 'no guardado, usa --out'})")
    else:
        print("\nNingun candidato real sobrevivió -- resultado honesto, no un error.")


if __name__ == "__main__":
    main()
