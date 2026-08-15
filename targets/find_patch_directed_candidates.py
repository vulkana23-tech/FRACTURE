#!/usr/bin/env python3
"""Fuzzing dirigido por parche: busca commits recientes de un repo real
que TOCAN codigo relacionado a seguridad (por mensaje de commit --
"fix overflow", "CVE-...", "null pointer", "out of bounds", etc.) y
extrae que funcion real cambio, para priorizarla como candidato de
`harness_gen/` -- el codigo ALREDEDOR de un parche reciente es donde
mas probablemente haya variantes del mismo bug o un fix incompleto, y
es mucho mas rapido de encontrar leyendo diffs reales que fuzzing
ciego. Tecnica real de bug bounty (muchos programas pagan
"regresion"/"fix incompleto"), no algo teorico.

100% local despues del clone (git log/show), sin llamadas a la API de
GitHub -- no compite por el rate limit que ya usa select_targets.py.

Uso:
  venv/bin/python3 targets/find_patch_directed_candidates.py \\
    --repo https://github.com/coinbase/cb-mpc-go --since-days 365
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

_CLONE_TIMEOUT = 120
_GIT_TIMEOUT = 30

# Palabras clave reales que un commit de seguridad/bugfix de memoria
# suele tener en el mensaje -- ingles Y español (algunos proyectos
# grandes de LatAm/España commitean en español), case-insensitive.
_SECURITY_KEYWORDS = re.compile(
    r"\b("
    r"overflow|underflow|out[- ]of[- ]bounds|\boob\b|"
    r"null[- ]?pointer|nil pointer|use[- ]after[- ]free|\buaf\b|double[- ]free|"
    r"race condition|data race|panic|segfault|sigsegv|deadlock|"
    r"cve-\d+|vulnerab\w*|exploit\w*|unsafe|"
    r"bound\w* check|sanitiz\w*|injection|"
    r"deserializ\w*|unmarshal\w*|malformed|untrusted|"
    r"buffer|denial[- ]of[- ]service|\bdos\b|"
    r"security|hardening|"
    r"desbordamiento|puntero nulo|fuera de (los )?l[ií]mites|vulnerabilidad"
    r")\b",
    re.IGNORECASE,
)

# git incluye la firma de la funcion que contiene el hunk en la linea
# "@@ ... @@ <contexto>" cuando puede inferirla (heuristica propia de
# git, no siempre acierta, pero cuando esta es gratis y confiable).
_HUNK_FUNC_RE = re.compile(r"^@@ .+ @@ ?(.+)$", re.MULTILINE)

# Bug real encontrado probando esto en vivo contra fabric-ca: TODOS los
# primeros hits reales eran bumps de dependencias/CI ("Update
# dependencies to address CVE-...", go.mod/go.sum/vendor/.github) o
# config de scanners (osv-scanner.toml) -- el mensaje SI menciona
# "CVE"/"vulnerab" (matchea bien), pero nada de codigo propio cambio.
# Intentar enumerar cada archivo de "ruido" posible (go.mod, Makefile,
# osv-scanner.toml, la proxima herramienta de turno...) es whack-a-mole
# sin fin -- se probo esa lista negra primero y un archivo nuevo
# (osv-scanner.toml) la esquivo en la primera corrida real. Lista
# BLANCA en vez de negra: un commit solo es candidato real si toca al
# menos un archivo de codigo fuente de un lenguaje que este proyecto
# fuzzea -- mucho mas robusto, no necesita mantenimiento cada vez que
# aparece una herramienta de CI nueva.
_SOURCE_CODE_EXT_RE = re.compile(
    r"\.(c|cc|cpp|cxx|h|hpp|hxx|go|rs|java|py|js|jsx|ts|tsx)$"
)
# Segundo hallazgo real en la misma corrida contra fabric-ca: un bump de
# dependencias SI toca archivos .go de verdad -- los del propio
# vendor/ (Go vendorea las dependencias completas, con extension real).
# Eso es codigo de TERCEROS, no del repo que se esta evaluando -- ese
# vendor/dependency ya tiene (o no) su propia cobertura de fuzzing por
# su cuenta, harnessearlo desde ACA es re-trabajo. docs/ tambien se
# excluye -- codigo Python/JS real pero de tooling de documentacion,
# no logica de la aplicacion.
_NON_APPLICATION_PATH_PREFIX_RE = re.compile(
    r"^(vendor|node_modules|third_party|docs)/"
)


def _has_source_code_change(files_changed: List[str]) -> bool:
    return any(
        _SOURCE_CODE_EXT_RE.search(f) and not _NON_APPLICATION_PATH_PREFIX_RE.match(f)
        for f in files_changed
    )


def _clone_with_history(repo_url: str, since_days: int) -> str:
    tmpdir = tempfile.mkdtemp(prefix="fracture_patchdir_")
    since_date = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%d")
    try:
        subprocess.run(
            ["git", "clone", f"--shallow-since={since_date}", repo_url, tmpdir],
            capture_output=True, timeout=_CLONE_TIMEOUT, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"clone fallo para {repo_url}: {e}") from e
    return tmpdir


def _list_security_relevant_commits(repo_dir: str) -> List[Dict]:
    result = subprocess.run(
        ["git", "log", "--pretty=format:%H|%ad|%s", "--date=short"],
        cwd=repo_dir, capture_output=True, text=True, timeout=_GIT_TIMEOUT, check=True,
    )
    commits = []
    for line in result.stdout.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        commit_hash, date, subject = parts
        if _SECURITY_KEYWORDS.search(subject):
            commits.append({"hash": commit_hash, "date": date, "subject": subject})
    return commits


def _diff_for_commit(repo_dir: str, commit_hash: str) -> str:
    result = subprocess.run(
        ["git", "show", "--unified=2", commit_hash],
        cwd=repo_dir, capture_output=True, text=True, timeout=_GIT_TIMEOUT, check=True,
    )
    return result.stdout


def _changed_files(repo_dir: str, commit_hash: str) -> List[str]:
    result = subprocess.run(
        ["git", "show", "--name-only", "--pretty=format:", commit_hash],
        cwd=repo_dir, capture_output=True, text=True, timeout=_GIT_TIMEOUT, check=True,
    )
    return [f for f in result.stdout.splitlines() if f.strip()]


def _guess_functions_touched(diff_text: str) -> List[str]:
    """Nunca inventa un nombre -- si git no pudo inferir el contexto del
    hunk (contenido vacio despues del segundo '@@'), se descarta ese
    hunk en vez de adivinar."""
    guesses = []
    for m in _HUNK_FUNC_RE.finditer(diff_text):
        context = m.group(1).strip()
        if context:
            guesses.append(context)
    return guesses


# Heuristica real agregada despues de investigar a mano 3 candidatos
# reales de cloudflare/workerd (ver harness_gen/README.md, "Intento
# real: candidato de workerd") -- los 3 eran bugs de ciclo de vida de
# V8/JS (re-entrancy, GC de buffers, semantica de capacidades RPC),
# nunca fuzzeables con libFuzzer porque necesitan el motor V8 real
# corriendo una secuencia de llamadas JS. Las 3 firmas reales tenian
# `jsg::Lock`/`jsg::Ref`/`jsg::Deserializer`/`v8::` en el contexto del
# hunk -- marcador barato y real (no perfecto: puede haber falsos
# positivos/negativos, es una señal de alerta para revision humana, no
# un filtro duro que descarta candidatos solo).
_JS_ENGINE_LIFECYCLE_MARKER_RE = re.compile(r"jsg::|v8::|V8::")


def _looks_js_engine_lifecycle_bound(functions_touched_guess: List[str]) -> bool:
    return any(_JS_ENGINE_LIFECYCLE_MARKER_RE.search(f) for f in functions_touched_guess)


def find_patch_directed_candidates(repo_url: str, since_days: int = 365, max_commits: int = 20) -> List[Dict]:
    repo_dir = _clone_with_history(repo_url, since_days)
    try:
        commits = _list_security_relevant_commits(repo_dir)

        # Primero descartar los que son SOLO bumps de dependencias/CI --
        # barato (solo --name-only, sin el diff completo) -- recien
        # despues pedir el diff real de los que sobreviven, para no
        # gastar ese trabajo en commits que se van a tirar igual.
        real_candidates = []
        for c in commits:
            files = _changed_files(repo_dir, c["hash"])
            if not _has_source_code_change(files):
                continue
            real_candidates.append({**c, "files_changed": files})
            if len(real_candidates) >= max_commits:
                break

        candidates = []
        for c in real_candidates:
            diff_text = _diff_for_commit(repo_dir, c["hash"])
            functions = _guess_functions_touched(diff_text)
            candidates.append({
                **c,
                "functions_touched_guess": functions,
                "js_engine_lifecycle_bound": _looks_js_engine_lifecycle_bound(functions),
                "diff_excerpt": diff_text[:2000],
            })
        return candidates
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--since-days", type=int, default=365)
    parser.add_argument("--max-commits", type=int, default=20)
    args = parser.parse_args()

    print(f"Clonando {args.repo} (historial desde hace {args.since_days} dias)...")
    candidates = find_patch_directed_candidates(args.repo, args.since_days, args.max_commits)

    if not candidates:
        print("Sin commits con mensaje relacionado a seguridad en esa ventana de tiempo.")
        return

    fuzzable = [c for c in candidates if not c["js_engine_lifecycle_bound"]]
    lifecycle_bound = [c for c in candidates if c["js_engine_lifecycle_bound"]]
    print(f"\n{len(candidates)} commit(s) real(es) con mensaje relacionado a seguridad "
          f"({len(fuzzable)} candidato(s) real(es), {len(lifecycle_bound)} probablemente "
          f"NO fuzzeable(s) con libFuzzer -- ver abajo):\n")
    for c in candidates:
        marker = "  ⚠️  probablemente ciclo de vida de V8/JS, NO byte-parsing -- revisar el diff a mano antes de generar un harness" if c["js_engine_lifecycle_bound"] else ""
        print(f"[{c['date']}] {c['hash'][:10]} -- {c['subject']}{marker}")
        print(f"  archivos: {', '.join(c['files_changed'][:5])}"
              f"{' ...' if len(c['files_changed']) > 5 else ''}")
        if c["functions_touched_guess"]:
            print(f"  funciones/contexto tocado (heuristica de git, no siempre exacta):")
            for f in c["functions_touched_guess"][:5]:
                print(f"    - {f}")
        print()


if __name__ == "__main__":
    main()
