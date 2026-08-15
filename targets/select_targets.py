#!/usr/bin/env python3
"""Selecciona que repos de programas de bug bounty ya trackeados por
SPECTRE valen la pena fuzzear: solo lectura contra la base de SPECTRE
(nunca escribe ahi), cruzado contra GitHub (lenguaje real del repo) y
contra OSS-Fuzz (si Google ya lo fuzzea 24/7 hace años, no vale la pena
duplicar ese esfuerzo).

Uso:
  venv/bin/python3 targets/select_targets.py [--program handle]
"""

import argparse
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import psycopg2
import requests

from config import SPECTRE_DATABASE_URL

_TIMEOUT = 15
_PACE_SECONDS = 0.5  # buen ciudadano contra la API publica de GitHub (rate limit real sin auth: 60/hora)

# Tier 1: lenguajes donde fuzzing tradicionalmente encuentra bugs de
# memoria reales (el tipo de hallazgo que paga bounties grandes).
# Tier 2: Go -- memory-safe por diseño (bounds checking nativo), pero
# fuzzing igual encuentra panics/logica rota real via `go test -fuzz`
# (nativo del lenguaje) -- prioridad mas baja, no excluido.
_TIER_1_LANGUAGES = {"C", "C++"}
_TIER_2_LANGUAGES = {"Go", "Rust"}


def _fetch_watched_source_repos(conn) -> List[Dict]:
    """Solo repos de programas watched CON automated_scanning=="allowed"
    (mismo criterio de autorizacion que ya usa SPECTRE para scanning
    activo -- fuzzing local de un clone no es "activo" contra el target
    en si, pero reportar un hallazgo igual requiere que el programa
    autorice testing, asi que se filtra igual desde el origen)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT sa.asset_identifier, p.handle, p.name
            FROM bugbounty_scope_assets sa
            JOIN bugbounty_programs p ON p.id = sa.program_id
            WHERE p.is_watched = true
              AND sa.asset_type = 'SOURCE_CODE'
              AND sa.eligible_for_submission = true
              AND p.policy_parsed->>'automated_scanning' = 'allowed'
            ORDER BY 1
            """
        )
        rows = cur.fetchall()
    return [{"repo_url": r[0], "program_handle": r[1], "program_name": r[2]} for r in rows]


def _github_repo_info(repo_url: str) -> Optional[Dict]:
    """None si el repo no es de github.com o el request falla -- fail-open
    real, nunca se afirma un lenguaje sin confirmarlo."""
    if "github.com/" not in repo_url:
        return None
    path = repo_url.split("github.com/", 1)[1].rstrip("/")
    try:
        resp = requests.get(f"https://api.github.com/repos/{path}", timeout=_TIMEOUT)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    data = resp.json()
    # pushed_at viene GRATIS en la misma respuesta que ya pedimos para
    # language/archived -- no hace falta una llamada extra a la API de
    # commits (el rate limit sin auth ya es apretado, 60/hora, y cada
    # candidato ya consume 2 llamadas: esta + OSS-Fuzz). Se usa como
    # señal barata de "codigo posiblemente sin fuzzear todavia": un repo
    # con push reciente tiene mas probabilidad de tener paths nuevos que
    # ni Google ni nadie mas ya recorrio, uno sin actividad hace anios ya
    # tuvo tiempo de que cualquier bug obvio saliera a la luz solo.
    return {
        "language": data.get("language"),
        "archived": data.get("archived", False),
        "pushed_at": data.get("pushed_at"),
    }


def _check_oss_fuzz_coverage(repo_url: str) -> bool:
    """True si el repo YA esta integrado en OSS-Fuzz de Google -- chequea
    el project.yaml real (no solo si existe un archivo con el nombre
    que coincide, hay que confirmar que main_repo apunta al MISMO repo,
    nunca asumir por coincidencia de nombre). Fail-open (asume que NO
    esta cubierto) si el chequeo falla -- mejor investigar un candidato
    de mas que descartar uno real por error."""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    try:
        resp = requests.get(
            f"https://raw.githubusercontent.com/google/oss-fuzz/master/projects/{repo_name}/project.yaml",
            timeout=_TIMEOUT,
        )
    except requests.RequestException:
        return False
    if resp.status_code != 200:
        return False
    # No parseamos YAML de verdad para evitar una dependencia mas --
    # alcanza con buscar la URL del repo real en el texto del main_repo.
    return repo_url.rstrip("/") in resp.text or repo_url.rstrip("/").replace("https://github.com/", "") in resp.text


def _rank(language: Optional[str]) -> int:
    if language in _TIER_1_LANGUAGES:
        return 1
    if language in _TIER_2_LANGUAGES:
        return 2
    return 3


def _days_since_push(pushed_at: Optional[str]) -> int:
    """None/parseo fallido -> se trata como "hace mucho" (10 anios), no
    como "hace 0 dias" -- fail-open hacia ABAJO en prioridad, nunca
    hacia arriba, para no inventar señal de actividad que no se pudo
    confirmar de verdad."""
    if not pushed_at:
        return 3650
    try:
        pushed = datetime.strptime(pushed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return 3650
    return max(0, (datetime.now(timezone.utc) - pushed).days)


def select_targets(program_handle: Optional[str] = None) -> List[Dict]:
    conn = psycopg2.connect(SPECTRE_DATABASE_URL)
    try:
        repos = _fetch_watched_source_repos(conn)
    finally:
        conn.close()

    if program_handle:
        repos = [r for r in repos if r["program_handle"] == program_handle]

    candidates = []
    for repo in repos:
        info = _github_repo_info(repo["repo_url"])
        time.sleep(_PACE_SECONDS)
        if info is None or info["archived"]:
            continue
        language = info["language"]
        if language not in _TIER_1_LANGUAGES | _TIER_2_LANGUAGES:
            continue

        already_covered = _check_oss_fuzz_coverage(repo["repo_url"])
        time.sleep(_PACE_SECONDS)
        if already_covered:
            continue

        candidates.append(
            {
                **repo,
                "language": language,
                "tier": _rank(language),
                "days_since_push": _days_since_push(info.get("pushed_at")),
            }
        )

    # Dentro del mismo tier, push mas reciente primero -- codigo tocado
    # hace poco tiene mas chance real de tener paths que todavia nadie
    # (ni Google via OSS-Fuzz, ni este mismo proyecto en corridas
    # pasadas) recorrio. Nunca reemplaza los filtros duros de arriba
    # (lenguaje, scope, cobertura de OSS-Fuzz) -- solo ordena que
    # sobrevive esos filtros.
    candidates.sort(key=lambda c: (c["tier"], c["days_since_push"], c["repo_url"]))
    return candidates


def main():
    parser = argparse.ArgumentParser(description="Seleccion de targets de fuzzing")
    parser.add_argument("--program", default=None, help="handle de un programa especifico (default: todos)")
    args = parser.parse_args()

    print("Consultando repos de scope real (SPECTRE, solo lectura) + GitHub + OSS-Fuzz...\n")
    candidates = select_targets(args.program)

    if not candidates:
        print("Sin candidatos -- todos los repos en scope ya estan cubiertos por OSS-Fuzz, "
              "no son de un lenguaje relevante, o estan archivados.")
        return

    print(f"{len(candidates)} candidato(s) real(es) para fuzzing (no cubiertos por OSS-Fuzz), "
          f"ordenados por tier y actividad reciente:\n")
    for c in candidates:
        print(f"  [tier {c['tier']}] {c['language']:6s} push hace {c['days_since_push']:4d}d  "
              f"{c['repo_url']} ({c['program_name']})")


if __name__ == "__main__":
    main()
