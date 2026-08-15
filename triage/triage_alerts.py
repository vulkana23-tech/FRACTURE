#!/usr/bin/env python3
"""Corre triage real sobre las alertas que escribe orchestrator/
(orchestrator/alerts/<target_id>/<ts>/) -- las clasifica con
classify_go_panic.py (targets Go) o classify_sanitizer_crash.py (Rust/C),
escribe un triage.json por alerta, y mantiene un indice de dedup real
(triage/dedup_index.json) para que el mismo bug reportado 50 veces por
un fuzzer no se cuente como 50 hallazgos distintos.

Es el paso que faltaba: hoy orchestrator/alerts/ACOTA a un humano
teniendo que abrir cada carpeta a mano. Esto ya separa señal real de
ruido antes de eso.

Uso:
  venv/bin/python3 triage/triage_alerts.py
  venv/bin/python3 triage/triage_alerts.py --alerts-dir /otro/path
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_go_panic import extract_panic_info  # noqa: E402
from classify_sanitizer_crash import extract_crash_info  # noqa: E402

_ROOT = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_ALERTS_DIR = os.path.join(os.path.dirname(_ROOT), "orchestrator", "alerts")
_DEDUP_INDEX_PATH = os.path.join(_ROOT, "dedup_index.json")


def _load_dedup_index(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_dedup_index(index: dict, path: str) -> None:
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp_path, path)


def _classify_one(alert_dir: str, summary: dict) -> "dict | None":
    raw_path = os.path.join(alert_dir, "raw_output.txt")
    raw_text = ""
    if os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw_text = fh.read()

    if summary.get("engine") == "go":
        info = extract_panic_info(raw_text)
        if info is not None:
            # Mismo shape que classify_sanitizer_crash para que el resto
            # de este script no tenga que distinguir el origen.
            info = {
                "sanitizer": None,
                "bug_type": f"go-panic:{info['panic_type']}",
                "message": info["panic_message"],
                "target_frames": info["target_frames"],
                "top_frame": info["top_frame"],
                "severity": info["severity"],
                "stack_hash": info["stack_hash"],
            }
        return info

    return extract_crash_info(raw_text, returncode=summary.get("returncode"))


def triage_all(alerts_dir: str = _DEFAULT_ALERTS_DIR, dedup_index_path: str = _DEDUP_INDEX_PATH) -> dict:
    """Devuelve un resumen real de la corrida (para testear sin parsear stdout)."""
    dedup_index = _load_dedup_index(dedup_index_path)
    stats = {"already_triaged": 0, "newly_triaged": 0, "unclassified": 0, "new_unique_bugs": 0}

    if not os.path.isdir(alerts_dir):
        return stats

    for target_id in sorted(os.listdir(alerts_dir)):
        target_dir = os.path.join(alerts_dir, target_id)
        if not os.path.isdir(target_dir):
            continue
        for ts in sorted(os.listdir(target_dir)):
            alert_dir = os.path.join(target_dir, ts)
            summary_path = os.path.join(alert_dir, "summary.json")
            triage_path = os.path.join(alert_dir, "triage.json")
            if not os.path.isfile(summary_path):
                continue
            if os.path.exists(triage_path):
                stats["already_triaged"] += 1
                continue

            with open(summary_path, "r", encoding="utf-8") as fh:
                summary = json.load(fh)

            info = _classify_one(alert_dir, summary)
            if info is None:
                info = {
                    "sanitizer": None, "bug_type": "sin_clasificar",
                    "message": "no matcheo ningun patron conocido -- revision manual",
                    "target_frames": [], "top_frame": None,
                    "severity": "needs_review", "stack_hash": None,
                }
                stats["unclassified"] += 1

            with open(triage_path, "w", encoding="utf-8") as fh:
                json.dump(info, fh, indent=2, ensure_ascii=False)
            stats["newly_triaged"] += 1

            stack_hash = info.get("stack_hash")
            if stack_hash:
                if stack_hash not in dedup_index:
                    dedup_index[stack_hash] = {
                        "first_seen_alert": os.path.relpath(alert_dir, os.path.dirname(alerts_dir)),
                        "bug_type": info["bug_type"],
                        "severity": info["severity"],
                        "target_ids": [],
                        "occurrences": 0,
                    }
                    stats["new_unique_bugs"] += 1
                entry = dedup_index[stack_hash]
                entry["occurrences"] += 1
                if target_id not in entry["target_ids"]:
                    entry["target_ids"].append(target_id)
                entry["last_seen_at"] = datetime.now(timezone.utc).isoformat()

    _save_dedup_index(dedup_index, dedup_index_path)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--alerts-dir", default=_DEFAULT_ALERTS_DIR)
    parser.add_argument("--dedup-index", default=_DEDUP_INDEX_PATH)
    args = parser.parse_args()

    stats = triage_all(args.alerts_dir, args.dedup_index)
    index = _load_dedup_index(args.dedup_index)

    print(f"Alertas ya triadas antes: {stats['already_triaged']}")
    print(f"Alertas triadas ahora:    {stats['newly_triaged']}")
    print(f"  sin clasificar (revision manual directa): {stats['unclassified']}")
    print(f"Bugs unicos nuevos esta corrida: {stats['new_unique_bugs']}")
    print(f"Bugs unicos totales (dedup_index.json): {len(index)}")
    if index:
        by_severity = {}
        for entry in index.values():
            by_severity[entry["severity"]] = by_severity.get(entry["severity"], 0) + 1
        print("Por severidad:", ", ".join(f"{k}={v}" for k, v in sorted(by_severity.items())))


if __name__ == "__main__":
    main()
