#!/usr/bin/env python3
"""Clasifica un panic real de `go test -fuzz`/`go test -run`: extrae el
mensaje + los frames de stack que pertenecen al codigo del TARGET (no a
runtime/testing/reflect de Go, que son plomeria interna sin señal),
arma un hash de dedup a partir de eso, y clasifica severidad por tipo
de panic -- index/slice out of range y nil pointer dereference son
clases de bug de memoria-adyacente reales; un panic() explicito del
propio codigo del proyecto (con mensaje descriptivo) suele ser una
asercion intencional, no un bug de memoria.

Uso:
  venv/bin/python3 triage/classify_go_panic.py < go_test_output.txt
"""

import hashlib
import re
import sys
from typing import Dict, List, Optional

# Paquetes de la propia stdlib de Go que aparecen en CUALQUIER panic de
# un test/fuzz (plomeria interna) -- se filtran del stack para el hash
# de dedup y para identificar donde REALMENTE esta el bug (primer frame
# fuera de esta lista).
_GO_INTERNAL_PACKAGE_PREFIXES = ("testing.", "runtime.", "reflect.")

_HIGH_SEVERITY_PANIC_TYPES = (
    "index out of range",
    "slice bounds out of range",
    "nil pointer dereference",
    "invalid memory address",
    "integer divide by zero",
)

# Bug real encontrado probando esto en vivo contra fabric-amcl: la
# clase de caracteres original ([\w./]+) no incluia "-", asi que no
# matcheaba nombres de repo reales con guion (ej.
# "github.com/hyperledger/fabric-amcl/core.DL_unpack_pk") -- la linea
# entera no matcheaba y el frame de origen quedaba vacio.
_FRAME_RE = re.compile(r"^([\w./-]+\.[\w.]+)\(.*\)$")
_LOCATION_RE = re.compile(r"^\t(.+):(\d+)")


def _panic_type(message: str) -> str:
    for known in _HIGH_SEVERITY_PANIC_TYPES:
        if known in message:
            return known
    return "other"


def extract_panic_info(go_test_output: str) -> Optional[Dict]:
    """None si no hay panic real en el output (ej. corrida limpia)."""
    lines = go_test_output.split("\n")
    panic_line_idx = None
    panic_message = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("panic:") and "[recovered]" not in stripped:
            panic_message = stripped[len("panic:"):].strip()
            panic_line_idx = i
            break
        if stripped.startswith("panic:"):
            # "panic: X [recovered]" -- el mensaje real esta en la
            # proxima linea "panic: X" (Go repite el panic original
            # despues del wrapper de recover() de testing).
            panic_message = stripped[len("panic:"):].replace("[recovered]", "").strip()
            panic_line_idx = i
    if panic_message is None:
        return None

    target_frames: List[str] = []
    i = panic_line_idx or 0
    while i < len(lines) - 1:
        match = _FRAME_RE.match(lines[i].strip())
        if match:
            func = match.group(1)
            if not any(func.startswith(p) for p in _GO_INTERNAL_PACKAGE_PREFIXES):
                loc_match = _LOCATION_RE.match(lines[i + 1]) if i + 1 < len(lines) else None
                location = f"{loc_match.group(1)}:{loc_match.group(2)}" if loc_match else "?"
                target_frames.append(f"{func} ({location})")
        i += 1

    dedup_input = panic_message + "|" + "|".join(target_frames[:3])
    stack_hash = hashlib.sha256(dedup_input.encode()).hexdigest()[:16]

    return {
        "panic_message": panic_message,
        "panic_type": _panic_type(panic_message),
        "target_frames": target_frames,
        "top_frame": target_frames[0] if target_frames else None,
        "severity": "high" if _panic_type(panic_message) != "other" else "needs_review",
        "stack_hash": stack_hash,
    }


def main():
    output = sys.stdin.read()
    info = extract_panic_info(output)
    if info is None:
        print("Sin panic real en el output -- corrida limpia (o el formato no matcheo, revisar a mano).")
        return

    print(f"Severidad: {info['severity']}")
    print(f"Tipo: {info['panic_type']}")
    print(f"Mensaje: {info['panic_message']}")
    print(f"Stack hash (dedup): {info['stack_hash']}")
    print(f"Frame de origen: {info['top_frame']}")
    if len(info["target_frames"]) > 1:
        print("Stack completo (codigo del target, sin plomeria de Go):")
        for frame in info["target_frames"]:
            print(f"  {frame}")


if __name__ == "__main__":
    main()
