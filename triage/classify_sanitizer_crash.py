#!/usr/bin/env python3
"""Clasifica un crash real de ASAN/UBSAN/MSAN/LeakSanitizer (targets C)
o un panic real de Rust (targets cargo-fuzz) -- la contraparte de
classify_go_panic.py para el resto de los lenguajes que fuzzea
FRACTURE. Mismo criterio: extraer el mensaje real + los frames que
pertenecen al codigo del TARGET (no al runtime del sanitizer/libc/std),
armar un hash de dedup a partir de eso, y clasificar severidad real
(corrupcion de memoria real vs. una asercion/abort intencional del
propio programa, que no es un bug de memoria).

Todos los fixtures de test son capturas REALES (compilados y corridos
de verdad con clang -fsanitize=..., no texto inventado a mano) -- ver
triage/testdata/.

Uso:
  venv/bin/python3 triage/classify_sanitizer_crash.py < raw_output.txt
"""

import hashlib
import re
import sys
from typing import Dict, List, Optional

# --------------------------------------------------------------------
# Deteccion del tipo de crash (orden de prioridad real: un output puede
# mencionar "sanitizer" en un comentario sin ser un reporte real, asi
# que se busca el patron exacto que cada sanitizer imprime).
# --------------------------------------------------------------------
_ASAN_ERROR_RE = re.compile(r"ERROR: AddressSanitizer: (\S+)")
_MSAN_ERROR_RE = re.compile(r"ERROR: MemorySanitizer: (\S+)")
_LSAN_ERROR_RE = re.compile(r"ERROR: LeakSanitizer: (.+)")
_UBSAN_RUNTIME_ERROR_RE = re.compile(
    r"^(\S+):(\d+):(\d+): runtime error: (.+)$", re.MULTILINE
)
# "thread 'main' (1716567) panicked at rust_panic.rs:2:15:\n<mensaje>"
# -- el pid entre parentesis es opcional (aparece en binarios thread-aware
# recientes, no en todas las versiones de rustc).
_RUST_PANIC_RE = re.compile(
    r"^thread '.*?'(?: \(\d+\))? panicked at ([^\n]+):\n(.+)$", re.MULTILINE
)

# Frame con ubicacion real de codigo fuente: "#N 0xADDR in FUNC PATH:LINE[:COL]"
# -- a diferencia de "#N 0xADDR in FUNC (MODULE+0xOFFSET)" (sin ':LINE'
# al final), que es plomeria del sanitizer/libc sin simbolos de debug.
_C_FRAME_WITH_LOCATION_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>.+?)\s+(?P<path>\S+):(?P<line>\d+)(?::\d+)?\s*$",
    re.MULTILINE,
)
# Backtrace de Rust: formato de DOS lineas, "   N: symbol\n   at path:line[:col]"
_RUST_FRAME_RE = re.compile(
    r"^\s*\d+:\s+(?P<func>\S.*?)\n\s+at\s+(?P<path>\S+):(?P<line>\d+)(?::\d+)?",
    re.MULTILINE,
)

_C_INTERNAL_FUNC_PREFIXES = (
    "__asan_", "__ubsan_", "__msan_", "__sanitizer_", "__interceptor_",
)
_RUST_INTERNAL_FUNC_PREFIXES = (
    "__rustc::", "core::panicking", "core::ops::function", "core::result",
    "core::option", "std::rt::", "std::panicking", "std::sys::",
)

_HIGH_SEVERITY_ASAN_TYPES = {
    "heap-buffer-overflow", "heap-use-after-free", "use-after-free",
    "stack-buffer-overflow", "stack-buffer-underflow", "global-buffer-overflow",
    "double-free", "invalid-free", "use-after-return", "use-after-poison",
    "stack-use-after-return", "stack-use-after-scope", "alloc-dealloc-mismatch",
    "new-delete-type-mismatch", "SEGV", "wild-pointer-dereference",
    "negative-size-param", "calloc-overflow",
}
_MEDIUM_SEVERITY_ASAN_TYPES = {"stack-overflow"}

_HIGH_SEVERITY_UBSAN_MARKERS = ("null pointer", "misaligned address", "out of bounds")

_HIGH_SEVERITY_RUST_PANIC_MARKERS = ("index out of bounds", "slice index", "out of range")
_MEDIUM_SEVERITY_RUST_PANIC_MARKERS = ("attempt to", "unwrap()", "expect(")


def _extract_c_frames(text: str) -> List[str]:
    frames = []
    for m in _C_FRAME_WITH_LOCATION_RE.finditer(text):
        func = m.group("func")
        if any(func.startswith(p) for p in _C_INTERNAL_FUNC_PREFIXES):
            continue
        frames.append(f"{func} ({m.group('path')}:{m.group('line')})")
    return frames


def _extract_rust_frames(text: str) -> List[str]:
    frames = []
    for m in _RUST_FRAME_RE.finditer(text):
        func = m.group("func")
        if any(func.startswith(p) for p in _RUST_INTERNAL_FUNC_PREFIXES):
            continue
        frames.append(f"{func} ({m.group('path')}:{m.group('line')})")
    return frames


def _stack_hash(*parts: str) -> str:
    # Nunca se incluye el mensaje crudo completo -- dos corridas del
    # MISMO bug tienen direcciones de memoria distintas bajo ASLR, eso
    # rompería el dedup. Solo tipo de bug + frames (deterministicos
    # para el mismo bug real) entran al hash.
    dedup_input = "|".join(parts)
    return hashlib.sha256(dedup_input.encode()).hexdigest()[:16]


def _asan_msan_severity(bug_type: str) -> str:
    if bug_type in _HIGH_SEVERITY_ASAN_TYPES:
        return "high"
    if bug_type in _MEDIUM_SEVERITY_ASAN_TYPES:
        return "medium"
    return "needs_review"


def _ubsan_severity(message: str) -> str:
    lowered = message.lower()
    if any(marker in lowered for marker in _HIGH_SEVERITY_UBSAN_MARKERS):
        return "high"
    # Overflow de enteros/shift/etc: UB real, pero la mayoria de las
    # veces resulta benigno en la practica -- necesita ojo humano, no
    # se puede afirmar severidad sin mirar el contexto real.
    return "needs_review"


def _rust_panic_severity(message: str) -> str:
    lowered = message.lower()
    if any(marker in lowered for marker in _HIGH_SEVERITY_RUST_PANIC_MARKERS):
        return "high"
    if any(marker in lowered for marker in _MEDIUM_SEVERITY_RUST_PANIC_MARKERS):
        return "medium"
    # panic!("mensaje propio") sin ninguno de los patrones de arriba
    # suele ser una asercion intencional del propio codigo -- mismo
    # criterio que classify_go_panic.py para panic() explicito.
    return "needs_review"


def extract_crash_info(raw_text: str, returncode: Optional[int] = None) -> Optional[Dict]:
    """None si no hay señal real de crash (corrida limpia).

    `returncode`, si se pasa, es el exit code real del proceso (el
    scheduler ya lo tiene en outcome["returncode"]) -- hace falta para
    el caso real de un abort()/SIGSEGV sin sanitizer instrumentado
    encima: el texto capturado por subprocess.run() no incluye ningun
    marcador tipo "Aborted (core dumped)" (eso lo imprime el job
    control de una shell INTERACTIVA, no esta presente cuando el
    proceso se lanza con subprocess.run desde Python) -- confirmado en
    vivo generando el fixture real de este caso, no asumido. Sin el
    returncode, un abort limpio sin texto de diagnostico es
    indistinguible de una corrida limpia real."""

    m = _ASAN_ERROR_RE.search(raw_text)
    if m:
        bug_type = m.group(1)
        frames = _extract_c_frames(raw_text)
        return {
            "sanitizer": "AddressSanitizer",
            "bug_type": bug_type,
            "message": bug_type,
            "target_frames": frames,
            "top_frame": frames[0] if frames else None,
            "severity": _asan_msan_severity(bug_type),
            "stack_hash": _stack_hash("asan", bug_type, *frames[:3]),
        }

    m = _MSAN_ERROR_RE.search(raw_text)
    if m:
        bug_type = m.group(1)
        frames = _extract_c_frames(raw_text)
        return {
            "sanitizer": "MemorySanitizer",
            "bug_type": bug_type,
            "message": bug_type,
            "target_frames": frames,
            "top_frame": frames[0] if frames else None,
            "severity": _asan_msan_severity(bug_type),
            "stack_hash": _stack_hash("msan", bug_type, *frames[:3]),
        }

    m = _LSAN_ERROR_RE.search(raw_text)
    if m:
        frames = _extract_c_frames(raw_text)
        return {
            "sanitizer": "LeakSanitizer",
            "bug_type": "memory-leak",
            "message": m.group(1).strip(),
            "target_frames": frames,
            "top_frame": frames[0] if frames else None,
            # Leaks rara vez pagan en programas de bounty y casi nunca
            # son explotables por si solos -- señal real pero de baja
            # prioridad frente a corrupcion de memoria.
            "severity": "low",
            "stack_hash": _stack_hash("lsan", "memory-leak", *frames[:3]),
        }

    m = _UBSAN_RUNTIME_ERROR_RE.search(raw_text)
    if m:
        path, line, col, message = m.groups()
        location = f"{path}:{line}:{col}"
        frames = _extract_c_frames(raw_text)  # normalmente vacio -- UBSAN default no imprime backtrace
        return {
            "sanitizer": "UndefinedBehaviorSanitizer",
            "bug_type": message.split(":")[0].strip(),
            "message": message.strip(),
            "target_frames": frames,
            "top_frame": frames[0] if frames else location,
            "severity": _ubsan_severity(message),
            "stack_hash": _stack_hash("ubsan", message.split(":")[0].strip(), location, *frames[:3]),
        }

    m = _RUST_PANIC_RE.search(raw_text)
    if m:
        location, message = m.groups()
        message = message.strip()
        frames = _extract_rust_frames(raw_text)
        return {
            "sanitizer": None,
            "bug_type": "rust-panic",
            "message": message,
            "target_frames": frames,
            "top_frame": frames[0] if frames else location,
            "severity": _rust_panic_severity(message),
            "stack_hash": _stack_hash("rust-panic", message, *frames[:3]),
        }

    if returncode is not None and returncode != 0:
        # Termino mal (abort/segfault/signal) pero sin reporte de
        # sanitizer en el texto -- tipicamente un assert()/abort()
        # explicito del propio programa (asercion intencional, mismo
        # criterio que un panic() con mensaje propio) o un SEGV que el
        # sanitizer no llego a interceptar. Necesita revision humana,
        # no se puede clasificar con mas precision solo con esto.
        first_relevant_line = next(
            (ln.strip() for ln in raw_text.splitlines() if ln.strip()), ""
        )
        return {
            "sanitizer": None,
            "bug_type": "abort-sin-reporte-de-sanitizer",
            "message": first_relevant_line or f"returncode={returncode}, sin texto de diagnostico",
            "target_frames": [],
            "top_frame": None,
            "severity": "needs_review",
            "stack_hash": _stack_hash("abort", str(returncode), first_relevant_line),
        }

    return None


def main() -> None:
    raw_text = sys.stdin.read()
    info = extract_crash_info(raw_text)  # sin --returncode por stdin, ver triage_alerts.py para el uso real integrado
    if info is None:
        print("Sin crash real en el output -- corrida limpia (o el formato no matcheo, revisar a mano).")
        return
    print(f"sanitizer:  {info['sanitizer'] or '(ninguno -- panic/abort sin sanitizer)'}")
    print(f"bug_type:   {info['bug_type']}")
    print(f"severity:   {info['severity']}")
    print(f"stack_hash: {info['stack_hash']}")
    print(f"top_frame:  {info['top_frame']}")
    print(f"message:    {info['message']}")
    if info["target_frames"]:
        print("target_frames:")
        for f in info["target_frames"]:
            print(f"  - {f}")


if __name__ == "__main__":
    main()
