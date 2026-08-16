#!/usr/bin/env python3
"""Genera Y VALIDA un test de estrés de concurrencia en Go
(`go test -race`) para un conjunto de funciones reales de un paquete
real, usando qwen3-coder (Ollama) -- mismo criterio de "compilar y
CORRER de verdad, iterar contra el error real" que
generate_go_harness.py/generate_harness.py/generate_rust_harness.py.

Por qué existe: `find_patch_directed_candidates.py` ya encuentra
commits reales de "race condition"/"data race" (matchean
`_SECURITY_KEYWORDS`), pero hasta ahora todos esos candidatos se
descartaban como "no fuzzeable con libFuzzer" (ver
targets/README.md, caso real `hyperledger/fabric-lib-go` commit
`8fe16c9967`) -- cierto para fuzzing de bytes, pero Go trae su PROPIO
detector de razas (`-race`, basado en ThreadSanitizer) que sí puede
encontrar una carrera real ejercitando el código real bajo
concurrencia, sin necesitar ningún byte de entrada.

A diferencia de los otros generadores, "éxito" acá NO significa "no
encontró nada" -- significa "el test generado es un stress test de
concurrencia VÁLIDO que corre de verdad" (compila, ejecuta, y termina
sin un error de build/setup). Que el detector de razas SI encuentre
una carrera real es un resultado tan válido como que no encuentre
nada -- ambos se reportan por separado (`race_detected`), ninguno de
los dos es un "fallo" de generación.

Validado en vivo (2026-08-16) a mano contra hyperledger/fabric-lib-go:
un stress test de 2 goroutines (InitFactories/GetDefault) detectó la
carrera real en la version PRE-fix (commit padre de 8fe16c9967) en
0.027s, y salió limpio en la version POST-fix -- confirma que la
técnica funciona antes de automatizarla acá.

Uso:
  venv/bin/python3 harness_gen/generate_race_test.py \\
    --repo https://github.com/hyperledger/fabric-lib-go \\
    --package-path bccsp/factory \\
    --functions InitFactories,GetDefault \\
    --out orchestrator/fuzz_tests/fabric_lib_go_factory_race_test.go
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional, Tuple

import requests

from config import OLLAMA_MODEL, OLLAMA_URL

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "orchestrator"))
from run_go_fuzzer import _clone_shallow, _ensure_go_module, _generate_mocks  # noqa: E402 -- reuso real, no reimplementacion

_GENERATE_TIMEOUT = 1200  # mismo motivo real ya documentado en generate_go_harness.py (CPU pura, ~0.8 tok/seg)
_VALIDATE_TIMEOUT = 60
_MAX_ATTEMPTS = 3

_RACE_TEST_RULES = """Reglas del test de estrés de concurrencia (obligatorias):
- Un solo `func TestXxx(t *testing.T) {{ ... }}` real (paquete de test estandar, NO `go test -fuzz`).
- Adentro, lanzá VARIAS goroutines reales (`go func() {{ ... }}()`) que llamen a las funciones objetivo de forma CONCURRENTE, en un loop (al menos 20-50 iteraciones) -- el objetivo es maximizar la chance de que el detector de razas de Go (`-race`) vea un acceso concurrente real a estado compartido.
- CRÍTICO, confirmado en vivo (no es una preferencia de estilo): TODAS las goroutines de TODAS las funciones objetivo van MEZCLADAS en el MISMO lote/loop, con un solo `sync.WaitGroup` y un solo `wg.Wait()` AL FINAL de todo el test. NUNCA hagas `wg.Wait()` entre "oleadas" de funciones distintas (ej. lanzar 50 goroutines de FuncA, esperarlas con wg.Wait(), y RECIÉN DESPUÉS lanzar 50 de FuncB) -- eso serializa completamente el acceso, ninguna goroutine de FuncA sigue viva cuando arranca FuncB, así que el detector de razas NUNCA puede ver un acceso concurrente real sin importar cuántas veces se corra. Confirmado con 20 repeticiones reales: la estructura de oleadas separadas detectó la carrera real 0/20 veces; la misma carrera con TODAS las goroutines mezcladas en un solo lote la detectó 20/20 veces.
- Usá `sync.WaitGroup` para esperar a que todas las goroutines terminen antes de que el test retorne.
- Nunca uses `t.Fatal`/`panic` por un error ESPERADO que devuelvan las funciones (ej. un error de inicialización) -- eso no es el bug que estamos buscando, solo ignoralo o descartalo.
- Devolvé SOLO el código Go completo del archivo de test (package {package_name}, imports incluidos), sin explicación antes o después, sin markdown code fences."""

_PROMPT_TEMPLATE = """Sos un experto en detección de race conditions en Go (`go test -race`, basado en ThreadSanitizer). Te doy el contenido real de un paquete real de un proyecto real, y una lista de funciones/métodos públicos de ese paquete que un commit real de seguridad reciente marcó como relacionados a una race condition.

{rules}

Contexto: esto se inyecta como archivo ADENTRO del mismo paquete real ({package_name}) -- podés usar directamente cualquier tipo/función no exportada de ese paquete, no hace falta importarlo.

Archivos reales del paquete ({package_name}):
{files_content}

Funciones objetivo a ejercitar concurrentemente: {functions_list}

Devolvé SOLO el código Go completo del archivo de test, sin explicación, sin markdown."""

_RETRY_TEMPLATE = """El test anterior no compiló/corrió. Este es el error REAL de `go test`:

{error}

Test anterior:
```go
{previous_test}
```

{rules}

Corregilo en base a ese error real. Devolvé SOLO el código Go completo corregido, sin explicación, sin markdown."""


def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def _call_ollama(prompt: str) -> str:
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=_GENERATE_TIMEOUT,
    )
    resp.raise_for_status()
    return _strip_markdown_fences(resp.json().get("response", ""))


_TEST_FUNC_RE = re.compile(r"^func\s+(Test\w+)\s*\(", re.MULTILINE)
_PACKAGE_RE = re.compile(r"^package\s+(\S+)", re.MULTILINE)


def _read_package_files(repo_dir: str, package_path: str) -> Tuple[str, str]:
    """Concatena el contenido real de todos los .go NO-test del paquete
    (paquetes chicos, caso real mas comun de estos candidatos -- si un
    paquete tiene demasiados archivos, el prompt se hace mas largo pero
    sigue siendo correcto, no se trunca nada)."""
    pkg_dir = os.path.join(repo_dir, package_path)
    if not os.path.isdir(pkg_dir):
        raise FileNotFoundError(f"{package_path} no existe en el repo clonado")

    package_name = None
    combined = []
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".go") or fname.endswith("_test.go"):
            continue
        fpath = os.path.join(pkg_dir, fname)
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        if package_name is None:
            m = _PACKAGE_RE.search(content)
            if m:
                package_name = m.group(1)
        combined.append(f"--- {fname} ---\n```go\n{content}\n```")

    if package_name is None:
        raise RuntimeError(f"ningun archivo .go real (no-test) con 'package' valido en {package_path}")
    return package_name, "\n\n".join(combined)


def _extract_test_func_name(test_code: str) -> Optional[str]:
    m = _TEST_FUNC_RE.search(test_code)
    return m.group(1) if m else None


# Bug real encontrado validando esto en vivo (2026-08-16, no teorico):
# el modelo generó un test con 3 oleadas SECUENCIALES de goroutines
# (InitFactories, despues GetDefault, despues initFactories), con
# `wg.Wait()` entre cada oleada -- compilaba y corria limpio (paso la
# validacion), pero esa estructura NUNCA puede detectar una carrera
# real: `wg.Wait()` sincroniza completamente antes de que arranque la
# oleada siguiente, asi que dos funciones DISTINTAS nunca estan
# corriendo en simultaneo. Confirmado reproduciendo el patron exacto en
# un paquete Go minimo con una carrera real conocida: la estructura de
# oleadas separadas la detecto 0/20 veces corriendo el mismo test 20
# veces; la misma carrera con todas las goroutines mezcladas en un solo
# lote la detecto 20/20. Chequeo deterministico (no confiar solo en
# que el modelo obedezca la regla del prompt): mas de un `.Wait()` real
# es la firma directa del antipatron -- se rechaza ANTES de compilar,
# ahorra tiempo real de Ollama en el reintento.
_MULTIPLE_WAIT_RE = re.compile(r"\.Wait\(\)")


def _try_compile_and_run(repo_dir: str, package_path: str, test_code: str) -> Tuple[bool, bool, str]:
    """Devuelve (valido, carrera_detectada, output). 'valido' es False
    solo si hubo un error real de build/setup -- que el detector SI
    encuentre una carrera real es un resultado valido (y notable), no
    un fallo de generacion (ver docstring del modulo)."""
    pkg_dir = os.path.join(repo_dir, package_path)
    test_func_name = _extract_test_func_name(test_code)
    if not test_func_name:
        return False, False, "el codigo generado no tiene ninguna func TestXxx(t *testing.T) real"

    wait_count = len(_MULTIPLE_WAIT_RE.findall(test_code))
    if wait_count > 1:
        return False, False, (
            f"el test generado tiene {wait_count} llamadas a .Wait() -- eso indica "
            "oleadas SEPARADAS de goroutines sincronizadas entre si (ej. lanzar+esperar "
            "las goroutines de una funcion, y RECIEN DESPUES lanzar las de otra). Esa "
            "estructura NUNCA puede detectar una carrera real (confirmado en vivo: 0/20 "
            "detecciones) porque las goroutines de funciones distintas nunca corren en "
            "simultaneo. TODAS las goroutines de TODAS las funciones objetivo tienen que "
            "estar mezcladas en el MISMO lote, con un unico wg.Wait() al final de todo el test."
        )

    # Mismo bug real ya documentado en generate_go_harness.py: un
    # nombre de archivo que empieza con "_" es ignorado en silencio por
    # el tool `go` -- nombre sin underscore inicial.
    injected_path = os.path.join(pkg_dir, "harness_gen_race_candidate_test.go")
    with open(injected_path, "w", encoding="utf-8") as fh:
        fh.write(test_code)
    try:
        result = subprocess.run(
            # -mod=mod: varios repos reales de este scope tienen
            # vendor/modules.txt desincronizado del vendor/ real (bug
            # real encontrado validando esto contra fabric-lib-go) --
            # evita depender de que el vendoring este perfecto en un
            # clon temporal descartable.
            ["go", "test", "-mod=mod", "-race", "-run", f"^{test_func_name}$", "-count=1", "."],
            cwd=pkg_dir, capture_output=True, text=True, timeout=_VALIDATE_TIMEOUT,
        )
    finally:
        os.remove(injected_path)

    combined = result.stdout + result.stderr
    race_detected = "WARNING: DATA RACE" in combined
    if result.returncode == 0:
        return True, False, combined[-4000:]
    if race_detected:
        return True, True, combined[-4000:]
    return False, False, combined[-4000:]


def generate_and_validate_race_test(
    repo_url: str, package_path: str, functions: List[str], max_attempts: int = _MAX_ATTEMPTS,
) -> dict:
    repo_dir = _clone_shallow(repo_url)
    try:
        _ensure_go_module(repo_dir, repo_url)
        _generate_mocks(repo_dir)
        package_name, files_content = _read_package_files(repo_dir, package_path)

        prompt = _PROMPT_TEMPLATE.format(
            rules=_RACE_TEST_RULES.format(package_name=package_name),
            package_name=package_name, files_content=files_content,
            functions_list=", ".join(functions),
        )
        test_code = _call_ollama(prompt)

        attempts_log = []
        for attempt in range(1, max_attempts + 1):
            ok, race_detected, output = _try_compile_and_run(repo_dir, package_path, test_code)
            attempts_log.append({"attempt": attempt, "ok": ok, "race_detected": race_detected,
                                  "output": output if not ok else ""})
            if ok:
                return {"success": True, "test_code": test_code, "package_name": package_name,
                        "race_detected": race_detected, "attempts": attempts_log}
            if attempt == max_attempts:
                return {"success": False, "test_code": test_code, "package_name": package_name,
                        "race_detected": False, "attempts": attempts_log}
            retry_prompt = _RETRY_TEMPLATE.format(
                error=output, previous_test=test_code,
                rules=_RACE_TEST_RULES.format(package_name=package_name),
            )
            test_code = _call_ollama(retry_prompt)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--package-path", required=True)
    parser.add_argument("--functions", required=True, help="lista separada por comas")
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-attempts", type=int, default=_MAX_ATTEMPTS)
    args = parser.parse_args()

    functions = [f.strip() for f in args.functions.split(",") if f.strip()]
    print(f"Generando y validando test de race para {', '.join(functions)} en {args.package_path} "
          f"({args.repo})...")
    result = generate_and_validate_race_test(args.repo, args.package_path, functions, args.max_attempts)

    for a in result["attempts"]:
        status = "OK" if a["ok"] else "FALLO"
        marker = " -- CARRERA REAL DETECTADA" if a.get("race_detected") else ""
        print(f"  intento {a['attempt']}: {status}{marker}")
        if not a["ok"]:
            print(f"    {a['output'][-600:]}")

    if result["success"]:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["test_code"])
        if result["race_detected"]:
            print(f"\n*** CARRERA REAL DETECTADA *** -- test escrito en {args.out}, revision humana necesaria YA")
        else:
            print(f"\nTest VALIDADO (compila y corre de verdad bajo -race) -- sin carrera detectada, "
                  f"escrito en {args.out}")
    else:
        print(f"\nNo se pudo validar en {args.max_attempts} intentos -- NO se escribe {args.out}. "
              f"Ultimo error arriba, revision humana necesaria.")
        sys.exit(1)


if __name__ == "__main__":
    main()
