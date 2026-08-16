#!/usr/bin/env python3
"""Genera Y VALIDA un harness de Jazzer (JVM) para una funcion/metodo
real de una clase Java real, usando qwen3-coder (Ollama) -- mismo
criterio que generate_go_harness.py/generate_rust_harness.py: compila
y CORRE de verdad lo que genera el modelo, y si falla, le pasa el
error REAL de vuelta para que se corrija (hasta 3 intentos).

Mismo patron que Rust (build/rust_targets/<crate>, clon PERSISTENTE):
el classpath real (--classes-dir/--lib-dir) tiene que estar YA
PREPARADO (ver build/jvm_targets/<target>/, un *_build.sh por target
real -- Gradle/Maven real, no hay forma barata de bootstrapear un
proyecto Java arbitrario como si fuera "cargo fuzz build"). --repo se
usa SOLO para leer el .java fuente real (clon shallow aparte, nunca se
compila desde ahi).

Cubre los dos casos reales que ya aparecieron en este proyecto:
- Metodo PUBLICO que toma bytes/String directo -- se llama derecho.
- Metodo PRIVADO -- se crea la instancia SIN correr el constructor
  real (via ReflectionFactory, tecnica estandar de Java) e invoca por
  reflection (mismo patron real ya validado en
  FuzzParseAttributes.java, se le da al modelo como ejemplo concreto).

Uso:
  venv/bin/python3 harness_gen/generate_jvm_harness.py \\
    --repo https://github.com/hyperledger/fabric-chaincode-java \\
    --classes-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/classes \\
    --lib-dir /opt/fracture/build/jvm_targets/fabric_chaincode_java/lib \\
    --class org.hyperledger.fabric.contract.execution.JSONTransactionSerializer \\
    --function fromBuffer \\
    --out orchestrator/fuzz_harnesses/nuevo.java
"""

import argparse
import glob
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
from run_jvm_fuzzer import run_jvm_fuzzer  # noqa: E402 -- reuso real, no reimplementacion

_CLONE_TIMEOUT = 60
_GENERATE_TIMEOUT = 1200  # mismo motivo real que Go/Rust/C: 30B en CPU pura, sin GPU, ~0.8 tok/seg medido
_VALIDATE_DURATION = 5
_VALIDATE_WORKERS = 2
_MAX_ATTEMPTS = 4

_JVM_HARNESS_RULES = """Reglas del harness de Jazzer (obligatorias):
- La clase tiene que llamarse EXACTAMENTE {fuzz_class_name} y tener un metodo `public static void fuzzerTestOneInput(byte[] data)`.
- Regla real encontrada en producción: si la función objetivo es PÚBLICA, SIEMPRE llamala DIRECTO -- importá la clase con un `import` normal al principio del archivo y usá `new NombreClase(...)` + `instancia.metodo(...)`. NUNCA uses reflection para un método público -- es innecesariamente complejo y en la práctica generó errores reales de compilación (paquete mal escrito, símbolo no importado). El bypass de reflection de abajo es SOLO para métodos PRIVADOS.
- Si la función objetivo es PRIVADA o requiere una instancia difícil de construir (constructor real complejo), usá EXACTAMENTE este patron de bypass de constructor via reflection (funciona, ya probado en producción):
```java
sun.reflect.ReflectionFactory rf = sun.reflect.ReflectionFactory.getReflectionFactory();
java.lang.reflect.Constructor<Object> objectCtor = Object.class.getDeclaredConstructor();
java.lang.reflect.Constructor<?> ctor = rf.newConstructorForSerialization(TargetClass.class, objectCtor);
ctor.setAccessible(true);
Object instance = ctor.newInstance();
java.lang.reflect.Method m = TargetClass.class.getDeclaredMethod("metodoPrivado", byte[].class);
m.setAccessible(true);
m.invoke(instance, data);
```
  SOLO usá este patron de bypass si estás seguro de que el método no usa campos de instancia sin inicializar de forma insegura (mirá el código real que te doy).
- Si la función necesita otros parámetros de un tipo que NO está en el código que te doy (no viste su API real), construí la instancia MÁS SIMPLE posible -- `new TipoQueSea()` sin llamar ningún método sobre ella después, nunca adivines nombres de setters/getters de una clase cuyo código real no viste (error real ya encontrado en producción: `ts.setType("string")` sobre una clase que en realidad no tiene ese método).
- Envolvé excepciones ESPERADAS del contrato normal de la función (ej. las que ya declara `throws`, o excepciones de parseo documentadas como comportamiento normal ante input inválido) en un catch que las descarte -- pero dejá que CUALQUIER excepción no declarada/no esperada se propague sola (nunca uses un catch genérico `catch (Exception e) {{}}` que trague todo).
- Devolvé SOLO el código Java completo del harness, sin explicación antes o después, sin markdown code fences."""

_PROMPT_TEMPLATE = """Sos un experto en fuzzing con Jazzer (JVM). Te doy el contenido real de una clase Java de un proyecto real, y el nombre de un método público o privado de esa clase para fuzzear.

{rules}

Clase real ({class_fqn}):
```java
{source_content}
```

Método objetivo: {function_name}

Harness ({fuzz_class_name}.java):"""

_RETRY_TEMPLATE = """El harness anterior no compiló/corrió. Este es el error REAL:

{error}

Harness anterior:
```java
{previous_harness}
```

{rules}

Corregilo en base a ese error real. Devolvé SOLO el código Java completo corregido, sin explicación, sin markdown."""


def _clone_shallow(repo_url: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="fracture_jvmgen_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, tmpdir],
            capture_output=True, timeout=_CLONE_TIMEOUT, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"clone fallo para {repo_url}: {e}") from e
    return tmpdir


def _find_java_source(repo_dir: str, class_fqn: str) -> str:
    simple_name = class_fqn.rsplit(".", 1)[-1]
    target_filename = simple_name + ".java"
    for root, _, files in os.walk(repo_dir):
        if target_filename in files:
            with open(os.path.join(root, target_filename), "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
    raise FileNotFoundError(f"{target_filename} no encontrado en el repo clonado")


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


def _try_compile_and_run(
    classes_dir: str, lib_dir: str, fuzz_class_name: str, harness_code: str,
) -> Tuple[bool, str]:
    jars = sorted(glob.glob(os.path.join(lib_dir, "*.jar")))
    classpath = ":".join([classes_dir] + jars)

    harness_path = os.path.join(classes_dir, f"{fuzz_class_name}.java")
    with open(harness_path, "w", encoding="utf-8") as fh:
        fh.write(harness_code)
    try:
        compile_result = subprocess.run(
            ["javac", "-cp", classpath, "-d", classes_dir, harness_path],
            capture_output=True, text=True, timeout=120,
        )
        if compile_result.returncode != 0:
            return False, compile_result.stderr[-4000:]

        corpus_dir = tempfile.mkdtemp(prefix="fracture_jvmgen_corpus_")
        artifact_dir = tempfile.mkdtemp(prefix="fracture_jvmgen_artifacts_")
        try:
            outcome = run_jvm_fuzzer(
                classes_dir, lib_dir, fuzz_class_name, corpus_dir, artifact_dir,
                duration_seconds=_VALIDATE_DURATION, workers=_VALIDATE_WORKERS,
            )
        finally:
            shutil.rmtree(corpus_dir, ignore_errors=True)
            shutil.rmtree(artifact_dir, ignore_errors=True)

        # Igual que Go/Rust/C: returncode!=0 sin crashes = nunca corrio
        # de verdad (ej. classpath roto en runtime aunque compile), no
        # una corrida limpia real.
        if outcome.get("returncode", 0) != 0 and not outcome.get("crashes"):
            return False, (outcome.get("stderr_tail", "") + outcome.get("stdout_tail", ""))[-4000:]
        return True, ""
    finally:
        os.remove(harness_path)


def generate_and_validate_jvm_harness(
    repo_url: str, classes_dir: str, lib_dir: str, class_fqn: str, function_name: str,
    fuzz_class_name: Optional[str] = None, max_attempts: int = _MAX_ATTEMPTS,
) -> dict:
    if fuzz_class_name is None:
        fuzz_class_name = "Fuzz" + function_name[0].upper() + function_name[1:]

    repo_dir = _clone_shallow(repo_url)
    try:
        source_content = _find_java_source(repo_dir, class_fqn)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)

    rules = _JVM_HARNESS_RULES.format(fuzz_class_name=fuzz_class_name)
    prompt = _PROMPT_TEMPLATE.format(
        rules=rules, class_fqn=class_fqn, source_content=source_content,
        function_name=function_name, fuzz_class_name=fuzz_class_name,
    )
    harness = _call_ollama(prompt)

    attempts_log = []
    for attempt in range(1, max_attempts + 1):
        ok, error = _try_compile_and_run(classes_dir, lib_dir, fuzz_class_name, harness)
        attempts_log.append({"attempt": attempt, "ok": ok, "error": error if not ok else ""})
        if ok:
            return {"success": True, "harness": harness, "fuzz_class_name": fuzz_class_name,
                    "attempts": attempts_log}
        if attempt == max_attempts:
            return {"success": False, "harness": harness, "fuzz_class_name": fuzz_class_name,
                    "attempts": attempts_log}
        retry_prompt = _RETRY_TEMPLATE.format(error=error, previous_harness=harness, rules=rules)
        harness = _call_ollama(retry_prompt)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--classes-dir", required=True)
    parser.add_argument("--lib-dir", required=True)
    parser.add_argument("--class", dest="class_fqn", required=True, help="nombre calificado completo (FQN)")
    parser.add_argument("--function", required=True)
    parser.add_argument("--fuzz-class-name", default=None)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-attempts", type=int, default=_MAX_ATTEMPTS)
    args = parser.parse_args()

    print(f"Generando y validando harness para {args.class_fqn}#{args.function}()...")
    result = generate_and_validate_jvm_harness(
        args.repo, args.classes_dir, args.lib_dir, args.class_fqn, args.function,
        args.fuzz_class_name, args.max_attempts,
    )

    for a in result["attempts"]:
        status = "OK" if a["ok"] else "FALLO"
        print(f"  intento {a['attempt']}: {status}")
        if not a["ok"]:
            print(f"    {a['error'][-600:]}")

    if result["success"]:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["harness"])
        print(f"\nHarness VALIDADO (compila y corre de verdad) -- escrito en {args.out}")
        print(f"fuzz_class: {result['fuzz_class_name']}, ya compilado en {args.classes_dir}")
    else:
        print(f"\nNo se pudo validar en {args.max_attempts} intentos -- NO se escribe {args.out}. "
              f"Ultimo error arriba, revision humana necesaria.")
        sys.exit(1)


if __name__ == "__main__":
    main()
