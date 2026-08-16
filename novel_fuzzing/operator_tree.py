#!/usr/bin/env python3
"""Prototipo real de la idea "novel_fuzzing": un álgebra de operadores
componibles para mutación ESTRUCTURADA (no a nivel de bytes) de
documentos JSON, evaluada literalmente desde la notación real que la
motivó: `seq(loop(interleave,3), choice(transpose, semantic_inverse))`.

Por qué esto y no reemplazar el motor de mutación de libFuzzer: los 4
motores de fuzzing que ya tiene FRACTURE (Rust/C via libFuzzer, JVM via
Jazzer, Go nativo) mutan BYTES crudos, guiados por cobertura -- no
tienen ningún modelo de la estructura del input. Reescribir el mutator
interno de cada uno (LLVMFuzzerCustomMutator en C, engines separados en
Rust/Go/JVM) es reingeniería real de 4 motores distintos, alto
riesgo/esfuerzo. En cambio, esto genera semillas de corpus
ESTRUCTURALMENTE interesantes (documentos JSON reales mutados a nivel
de árbol: transponer elementos, invertir semántica de un valor,
mezclar dos documentos) y las inyecta al corpus ANTES de una campaña
real -- libFuzzer sigue siendo el motor de ejecución/cobertura, esto
solo mejora el punto de partida. Bajo riesgo, no toca ninguno de los 4
engines existentes.

Cada operador opera sobre un valor JSON ya parseado (dict/list/scalar
de Python), nunca sobre bytes crudos directamente -- eso es lo que lo
distingue de la mutación byte-a-byte que ya hacen los motores
existentes.
"""

import copy
import json
import random
import re
from typing import Any, List


JSONValue = Any  # dict | list | str | float | int | bool | None


# ---------------------------------------------------------------------------
# Operadores primitivos -- cada uno toma (valor, corpus_real, rng) y
# devuelve un valor JSON nuevo. `corpus_real` (lista de otros documentos
# ya parseados) solo lo usa `interleave`; los demas lo ignoran.
# ---------------------------------------------------------------------------

def _collect_containers(value: JSONValue, out: List[JSONValue]) -> None:
    """Junta TODOS los dict/list alcanzables (incluyendo el raiz) --
    para elegir un contenedor al azar donde aplicar una mutacion
    estructural, no solo en el nivel superior."""
    if isinstance(value, (dict, list)):
        out.append(value)
        children = value.values() if isinstance(value, dict) else value
        for child in children:
            _collect_containers(child, out)


def op_transpose(value: JSONValue, corpus_real: List[JSONValue], rng: random.Random) -> JSONValue:
    """Intercambia la posicion de dos elementos hermanos -- dos valores
    de un dict (las claves quedan fijas, los valores se cruzan) o dos
    elementos de una lista. Nunca inventa un valor nuevo, solo
    reordena/cruza los que ya estan ahi -- el analogo estructural de
    'swap de bytes' pero a nivel de arbol."""
    result = copy.deepcopy(value)
    containers = []
    _collect_containers(result, containers)
    candidates = [c for c in containers if len(c) >= 2]
    if not candidates:
        return result
    target = rng.choice(candidates)
    if isinstance(target, list):
        i, j = rng.sample(range(len(target)), 2)
        target[i], target[j] = target[j], target[i]
    else:
        keys = list(target.keys())
        k1, k2 = rng.sample(keys, 2)
        target[k1], target[k2] = target[k2], target[k1]
    return result


# Inversiones semanticas reales por tipo -- preservan la VALIDEZ de
# tipo (nunca convierten un numero en una lista, por ejemplo) pero
# invierten el significado logico del valor. Bug real de disenio que
# esto apunta a encontrar: codigo que asume que un campo "siempre" es
# true/no-vacio/positivo y no valida el caso opuesto explicitamente.
def _invert_scalar(v: JSONValue, rng: random.Random) -> JSONValue:
    if isinstance(v, bool):
        return not v
    if v is None:
        return rng.choice([0, "", [], {}, False])
    if isinstance(v, (int, float)):
        return -v if v != 0 else 1
    if isinstance(v, str):
        return "" if v else "x"
    return v


def op_semantic_inverse(value: JSONValue, corpus_real: List[JSONValue], rng: random.Random) -> JSONValue:
    """Encuentra un valor escalar (bool/null/numero/string) alcanzable
    y le invierte el significado logico -- ver _invert_scalar. Si no
    hay ninguno (documento vacio, o solo contenedores vacios), no
    cambia nada (nunca inventa un campo que no estaba)."""
    result = copy.deepcopy(value)

    def walk(node):
        if isinstance(node, dict):
            keys = list(node.keys())
            rng.shuffle(keys)
            for k in keys:
                if walk(node[k]):
                    return True
            return False
        if isinstance(node, list):
            indices = list(range(len(node)))
            rng.shuffle(indices)
            for i in indices:
                if walk(node[i]):
                    return True
            return False
        return True  # es un escalar, lo mutamos en el llamador

    def mutate_first_scalar(node):
        if isinstance(node, dict):
            for k in list(node.keys()):
                if isinstance(node[k], (dict, list)):
                    if mutate_first_scalar(node[k]):
                        return True
                else:
                    node[k] = _invert_scalar(node[k], rng)
                    return True
            return False
        if isinstance(node, list):
            for i in range(len(node)):
                if isinstance(node[i], (dict, list)):
                    if mutate_first_scalar(node[i]):
                        return True
                else:
                    node[i] = _invert_scalar(node[i], rng)
                    return True
            return False
        return False

    if isinstance(result, (dict, list)):
        mutate_first_scalar(result)
    else:
        result = _invert_scalar(result, rng)
    return result


def op_interleave(value: JSONValue, corpus_real: List[JSONValue], rng: random.Random) -> JSONValue:
    """Mezcla el documento con OTRO documento real del corpus -- si
    ambos son dicts, une claves alternando la fuente; si ambos son
    listas, intercala elementos de las dos. Si los tipos no combinan
    (uno es dict y el otro lista/escalar), devuelve el original sin
    tocar -- nunca fuerza una mezcla sin sentido."""
    if not corpus_real:
        return copy.deepcopy(value)
    other = rng.choice(corpus_real)

    if isinstance(value, dict) and isinstance(other, dict):
        merged = {}
        keys = list(dict.fromkeys(list(value.keys()) + list(other.keys())))
        for i, k in enumerate(keys):
            src = value if i % 2 == 0 else other
            merged[k] = copy.deepcopy(src.get(k, value.get(k, other.get(k))))
        return merged

    if isinstance(value, list) and isinstance(other, list):
        merged = []
        for i in range(max(len(value), len(other))):
            if i < len(value):
                merged.append(copy.deepcopy(value[i]))
            if i < len(other):
                merged.append(copy.deepcopy(other[i]))
        return merged

    return copy.deepcopy(value)


_PRIMITIVES = {
    "transpose": op_transpose,
    "semantic_inverse": op_semantic_inverse,
    "interleave": op_interleave,
}


# ---------------------------------------------------------------------------
# Combinadores -- seq/loop/choice. Evaluan la notacion REAL
# (seq(loop(interleave,3), choice(transpose, semantic_inverse))) via un
# parser chico de la sintaxis literal, no una traduccion a mano --
# demuestra que la notacion es ejecutable, no solo ilustrativa.
# ---------------------------------------------------------------------------

class OpNode:
    def __init__(self, name: str, args: List):
        self.name = name
        self.args = args

    def __repr__(self):
        return f"{self.name}({', '.join(repr(a) for a in self.args)})"


_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|\(|\)|,|\d+")


def parse_operator_tree(expr: str) -> OpNode:
    """Parser recursivo-descendente chico para la notacion real:
    identificador, opcionalmente seguido de '(' args separados por ','
    ')'. Un argumento es o bien otro nodo (identificador con o sin
    parentesis) o un entero literal (para loop(X, 3))."""
    tokens = _TOKEN_RE.findall(expr)
    pos = 0

    def parse_node():
        nonlocal pos
        name = tokens[pos]
        pos += 1
        if pos < len(tokens) and tokens[pos] == "(":
            pos += 1
            args = []
            while tokens[pos] != ")":
                if tokens[pos].isdigit():
                    args.append(int(tokens[pos]))
                    pos += 1
                else:
                    args.append(parse_node())
                if tokens[pos] == ",":
                    pos += 1
            pos += 1  # consume ')'
            return OpNode(name, args)
        return OpNode(name, [])

    node = parse_node()
    if pos != len(tokens):
        raise ValueError(f"expresion invalida, tokens sobrantes despues de la posicion {pos}: {tokens[pos:]}")
    return node


def eval_operator_tree(node: OpNode, value: JSONValue, corpus_real: List[JSONValue], rng: random.Random) -> JSONValue:
    if node.name in _PRIMITIVES:
        return _PRIMITIVES[node.name](value, corpus_real, rng)

    if node.name == "seq":
        for arg in node.args:
            value = eval_operator_tree(arg, value, corpus_real, rng)
        return value

    if node.name == "loop":
        inner, count = node.args
        for _ in range(count):
            value = eval_operator_tree(inner, value, corpus_real, rng)
        return value

    if node.name == "choice":
        chosen = rng.choice(node.args)
        return eval_operator_tree(chosen, value, corpus_real, rng)

    raise ValueError(f"operador desconocido: {node.name!r} (primitivos: {sorted(_PRIMITIVES)}, "
                      f"combinadores: seq/loop/choice)")


def mutate(expr: str, value: JSONValue, corpus_real: List[JSONValue], rng: random.Random) -> JSONValue:
    """Punto de entrada real: parsea `expr` (la notacion literal) UNA
    vez y la evalua contra `value`. Ejemplo real:
    mutate("seq(loop(interleave,3), choice(transpose, semantic_inverse))", doc, corpus, rng)."""
    tree = parse_operator_tree(expr)
    return eval_operator_tree(tree, value, corpus_real, rng)
