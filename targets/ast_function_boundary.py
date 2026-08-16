"""Resuelve la funcion/metodo real que contiene una linea de codigo,
parseando el archivo con tree-sitter en vez de confiar solo en la
heuristica de contexto que `git show` infiere gratis.

Por que existe: `targets/README.md` documenta una limitacion real
encontrada en vivo (no teorica) -- el fix real de UAF en
`jsg::Function` (cloudflare/workerd, commit `644f2c1598`) NO quedo
marcado por `_guess_functions_touched` porque el hunk de git anclo el
contexto a la clase CONTENEDORA (`class Function<Ret(Args...)> {`) en
vez de al metodo real (`Ret operator()(jsg::Lock& jsl, Args... args)`)
-- pasa cuando el metodo esta definido inline dentro de una clase
template en un header, un caso donde la heuristica propia de git no
baja hasta la firma real. Este modulo es una SEGUNDA fuente de señal,
basada en el AST real del archivo post-parche en vez del contexto que
`git show` infiere -- no reemplaza `_guess_functions_touched` (que es
gratis y funciona bien en el caso comun), lo complementa para el caso
donde falla.

Nunca lanza sobre codigo real que no parsea limpio -- best-effort,
devuelve lista vacia si el lenguaje no esta soportado o el parseo
falla, exactamente la misma filosofia que "nunca inventar un nombre"
de `_guess_functions_touched`.
"""

import re
from typing import Dict, List, Optional, Set, Tuple

try:
    from tree_sitter import Language, Node, Parser
    import tree_sitter_cpp
    import tree_sitter_go
    import tree_sitter_java
    import tree_sitter_rust
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False

# Nodos que tree-sitter etiqueta como "definicion de funcion/metodo
# real, con cuerpo" para cada gramatica -- confirmado en vivo parseando
# ejemplos reales de cada lenguaje (ver test_ast_function_boundary.py).
_FUNCTION_NODE_TYPES: Dict[str, Set[str]] = {
    "cpp": {"function_definition"},
    "go": {"function_declaration", "method_declaration"},
    "rust": {"function_item"},
    "java": {"method_declaration", "constructor_declaration"},
}

# Nodo que marca donde empieza el CUERPO real (para cortar la firma
# ahi y no arrastrar el cuerpo entero en el texto de la firma).
_BODY_NODE_TYPES = {"compound_statement", "block", "function_body"}

_EXT_TO_LANG = {
    ".c": "cpp", ".h": "cpp",  # C es un subconjunto sintactico razonable de C++
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
}

_parsers_cache: Dict[str, "Parser"] = {}


def _get_parser(lang_name: str) -> Optional["Parser"]:
    if not _TREE_SITTER_AVAILABLE:
        return None
    if lang_name in _parsers_cache:
        return _parsers_cache[lang_name]
    module_by_lang = {
        "cpp": tree_sitter_cpp,
        "go": tree_sitter_go,
        "rust": tree_sitter_rust,
        "java": tree_sitter_java,
    }
    module = module_by_lang.get(lang_name)
    if module is None:
        return None
    language = Language(module.language())
    parser = Parser(language)
    _parsers_cache[lang_name] = parser
    return parser


def language_for_path(file_path: str) -> Optional[str]:
    for ext, lang in _EXT_TO_LANG.items():
        if file_path.endswith(ext):
            return lang
    return None


def _collect_enclosing_chain(node: "Node", row: int, func_types: Set[str], chain: List["Node"]) -> None:
    """Junta TODOS los nodos funcion-como que contienen `row`, del mas
    externo al mas interno -- no solo el mas chico/especifico.

    Bug real encontrado corriendo esto en vivo contra
    cloudflare/workerd (no teorico): los macros `KJ_SWITCH_ONEOF`/
    `KJ_CASE_ONEOF` (con forma `NOMBRE(args) { ... }`) enganan a la
    gramatica de tree-sitter-cpp -- sin preprocesar el archivo, los
    parsea como si fueran DEFINICIONES DE FUNCION anidadas dentro del
    metodo real que las contiene. Quedandose solo con el nodo mas chico
    que contiene la linea cambiada devolvia `KJ_CASE_ONEOF(native,
    Ref<NativeFunction>)` en vez de `Ret operator()(jsg::Lock& jsl,
    Args... args)` -- perdiendo exactamente la firma real que se
    necesitaba para que `_looks_js_engine_lifecycle_bound` la marcara.
    Devolver la cadena completa de ancestros incluye ambas: la firma
    real de mas afuera (la que importa) y el ruido de macro de mas
    adentro (inofensivo, `_looks_js_engine_lifecycle_bound` solo
    necesita que ALGUNA firma matchee)."""
    if not (node.start_point[0] <= row <= node.end_point[0]):
        return
    if node.type in func_types:
        chain.append(node)
    for child in node.children:
        _collect_enclosing_chain(child, row, func_types, chain)


def _signature_text(node: "Node", source: bytes) -> str:
    body_start = node.end_byte
    for child in node.children:
        if child.type in _BODY_NODE_TYPES:
            body_start = child.start_byte
            break
    raw = source[node.start_byte:body_start].decode("utf-8", errors="replace")
    return " ".join(raw.split())


def enclosing_function_signatures(file_path: str, source: bytes, changed_lines: Set[int]) -> List[str]:
    """`changed_lines` son numeros de linea 1-indexados (como los que
    imprime git) del lado POST-parche del archivo. Devuelve firmas
    unicas, en el mismo orden que aparecen, de las funciones/metodos
    reales que contienen al menos una de esas lineas -- vacio si el
    lenguaje no esta soportado o el parseo falla (nunca inventa,
    nunca revienta el pipeline que lo llama)."""
    lang_name = language_for_path(file_path)
    if lang_name is None:
        return []
    parser = _get_parser(lang_name)
    if parser is None:
        return []
    try:
        tree = parser.parse(source)
    except Exception:
        return []

    func_types = _FUNCTION_NODE_TYPES[lang_name]
    signatures: List[str] = []
    seen = set()
    for line in sorted(changed_lines):
        row = line - 1
        if row < 0:
            continue
        chain: List["Node"] = []
        _collect_enclosing_chain(tree.root_node, row, func_types, chain)
        for node in chain:
            sig = _signature_text(node, source)
            if sig and sig not in seen:
                seen.add(sig)
                signatures.append(sig)
    return signatures


# Parsea encabezados de hunk unificado ("@@ -a,b +c,d @@ ...") para
# extraer el rango de lineas del lado POST-parche -- mismo formato que
# ya usa _HUNK_FUNC_RE en find_patch_directed_candidates.py, pero acá
# hace falta el numero de linea real, no solo el contexto de texto.
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def changed_line_numbers_post_patch(file_diff_text: str) -> Set[int]:
    """`file_diff_text` es el diff de UN SOLO archivo (unified, con
    encabezados @@). Devuelve el conjunto de numeros de linea reales
    (lado post-parche) que el diff toca -- suficiente para ubicar en
    que funcion cae cada hunk sin tener que re-parsear el diff entero
    linea por linea."""
    lines: Set[int] = set()
    for m in _HUNK_HEADER_RE.finditer(file_diff_text):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        if count == 0:
            # hunk de borrado puro (0 lineas del lado post) -- no hay
            # linea real del lado nuevo para anclar, se descarta.
            continue
        for offset in range(count):
            lines.add(start + offset)
    return lines
