"""Tests reales (compilan/corren Go de verdad contra harness_gen/testdata/samplepkg/,
un paquete local minimo -- no dependen de red ni de clonar un repo real,
a diferencia del flujo completo con Ollama que si necesita ambos).

test_try_compile_and_run_rejects_file_with_unused_import es la
regresion real del bug encontrado en produccion (2026-08-15): el
archivo inyectado se llamaba "_harness_gen_candidate_test.go" -- un
nombre que EMPIEZA con "_" es ignorado en silencio por el propio `go`
tool, asi que la validacion nunca compilaba nada de verdad y cualquier
harness invalido (imports sin usar, sintaxis rota, lo que sea) pasaba
como "OK". Confirmado en vivo con un harness real generado por
qwen3-coder que SI tenia ese bug -- ver harness_gen/README.md para el
relato completo."""

import os

from generate_go_harness import _find_function_file, _strip_markdown_fences, _try_compile_and_run

_TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


def test_strip_markdown_fences_removes_fences():
    text = "```go\npackage samplepkg\n\nfunc X() {}\n```"
    assert _strip_markdown_fences(text) == "package samplepkg\n\nfunc X() {}"


def test_strip_markdown_fences_noop_without_fences():
    text = "package samplepkg\n\nfunc X() {}"
    assert _strip_markdown_fences(text) == text


def test_find_function_file_locates_real_function():
    filename, content, package_name = _find_function_file(_TESTDATA, "samplepkg", "ParseLenPrefixed")
    assert filename == "sample.go"
    assert package_name == "samplepkg"
    assert "func ParseLenPrefixed(data []byte) []byte" in content


def test_find_function_file_raises_for_missing_function():
    try:
        _find_function_file(_TESTDATA, "samplepkg", "FunctionThatDoesNotExist")
        assert False, "tenia que lanzar FileNotFoundError"
    except FileNotFoundError:
        pass


def test_try_compile_and_run_rejects_file_with_unused_import():
    # Regresion real del bug del nombre de archivo con "_" inicial --
    # ver docstring del modulo. Este harness es invalido a proposito
    # (importa "strings" y nunca lo usa).
    bad_harness = '''package samplepkg

import (
\t"testing"
\t"strings"
)

func FuzzParseLenPrefixed(f *testing.F) {
\tf.Add([]byte{0x01, 0x41})
\tf.Fuzz(func(t *testing.T, data []byte) {
\t\tif len(data) == 0 {
\t\t\treturn
\t\t}
\t\tParseLenPrefixed(data)
\t})
}
'''
    ok, err = _try_compile_and_run(_TESTDATA, "samplepkg", bad_harness, "FuzzParseLenPrefixed")
    assert ok is False
    assert "imported and not used" in err


def test_try_compile_and_run_accepts_valid_harness_and_runs_it_for_real():
    # ParseLenPrefixed panickea de verdad si el prefijo de longitud pide
    # mas bytes de los que hay (a proposito, ver sample.go) -- el guard
    # de abajo evita ESE input especifico para que este test verifique
    # el validador (compila + corre), no que encuentre el bug real
    # (eso ya lo prueban los tests de scheduler.py/triage/ por separado).
    good_harness = '''package samplepkg

import "testing"

func FuzzParseLenPrefixed(f *testing.F) {
\tf.Add([]byte{0x01, 0x41})
\tf.Fuzz(func(t *testing.T, data []byte) {
\t\tif len(data) == 0 || int(data[0]) > len(data)-1 {
\t\t\treturn
\t\t}
\t\tParseLenPrefixed(data)
\t})
}
'''
    ok, err = _try_compile_and_run(_TESTDATA, "samplepkg", good_harness, "FuzzParseLenPrefixed")
    assert ok is True, err
    assert err == ""
