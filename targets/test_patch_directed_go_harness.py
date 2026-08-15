"""Tests de la parte determinística (extracción/priorización de
candidatos Go) -- sin red, sin Ollama. La parte que sí depende de
ambos (find_and_generate) se probó en vivo contra
hyperledger/fabric -- ver targets/README.md para el resultado real y
por qué se descartó el harness que salió (`Ready()`, sin superficie de
bytes real)."""

from patch_directed_go_harness import _extract_go_candidates


def _make_candidate(files_changed, functions_touched_guess):
    return {"files_changed": files_changed, "functions_touched_guess": functions_touched_guess}


def test_extracts_real_go_function_names():
    candidate = _make_candidate(
        ["gossip/state/payloads_buffer.go"],
        ["func (b *PayloadsBufferImpl) Push(payload *proto.Payload) {"],
    )
    results = _extract_go_candidates(candidate)
    assert len(results) == 1
    assert results[0]["function_name"] == "Push"
    assert results[0]["package_path"] == "gossip/state"


def test_ignores_non_test_go_files_only():
    candidate = _make_candidate(
        ["gossip/state/payloads_buffer_test.go"],
        ["func (b *PayloadsBufferImpl) Push(payload *proto.Payload) {"],
    )
    assert _extract_go_candidates(candidate) == []


def test_ignores_non_function_contexts():
    candidate = _make_candidate(
        ["gossip/state/payloads_buffer.go"],
        ["import (", "type metricsBuffer struct {"],
    )
    assert _extract_go_candidates(candidate) == []


def test_prioritizes_byte_or_string_taking_functions_over_others():
    # Caso real encontrado corriendo esto en vivo contra
    # hyperledger/fabric: sin esta priorizacion, el primer candidato
    # que salia era Ready() (sin parametros reales) en vez de una
    # funcion que si toma bytes/strings -- el harness compilaba y
    # corria (VALIDO) pero sin ninguna superficie de fuzzing real.
    candidate = _make_candidate(
        ["gossip/state/payloads_buffer.go"],
        [
            "func (b *PayloadsBufferImpl) Ready() chan struct{} {",
            "func (b *PayloadsBufferImpl) Push(payload *proto.Payload) {",
            "func ParseHeader(data []byte) (int, error) {",
        ],
    )
    results = _extract_go_candidates(candidate)
    # ParseHeader (toma []byte real) tiene que salir ANTES que Ready()
    # (sin parametros) en la lista final.
    names_in_order = [r["function_name"] for r in results]
    assert names_in_order.index("ParseHeader") < names_in_order.index("Ready")


def test_tries_all_changed_go_files_when_context_is_ambiguous():
    candidate = _make_candidate(
        ["pkg/a/file1.go", "pkg/b/file2.go"],
        ["func Decode(data []byte) error {"],
    )
    results = _extract_go_candidates(candidate)
    assert len(results) == 2
    assert {r["package_path"] for r in results} == {"pkg/a", "pkg/b"}
