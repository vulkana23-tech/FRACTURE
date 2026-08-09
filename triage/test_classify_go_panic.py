"""Tests contra el fixture REAL (no sintetico) capturado corriendo
go test de verdad contra el crash real de fabric-amcl -- ver
findings/2026-08-09_fabric-amcl-dilithium-panic.md para el contexto
completo de este hallazgo."""

import os

from classify_go_panic import extract_panic_info

_FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "testdata",
    "fabric_amcl_dilithium_panic_real.txt",
)


def _load_fixture() -> str:
    with open(_FIXTURE_PATH, "r") as fh:
        return fh.read()


def test_extracts_real_panic_message():
    info = extract_panic_info(_load_fixture())
    assert info is not None
    assert "index out of range" in info["panic_message"]


def test_classifies_index_out_of_range_as_high_severity():
    info = extract_panic_info(_load_fixture())
    assert info["severity"] == "high"
    assert info["panic_type"] == "index out of range"


def test_extracts_real_target_stack_excluding_go_internals():
    info = extract_panic_info(_load_fixture())
    # El primer frame real (no testing/runtime/reflect) tiene que ser
    # exactamente donde esta el bug real -- confirmado a mano leyendo
    # el codigo fuente real de fabric-amcl.
    assert "DL_unpack_pk" in info["top_frame"]
    assert "DILITHIUM.go:484" in info["top_frame"]
    # El resto de la cadena de llamadas real tiene que estar completa.
    joined = " ".join(info["target_frames"])
    assert "DL_verify_2" in joined
    assert "FuzzDLVerify2" in joined
    # Nunca frames de plomeria interna de Go en el stack filtrado.
    assert "testing.tRunner" not in joined
    assert "runtime.panic" not in joined


def test_returns_none_for_clean_output():
    clean_output = "=== RUN   FuzzExample\n--- PASS: FuzzExample (0.01s)\nPASS\nok  \tsome/package\t0.012s\n"
    assert extract_panic_info(clean_output) is None


def test_stack_hash_is_deterministic():
    fixture = _load_fixture()
    info1 = extract_panic_info(fixture)
    info2 = extract_panic_info(fixture)
    assert info1["stack_hash"] == info2["stack_hash"]
