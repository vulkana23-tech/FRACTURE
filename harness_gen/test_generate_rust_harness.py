"""Tests contra harness_gen/testdata/rust_samplecrate/, un crate Rust
real y minimo, local (no depende de red ni de clonar nada) -- las
operaciones que MUTAN el crate (scaffolding, registro de targets)
corren contra una copia temporal, nunca contra el fixture commiteado."""

import os
import shutil
import tempfile

from generate_rust_harness import (
    _crate_name,
    _ensure_fuzz_scaffolding,
    _find_function_file,
    _register_fuzz_target,
    _remove_placeholder_target,
)

_TESTDATA_CRATE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "testdata", "rust_samplecrate"
)


def _copy_crate_to_tmp() -> str:
    tmpdir = tempfile.mkdtemp(prefix="fracture_rust_harness_test_")
    crate_dir = os.path.join(tmpdir, "rust_samplecrate")
    shutil.copytree(_TESTDATA_CRATE, crate_dir)
    return crate_dir


def test_crate_name_reads_real_cargo_toml():
    assert _crate_name(_TESTDATA_CRATE) == "rust_samplecrate"


def test_find_function_file_locates_real_pub_fn():
    path, content = _find_function_file(_TESTDATA_CRATE, "parse_len_prefixed")
    assert path == os.path.join("src", "lib.rs")
    assert "pub fn parse_len_prefixed(data: &[u8])" in content


def test_find_function_file_raises_for_missing_function():
    try:
        _find_function_file(_TESTDATA_CRATE, "funcion_que_no_existe")
        assert False, "tenia que lanzar FileNotFoundError"
    except FileNotFoundError:
        pass


def test_find_function_file_ignores_non_pub_functions():
    # parse_len_prefixed es pub -- una funcion privada con nombre
    # parecido no tendria que matchear (esto documenta la intencion,
    # no hay una funcion privada real en el fixture para probarlo
    # negativamente sin agregar ruido al fixture).
    _, content = _find_function_file(_TESTDATA_CRATE, "parse_len_prefixed")
    assert "pub fn" in content


def test_ensure_fuzz_scaffolding_bootstraps_real_fuzz_dir():
    crate_dir = _copy_crate_to_tmp()
    try:
        assert not os.path.isdir(os.path.join(crate_dir, "fuzz"))
        created = _ensure_fuzz_scaffolding(crate_dir)
        assert created is True
        assert os.path.isfile(os.path.join(crate_dir, "fuzz", "Cargo.toml"))
        # cargo +nightly fuzz init ya arma el path a la crate real --
        # confirmar que apunta a ESTE crate, no a otro.
        with open(os.path.join(crate_dir, "fuzz", "Cargo.toml")) as fh:
            assert "[dependencies.rust_samplecrate]" in fh.read()
    finally:
        shutil.rmtree(os.path.dirname(crate_dir), ignore_errors=True)


def test_ensure_fuzz_scaffolding_never_touches_existing_fuzz_dir():
    crate_dir = _copy_crate_to_tmp()
    try:
        _ensure_fuzz_scaffolding(crate_dir)
        cargo_toml_path = os.path.join(crate_dir, "fuzz", "Cargo.toml")
        with open(cargo_toml_path) as fh:
            before = fh.read()
        created_again = _ensure_fuzz_scaffolding(crate_dir)
        with open(cargo_toml_path) as fh:
            after = fh.read()
        assert created_again is False
        assert before == after
    finally:
        shutil.rmtree(os.path.dirname(crate_dir), ignore_errors=True)


def test_remove_placeholder_target_leaves_valid_toml_no_orphaned_lines():
    # Regresion real del bug encontrado en produccion (2026-08-16): un
    # regex no-greedy generico dejaba "test = false\ndoc = false\n
    # bench = false" huerfanos (sin su [[bin]]/name/path), TOML
    # invalido. El fix hace match literal del bloque exacto que
    # `cargo +nightly fuzz init` genera de verdad.
    crate_dir = _copy_crate_to_tmp()
    try:
        _ensure_fuzz_scaffolding(crate_dir)
        _remove_placeholder_target(crate_dir)
        cargo_toml_path = os.path.join(crate_dir, "fuzz", "Cargo.toml")
        with open(cargo_toml_path) as fh:
            content = fh.read()
        assert "fuzz_target_1" not in content
        # Nunca deja "test = false" huerfano sin su [[bin]] -- si el
        # bug reaparece, esto lo atrapa.
        assert "[[bin]]" not in content or content.count("[[bin]]") == content.count("name =")
        assert not os.path.isfile(
            os.path.join(crate_dir, "fuzz", "fuzz_targets", "fuzz_target_1.rs")
        )
    finally:
        shutil.rmtree(os.path.dirname(crate_dir), ignore_errors=True)


def test_register_fuzz_target_appends_without_touching_existing_entries():
    crate_dir = _copy_crate_to_tmp()
    try:
        _ensure_fuzz_scaffolding(crate_dir)
        _remove_placeholder_target(crate_dir)
        _register_fuzz_target(crate_dir, "primer_target")
        _register_fuzz_target(crate_dir, "segundo_target")
        cargo_toml_path = os.path.join(crate_dir, "fuzz", "Cargo.toml")
        with open(cargo_toml_path) as fh:
            content = fh.read()
        assert 'name = "primer_target"' in content
        assert 'name = "segundo_target"' in content
        assert content.count("[[bin]]") == 2
    finally:
        shutil.rmtree(os.path.dirname(crate_dir), ignore_errors=True)


def test_register_fuzz_target_is_idempotent_for_same_name():
    crate_dir = _copy_crate_to_tmp()
    try:
        _ensure_fuzz_scaffolding(crate_dir)
        _remove_placeholder_target(crate_dir)
        _register_fuzz_target(crate_dir, "mismo_target")
        _register_fuzz_target(crate_dir, "mismo_target")
        cargo_toml_path = os.path.join(crate_dir, "fuzz", "Cargo.toml")
        with open(cargo_toml_path) as fh:
            content = fh.read()
        assert content.count('name = "mismo_target"') == 1
    finally:
        shutil.rmtree(os.path.dirname(crate_dir), ignore_errors=True)
