"""Tests contra harness_gen/testdata/c_samplelib/, una libreria C real y
minima, local (sin red) -- las partes que dependen de red/Ollama
(generate_and_validate_harness completo) se probaron en vivo contra
cJSON real, ver harness_gen/README.md para el resultado (2 intentos:
el primero fallo con un error REAL de compilador -- memcpy sin
<string.h> -- el segundo compilo y corrio)."""

import os

from generate_harness import (
    _find_matching_source_file,
    _fix_common_issues,
    _try_compile_and_run,
)

_TESTDATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "c_samplelib")
_HEADER_PATH = os.path.join(_TESTDATA_DIR, "samplelib.h")
_SOURCE_PATH = os.path.join(_TESTDATA_DIR, "samplelib.c")


def test_find_matching_source_file_locates_real_c_file():
    assert _find_matching_source_file(_HEADER_PATH) == _SOURCE_PATH


def test_find_matching_source_file_returns_none_when_missing():
    fake_header = os.path.join(_TESTDATA_DIR, "no_existe.h")
    assert _find_matching_source_file(fake_header) is None


def test_fix_common_issues_corrects_lowercase_include():
    harness = '#include "samplelib.h"\nint LLVMFuzzerTestOneInput(...) { return 0; }'
    fixed = _fix_common_issues(harness.replace('"samplelib.h"', '"SampleLib.h"'), "samplelib.h")
    assert '#include "samplelib.h"' in fixed


def test_fix_common_issues_adds_stdint_when_missing():
    harness = '#include "samplelib.h"\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }'
    fixed = _fix_common_issues(harness, "samplelib.h")
    assert "#include <stdint.h>" in fixed


def test_try_compile_and_run_accepts_valid_harness_and_runs_it_for_real():
    good_harness = '''#include "samplelib.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t out_len;
    samplelib_parse_len_prefixed(data, size, &out_len);
    return 0;
}
'''
    ok, err = _try_compile_and_run(good_harness, _TESTDATA_DIR, [_SOURCE_PATH], [])
    assert ok is True, err


def test_try_compile_and_run_rejects_harness_with_real_compile_error():
    # Mismo error real encontrado en vivo contra cJSON: memcpy sin
    # <string.h> -- "implicit function declaration" es un error real
    # de clang moderno (C99+), no un aviso.
    bad_harness = '''#include "samplelib.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char *buf = malloc(size);
    memcpy(buf, data, size);
    size_t out_len;
    samplelib_parse_len_prefixed(buf, size, &out_len);
    return 0;
}
'''
    ok, err = _try_compile_and_run(bad_harness, _TESTDATA_DIR, [_SOURCE_PATH], [])
    assert ok is False
    assert "implicit" in err.lower() or "undeclared" in err.lower()
