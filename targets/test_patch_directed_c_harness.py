"""Tests de la parte determinística (extracción/priorización de
candidatos C) -- sin red, sin Ollama. La parte que sí depende de
ambos (find_and_generate) queda pendiente de una corrida real contra
un repo C amalgamado del scope (cJSON-style) -- ver targets/README.md."""

from patch_directed_c_harness import _c_function_name_from_context, _extract_c_candidates, _header_name_for_source


def _make_candidate(files_changed, functions_touched_guess):
    return {"files_changed": files_changed, "functions_touched_guess": functions_touched_guess}


def test_c_function_name_from_real_cjson_signature():
    assert _c_function_name_from_context("CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value)") == "cJSON_Parse"


def test_c_function_name_ignores_control_flow_keywords():
    assert _c_function_name_from_context("if (value == NULL) {") is None
    assert _c_function_name_from_context("for (i = 0; i < len; i++) {") is None
    assert _c_function_name_from_context("while (parse_more(ctx)) {") == "parse_more"  # el keyword se salta, la llamada real adentro no


def test_c_function_name_ignores_non_function_context():
    assert _c_function_name_from_context("typedef struct cJSON {") is None
    assert _c_function_name_from_context("} cJSON;") is None


def test_header_name_for_source_c_to_h():
    assert _header_name_for_source("cJSON.c") == "cJSON.h"
    assert _header_name_for_source("src/parson.c") == "parson.h"


def test_header_name_for_source_header_stays_same():
    assert _header_name_for_source("include/zbxjson.h") == "zbxjson.h"


def test_header_name_for_source_non_c_file_returns_none():
    assert _header_name_for_source("README.md") is None
    assert _header_name_for_source("build.py") is None


def test_extracts_real_c_function_and_header():
    candidate = _make_candidate(
        ["cJSON.c", "cJSON.h"],
        ["CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value)"],
    )
    results = _extract_c_candidates(candidate)
    assert len(results) == 1
    assert results[0]["function_name"] == "cJSON_Parse"
    assert results[0]["header_name"] == "cJSON.h"


def test_extracts_header_even_when_only_c_file_changed():
    # generate_and_validate_harness busca el header en TODO el repo
    # clonado, no solo entre los archivos tocados por el commit -- no
    # hace falta que el .h haya cambiado en el mismo commit.
    candidate = _make_candidate(
        ["src/parson.c"],
        ["JSON_Value *json_parse_string(const char *string)"],
    )
    results = _extract_c_candidates(candidate)
    assert results[0]["header_name"] == "parson.h"


def test_ignores_commits_without_c_or_h_files():
    candidate = _make_candidate(
        ["docs/README.md", "go.mod"],
        ["int foo(char *bar)"],
    )
    assert _extract_c_candidates(candidate) == []


def test_prioritizes_byte_or_string_taking_functions_over_others():
    # Mismo criterio real ya validado en vivo para Go/Rust (ver
    # test_patch_directed_go_harness.py) -- preferir candidatos con
    # superficie de fuzzing real (const char*/uint8_t* como parametro)
    # sobre los que no toman ninguna entrada externa.
    candidate = _make_candidate(
        ["cJSON.c", "cJSON.h"],
        [
            "cJSON_bool cJSON_IsInvalid(const cJSON * const item)",
            "CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value)",
        ],
    )
    results = _extract_c_candidates(candidate)
    names_in_order = [r["function_name"] for r in results]
    assert names_in_order.index("cJSON_Parse") < names_in_order.index("cJSON_IsInvalid")


def test_excludes_test_function_that_leaked_in_from_a_different_file_in_same_commit():
    # Caso REAL encontrado corriendo esto en vivo contra
    # DaveGamble/cJSON (commit b2890c8d76, "prevent NULL pointer
    # dereference in cJSON_SetNumberHelper"): el commit tambien toca
    # tests/misc_tests.c, y el contexto de un hunk ahi se colaba como
    # candidato -- el pipeline generaba (y "validaba") un harness real,
    # pero fuzzeando cJSON_Parse en general porque el modelo ignoro el
    # nombre de funcion de test inexistente en el header, no la funcion
    # real del fix. cJSON_SetNumberHelper (la funcion real) tiene que
    # sobrevivir el filtro y quedar como unico candidato.
    candidate = _make_candidate(
        ["cJSON.c", "tests/misc_tests.c"],
        [
            "loop_end:",
            "static void cjson_functions_should_not_crash_with_null_pointers(void)",
            "cJSON_SetNumberHelper(cJSON *object, double number)",
        ],
    )
    results = _extract_c_candidates(candidate)
    names = [r["function_name"] for r in results]
    assert "cjson_functions_should_not_crash_with_null_pointers" not in names
    assert "cJSON_SetNumberHelper" in names


def test_deduplicates_same_function_name_across_contexts():
    candidate = _make_candidate(
        ["cJSON.c", "cJSON.h"],
        [
            "CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value)",
            "CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value) {",
        ],
    )
    results = _extract_c_candidates(candidate)
    assert len(results) == 1
