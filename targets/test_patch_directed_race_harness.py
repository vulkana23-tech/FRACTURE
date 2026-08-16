"""Tests de la parte determinística (filtro/extracción de candidatos de
race condition) -- sin red, sin Ollama. La parte que sí depende de
ambos (find_and_generate, generate_and_validate_race_test) se validó
en vivo a mano contra hyperledger/fabric-lib-go -- ver
targets/README.md: un stress test de 2 goroutines detectó la carrera
real (commit 8fe16c9967) en la versión pre-fix, y salió limpio en la
versión post-fix."""

from patch_directed_race_harness import _RACE_KEYWORDS_RE, _extract_race_candidates


def _make_candidate(files_changed, functions_touched_guess, subject=""):
    return {"files_changed": files_changed, "functions_touched_guess": functions_touched_guess,
            "subject": subject}


def test_race_keywords_matches_real_fabric_lib_go_subject():
    assert _RACE_KEYWORDS_RE.search("Use atomic.Pointer to prevent race condition in bccsp.Factory (#48)")


def test_race_keywords_does_not_match_unrelated_security_subjects():
    # Estos SI matchean _SECURITY_KEYWORDS (van al pipeline de bytes),
    # pero NO son candidatos de concurrencia.
    assert _RACE_KEYWORDS_RE.search("Fix heap buffer overflow") is None
    assert _RACE_KEYWORDS_RE.search("prevent NULL pointer dereference in cJSON_SetNumberHelper") is None


def test_race_keywords_matches_deadlock():
    assert _RACE_KEYWORDS_RE.search("Fix deadlock in connection pool")


def test_extracts_real_fabric_lib_go_functions():
    candidate = _make_candidate(
        ["bccsp/factory/factory.go", "bccsp/factory/nopkcs11.go"],
        [
            "func InitFactories(config *FactoryOpts) error {",
            "func GetDefault() bccsp.BCCSP {",
        ],
    )
    results = _extract_race_candidates(candidate)
    assert len(results) == 1
    assert results[0]["package_path"] == "bccsp/factory"
    assert results[0]["functions"] == ["InitFactories", "GetDefault"]


def test_ignores_test_files_only():
    candidate = _make_candidate(
        ["bccsp/factory/factory_test.go"],
        ["func TestInitFactories(t *testing.T) {"],
    )
    assert _extract_race_candidates(candidate) == []


def test_ignores_non_function_contexts():
    candidate = _make_candidate(
        ["bccsp/factory/factory.go"],
        ["import (", "type BCCSPFactory interface {"],
    )
    assert _extract_race_candidates(candidate) == []


def test_deduplicates_same_function_across_contexts():
    candidate = _make_candidate(
        ["bccsp/factory/factory.go"],
        [
            "func GetDefault() bccsp.BCCSP {",
            "func GetDefault() bccsp.BCCSP {",
        ],
    )
    results = _extract_race_candidates(candidate)
    assert results[0]["functions"] == ["GetDefault"]


def test_excludes_test_functions_from_same_commit():
    # Caso REAL encontrado corriendo esto en vivo contra
    # hyperledger/fabric-lib-go (commit 8fe16c9967): el commit real
    # toca factory_test.go en el mismo commit que el fix -- sin
    # filtrar, se colaban 11 nombres (TestMain,
    # TestBootBCCSPConcurrent, etc.) en un solo prompt y el modelo no
    # lograba compilar nada coherente en 3 intentos.
    candidate = _make_candidate(
        ["bccsp/factory/factory.go", "bccsp/factory/factory_test.go"],
        [
            "func initFactories(config *FactoryOpts) (bccsp.BCCSP, error) {",
            "func TestInitFactories(t *testing.T) {",
            "func TestMain(m *testing.M) {",
            "func InitFactories(config *FactoryOpts) error {",
            "func GetDefault() bccsp.BCCSP {",
            "func TestBootBCCSPConcurrent(t *testing.T) {",
        ],
    )
    results = _extract_race_candidates(candidate)
    assert len(results) == 1
    assert results[0]["functions"] == ["initFactories", "InitFactories", "GetDefault"]


def test_tries_each_distinct_package_touched():
    candidate = _make_candidate(
        ["pkg/a/file1.go", "pkg/b/file2.go"],
        ["func Shared() error {"],
    )
    results = _extract_race_candidates(candidate)
    assert {r["package_path"] for r in results} == {"pkg/a", "pkg/b"}
