"""Tests de la parte determinística (regex/filtros) -- sin red, sin
clonar nada. La parte que sí depende de red/git (find_patch_directed_candidates)
se probó en vivo contra hyperledger/fabric-ca (resultado honesto: 0
candidatos reales, todo el historial de seguridad eran bumps de
dependencias) y cloudflare/workerd (resultado real: encontró fixes
reales de use-after-free en src/workerd/api/streams/ y zlib-util.c++
-- código que este proyecto todavía NO tiene harnesseado, a diferencia
de dataurl/encoding/formdata/mimetype que sí) -- ver
targets/README.md."""

from find_patch_directed_candidates import (
    _SECURITY_KEYWORDS,
    _guess_functions_touched,
    _has_source_code_change,
    _looks_js_engine_lifecycle_bound,
)


def test_security_keywords_matches_real_workerd_subjects():
    assert _SECURITY_KEYWORDS.search("Address UAF and safety bugs in pipe handling")
    assert _SECURITY_KEYWORDS.search("Fix use-after-free when a native jsg::Function frees itself mid-call")


def test_security_keywords_does_not_match_unrelated_subjects():
    assert _SECURITY_KEYWORDS.search("Bump eslint to 9.2.0") is None
    assert _SECURITY_KEYWORDS.search("Rename variable for clarity") is None


def test_security_keywords_matches_spanish():
    assert _SECURITY_KEYWORDS.search("Arreglar desbordamiento en el parser")
    assert _SECURITY_KEYWORDS.search("Corrige puntero nulo en el handler")


def test_has_source_code_change_true_for_real_application_file():
    assert _has_source_code_change(["src/workerd/api/node/zlib-util.c++", "src/workerd/api/node/zlib-util.h"])


def test_has_source_code_change_false_for_dependency_bump_only():
    # Caso real encontrado probando esto contra fabric-ca: go.mod/go.sum
    # matchean "CVE" en el mensaje del commit pero no son codigo fuente.
    assert _has_source_code_change(["go.mod", "go.sum"]) is False


def test_has_source_code_change_false_for_vendored_source():
    # Segundo caso real encontrado: vendor/ SI tiene extension .go real
    # (Go vendorea el codigo completo de la dependencia) -- pero es
    # codigo de terceros, no del repo que se esta evaluando.
    assert _has_source_code_change(["vendor/github.com/felixge/httpsnoop/capture_metrics.go"]) is False


def test_has_source_code_change_false_for_docs():
    assert _has_source_code_change(["docs/source/conf.py", "docs/requirements.txt"]) is False


def test_has_source_code_change_true_when_mixed_with_noise():
    # Un bump de dependencias que ADEMAS toca codigo real de la app se
    # queda -- probablemente el bump vino empaquetado con un fix real.
    assert _has_source_code_change(["go.mod", "go.sum", "server/api.go"]) is True


def test_guess_functions_touched_extracts_real_function_context():
    # Formato real que imprime `git show` cuando puede inferir el
    # contexto del hunk (@@ -10,7 +10,9 @@ <contexto>).
    diff = (
        "@@ -52,7 +52,9 @@ jsg::Ref<Fetcher> Fetcher::deserialize(jsg::Lock& js,\n"
        "+  // nueva linea\n"
        "@@ -100,3 +102,3 @@ \n"
        "+  otra linea\n"
    )
    functions = _guess_functions_touched(diff)
    assert functions == ["jsg::Ref<Fetcher> Fetcher::deserialize(jsg::Lock& js,"]
    # El segundo hunk no tenia contexto real (git no pudo inferirlo) --
    # nunca se inventa un nombre, se descarta ese hunk.


def test_js_engine_lifecycle_marker_detects_real_workerd_signatures():
    # Firmas REALES extraidas de los 3 diffs de cloudflare/workerd
    # investigados a mano (ver harness_gen/README.md, "Intento real:
    # candidato de workerd") -- los 3 resultaron ser bugs de ciclo de
    # vida de V8/JS, no fuzzeables con libFuzzer.
    assert _looks_js_engine_lifecycle_bound([
        "jsg::Ref<Fetcher> Fetcher::deserialize(jsg::Lock& js,"
    ])
    assert _looks_js_engine_lifecycle_bound([
        "void ZlibUtil::CompressionStream<CompressionContext>::emitError("
    ]) is False  # esta firma puntual no menciona jsg::/v8:: -- confirma que no es un filtro perfecto
    assert _looks_js_engine_lifecycle_bound([
        "class Function<Ret(Args...)> {",
        "Ret operator()(jsg::Lock& jsl, Args... args) {",
    ])


def test_js_engine_lifecycle_marker_does_not_flag_real_fabric_private_chaincode_signature():
    # Firma REAL de unmarshal_values (fabric-private-chaincode) -- el
    # candidato que SI resulto ser la forma correcta de bug (parseo de
    # bytes no confiables), sin jsg::/v8:: en ningun lado.
    assert _looks_js_engine_lifecycle_bound([
        "int unmarshal_values("
    ]) is False
