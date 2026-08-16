"""Tests de la parte determinística (extracción/priorización de
candidatos Java) -- sin red, sin Ollama.

Los casos base son REALES: las firmas exactas de
`ClientIdentity.parseAttributes` y `JSONTransactionSerializer.fromBuffer`
(fabric-chaincode-java), los dos métodos que ya se fuzzearon de verdad
en este proyecto -- ver findings/2026-08-16_fabric-chaincode-java_*.md."""

from patch_directed_jvm_harness import _class_fqn_from_file, _extract_jvm_candidates


def test_class_fqn_from_standard_maven_gradle_layout():
    path = "fabric-chaincode-shim/src/main/java/org/hyperledger/fabric/contract/ClientIdentity.java"
    assert _class_fqn_from_file(path) == "org.hyperledger.fabric.contract.ClientIdentity"


def test_class_fqn_returns_none_for_non_standard_layout():
    assert _class_fqn_from_file("some/random/path.java") is None


def test_extracts_public_method_missed_by_hunk_context_from_diff_body():
    # Caso real: functions_touched_guess solo tiene el contexto de
    # clase (lo que git eligió), la firma real de fromBuffer esta en
    # diff_excerpt.
    candidate = {
        "files_changed": [
            "fabric-chaincode-shim/src/main/java/org/hyperledger/fabric/contract/execution/JSONTransactionSerializer.java"
        ],
        "functions_touched_guess": [
            "public class JSONTransactionSerializer implements SerializerInterface {"
        ],
        "diff_excerpt": (
            "@@ -150,3 +150,9 @@ public class JSONTransactionSerializer implements SerializerInterface {\n"
            "    public Object fromBuffer(final byte[] buffer, final TypeSchema ts) {\n"
            "        return convert(new String(buffer), ts);\n"
            "    }\n"
        ),
    }
    results = _extract_jvm_candidates(candidate)
    names = {r["function_name"] for r in results}
    assert "fromBuffer" in names
    assert all(r["class_fqn"] == "org.hyperledger.fabric.contract.execution.JSONTransactionSerializer" for r in results)


def test_prioritizes_byte_array_taking_method_over_others():
    candidate = {
        "files_changed": ["shim/src/main/java/org/x/Y.java"],
        "functions_touched_guess": [],
        "diff_excerpt": (
            "public String getId() {\n"
            "private Map<String, String> parseAttributes(final byte[] extensionValue) throws IOException {\n"
        ),
    }
    results = _extract_jvm_candidates(candidate)
    names_in_order = [r["function_name"] for r in results]
    assert names_in_order.index("parseAttributes") < names_in_order.index("getId")


def test_ignores_test_files():
    candidate = {
        "files_changed": ["shim/src/test/java/org/x/YTest.java"],
        "functions_touched_guess": [],
        "diff_excerpt": "public void testParse(byte[] data) {",
    }
    assert _extract_jvm_candidates(candidate) == []


def test_deduplicates_same_method_name():
    candidate = {
        "files_changed": ["shim/src/main/java/org/x/Y.java"],
        "functions_touched_guess": [
            "public Object fromBuffer(final byte[] buffer, final TypeSchema ts) {",
        ],
        "diff_excerpt": "public Object fromBuffer(final byte[] buffer, final TypeSchema ts) {",
    }
    results = _extract_jvm_candidates(candidate)
    names = [r["function_name"] for r in results]
    assert names.count("fromBuffer") == 1
