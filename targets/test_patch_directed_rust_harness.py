"""Tests de la parte determinística (extracción/priorización de
candidatos Rust) -- sin red, sin Ollama.

El caso base de estos tests es REAL, no inventado: el commit
361d245447 de filecoin-project/bellperson ("fix: read_many: return an
error instead of a panic", el propio mensaje dice "proof_bytes is
untrusted, user input") -- git ancló el contexto del hunk en
"impl<E: Engine> Proof<E> {" en vez de en la firma real
`pub fn read_many(proof_bytes: &[u8], num_proofs: usize) -> ...`, que
solo aparece en el cuerpo del diff. Ver
targets/README.md y harness_gen/README.md para el resultado completo
en vivo (find_and_generate)."""

from patch_directed_rust_harness import _extract_rust_candidates


def test_extracts_function_missed_by_hunk_context_from_diff_body():
    # Caso real: functions_touched_guess solo tiene el contexto de
    # impl (lo que git eligió), la firma real esta en diff_excerpt.
    candidate = {
        "files_changed": ["src/groth16/proof.rs"],
        "functions_touched_guess": ["impl<E: Engine> Proof<E> {"],
        "diff_excerpt": (
            "@@ -84,7 +84,16 @@ impl<E: Engine> Proof<E> {\n"
            "     }\n\n"
            "     pub fn read_many(proof_bytes: &[u8], num_proofs: usize) -> io::Result<Vec<Self>> {\n"
            "-        debug_assert_eq!(proof_bytes.len(), num_proofs * Self::size());\n"
        ),
    }
    results = _extract_rust_candidates(candidate)
    names = {r["function_name"] for r in results}
    assert "read_many" in names


def test_prioritizes_byte_slice_taking_function_over_others():
    candidate = {
        "files_changed": ["src/lib.rs"],
        "functions_touched_guess": [],
        "diff_excerpt": (
            "pub fn ready(&self) -> bool {\n"
            "pub fn parse(data: &[u8]) -> Result<Self, Error> {\n"
        ),
    }
    results = _extract_rust_candidates(candidate)
    names_in_order = [r["function_name"] for r in results]
    assert names_in_order.index("parse") < names_in_order.index("ready")


def test_ignores_test_files():
    candidate = {
        "files_changed": ["tests/integration_test.rs"],
        "functions_touched_guess": ["pub fn parse_test_input(data: &[u8]) {"],
        "diff_excerpt": "pub fn parse_test_input(data: &[u8]) {",
    }
    assert _extract_rust_candidates(candidate) == []


def test_deduplicates_same_function_name():
    candidate = {
        "files_changed": ["src/lib.rs"],
        "functions_touched_guess": ["pub fn parse(data: &[u8]) -> Result<Self, Error> {"],
        "diff_excerpt": "pub fn parse(data: &[u8]) -> Result<Self, Error> {",
    }
    results = _extract_rust_candidates(candidate)
    names = [r["function_name"] for r in results]
    assert names.count("parse") == 1
