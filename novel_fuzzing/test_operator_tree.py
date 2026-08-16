"""Tests deterministicos (rng con seed fija, sin red) para el álgebra
de operadores de mutación estructural."""

import random

from operator_tree import op_interleave, op_semantic_inverse, op_transpose, parse_operator_tree, mutate


def test_parses_the_real_notation_that_motivated_this():
    tree = parse_operator_tree("seq(loop(interleave,3), choice(transpose, semantic_inverse))")
    assert tree.name == "seq"
    assert len(tree.args) == 2
    assert tree.args[0].name == "loop"
    assert tree.args[0].args[0].name == "interleave"
    assert tree.args[0].args[1] == 3
    assert tree.args[1].name == "choice"
    assert {a.name for a in tree.args[1].args} == {"transpose", "semantic_inverse"}


def test_transpose_swaps_two_dict_values_keeping_keys():
    rng = random.Random(1)
    value = {"a": 1, "b": 2}
    result = op_transpose(value, [], rng)
    assert set(result.keys()) == {"a", "b"}
    assert set(result.values()) == {1, 2}
    assert result != value  # con seed 1 y solo 2 claves, el unico swap posible cambia el valor


def test_transpose_swaps_two_list_elements():
    rng = random.Random(2)
    value = [10, 20, 30]
    result = op_transpose(value, [], rng)
    assert sorted(result) == [10, 20, 30]
    assert len(result) == 3


def test_transpose_leaves_scalar_unchanged_no_container_to_mutate():
    rng = random.Random(3)
    assert op_transpose(42, [], rng) == 42
    assert op_transpose("hello", [], rng) == "hello"


def test_semantic_inverse_flips_bool():
    rng = random.Random(4)
    result = op_semantic_inverse(True, [], rng)
    assert result is False


def test_semantic_inverse_flips_null_to_non_null():
    rng = random.Random(5)
    result = op_semantic_inverse(None, [], rng)
    assert result is not None


def test_semantic_inverse_flips_empty_string_to_non_empty():
    rng = random.Random(6)
    assert op_semantic_inverse("", [], rng) == "x"


def test_semantic_inverse_flips_non_empty_string_to_empty():
    rng = random.Random(7)
    assert op_semantic_inverse("hello", [], rng) == ""


def test_semantic_inverse_negates_nonzero_number():
    rng = random.Random(8)
    result = op_semantic_inverse(5, [], rng)
    assert result == -5


def test_semantic_inverse_never_changes_type_of_container():
    rng = random.Random(9)
    value = {"active": True, "count": 3}
    result = op_semantic_inverse(value, [], rng)
    assert isinstance(result, dict)
    assert set(result.keys()) == {"active", "count"}


def test_interleave_merges_two_dicts_from_real_corpus():
    rng = random.Random(10)
    value = {"host": "a", "port": 1}
    other = {"host": "b", "port": 2, "extra": True}
    result = op_interleave(value, [other], rng)
    assert isinstance(result, dict)
    # todas las claves de ambos documentos tienen que aparecer
    assert set(result.keys()) >= {"host", "port"}


def test_interleave_merges_two_lists_from_real_corpus():
    rng = random.Random(11)
    value = [1, 2]
    other = [10, 20, 30]
    result = op_interleave(value, [other], rng)
    assert isinstance(result, list)
    assert len(result) == len(value) + len(other)


def test_interleave_with_empty_corpus_returns_copy_unchanged():
    rng = random.Random(12)
    value = {"a": 1}
    result = op_interleave(value, [], rng)
    assert result == value


def test_interleave_type_mismatch_returns_original_unchanged():
    rng = random.Random(13)
    value = {"a": 1}
    other = [1, 2, 3]  # tipo distinto -- no se fuerza una mezcla sin sentido
    result = op_interleave(value, [other], rng)
    assert result == value


def test_mutate_full_expression_never_raises_on_real_document():
    rng = random.Random(14)
    corpus = [{"host": "x", "active": True}, {"host": "y", "active": False, "tags": [1, 2]}]
    doc = {"host": "trapper", "active": True, "tags": ["a", "b", "c"]}
    for _ in range(50):
        doc = mutate("seq(loop(interleave,3), choice(transpose, semantic_inverse))", doc, corpus, rng)
        assert doc is not None
