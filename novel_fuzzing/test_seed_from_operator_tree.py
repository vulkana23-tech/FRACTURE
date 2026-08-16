"""Tests deterministicos (seed fija, sin red)."""

import json
import random

from seed_from_operator_tree import generate_seeds


def test_generate_seeds_returns_requested_count():
    seeds = [{"key": "a", "value": "aGVsbG8="}, [{"key": "b", "value": ""}]]
    rng = random.Random(1)
    result = generate_seeds(seeds, "transpose", 10, rng)
    assert len(result) == 10


def test_generate_seeds_size_stays_bounded_even_with_many_iterations():
    # Caso real encontrado contra fpc_unmarshal_values: la version
    # anterior de generate_seeds agregaba cada mutante al pool de
    # interleave, y con loop(interleave,3) compuesto 200 veces el
    # tamano del documento crecia sin control (un input real llego a
    # ~495KB). interleave() SOLO contra los seeds originales evita el
    # crecimiento compuesto -- el tamano serializado de CUALQUIER
    # mutante no puede superar la suma de los seeds originales.
    seeds = [
        [{"key": "a", "value": "aGVsbG8="}],
        [{"key": "b", "value": ""}, {"key": "c", "value": "d29ybGQ="}],
        [],
        [{"key": "x", "value": "YQ=="}, {"key": "y", "value": "Yg=="}, {"key": "z", "value": "Yw=="}],
    ]
    max_seed_size = max(len(json.dumps(s)) for s in seeds)
    rng = random.Random(42)
    result = generate_seeds(seeds, "seq(loop(interleave,3), choice(transpose, semantic_inverse))", 200, rng)
    sizes = [len(json.dumps(doc)) for doc in result]
    # interleave de dos listas concatena -- el maximo real posible es
    # la suma de los dos seeds mas grandes, con margen para las 3
    # iteraciones del loop -- muy por debajo del crecimiento
    # exponencial que causaba el bug real (495KB desde seeds de <100
    # bytes).
    assert max(sizes) < max_seed_size * 20
