#!/usr/bin/env python3
"""CLI real para generar semillas de corpus a partir del árbol de
operadores (ver operator_tree.py) -- toma documentos JSON semilla
reales, aplica la expresión N veces (cruzando cada mutante con los
demás documentos ya generados, para que `interleave` tenga variedad
real de donde mezclar, no solo los seeds originales), y escribe cada
resultado como un archivo de corpus nuevo (JSON serializado a bytes,
el mismo formato que consume LLVMFuzzerTestOneInput).

Uso:
  venv/bin/python3 novel_fuzzing/seed_from_operator_tree.py \\
    --seed-json seeds.json \\
    --expr "seq(loop(interleave,3), choice(transpose, semantic_inverse))" \\
    --count 200 --out-dir /tmp/mutant_corpus --seed-rng 42
"""

import argparse
import json
import os
import random
import sys

from operator_tree import mutate


def generate_seeds(seed_docs, expr: str, count: int, rng: random.Random):
    """Devuelve `count` documentos JSON nuevos -- cada uno parte de un
    seed real elegido al azar, y usa el pool ACUMULADO (seeds
    originales + mutantes ya generados en esta misma corrida) como
    `corpus_real` para `interleave`, asi la mezcla tiene variedad real
    despues de las primeras iteraciones."""
    pool = list(seed_docs)
    generated = []
    for _ in range(count):
        base = rng.choice(seed_docs)
        mutant = mutate(expr, base, pool, rng)
        generated.append(mutant)
        pool.append(mutant)
    return generated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed-json", required=True, help="archivo con una lista JSON de documentos semilla reales")
    parser.add_argument("--expr", required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--seed-rng", type=int, default=0)
    args = parser.parse_args()

    with open(args.seed_json, "r", encoding="utf-8") as fh:
        seed_docs = json.load(fh)
    if not isinstance(seed_docs, list) or not seed_docs:
        print("--seed-json tiene que ser una lista JSON no vacia de documentos semilla", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)
    rng = random.Random(args.seed_rng)
    mutants = generate_seeds(seed_docs, args.expr, args.count, rng)

    for i, doc in enumerate(mutants):
        out_path = os.path.join(args.out_dir, f"novel_fuzzing_{i:05d}.json")
        with open(out_path, "wb") as fh:
            fh.write(json.dumps(doc).encode("utf-8"))

    print(f"{len(mutants)} semillas reales escritas en {args.out_dir}")


if __name__ == "__main__":
    main()
