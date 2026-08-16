# novel_fuzzing/

Prototipo real de una idea que trajo el usuario: un álgebra de
operadores componibles para describir estrategias de mutación
ESTRUCTURADA (no a nivel de bytes), evaluada literalmente desde la
notación real que la motivó:

```
seq(loop(interleave,3), choice(transpose, semantic_inverse))
```

## Qué es y qué NO es

Los 4 motores de fuzzing que ya tiene FRACTURE (Rust/C via libFuzzer,
JVM via Jazzer, Go nativo) mutan **bytes crudos**, guiados por
cobertura -- sin ningún modelo de la estructura del input. Esta idea es
conceptualmente distinta: opera sobre un documento JSON ya **parseado**
(un árbol), no sobre su representación en bytes.

Esto NO reemplaza el motor de mutación de ninguno de los 4 engines
(reescribir el mutator interno de cada uno -- `LLVMFuzzerCustomMutator`
en C, engines separados en Rust/Go/JVM -- es reingeniería real de 4
motores distintos, alto riesgo/esfuerzo). En cambio, genera semillas de
corpus estructuralmente interesantes que se inyectan ANTES de una
campaña real -- libFuzzer sigue siendo el motor de ejecución/cobertura.

## `operator_tree.py`

Implementa la notación real como un mini-DSL **ejecutable** (parser
recursivo-descendente chico, no una traducción a mano de la idea):

- `transpose` -- intercambia la posición de dos elementos hermanos
  (dos valores de un dict, o dos elementos de una lista). Nunca inventa
  un valor nuevo, solo reordena/cruza los que ya están.
- `semantic_inverse` -- encuentra un valor escalar alcanzable (bool,
  null, número, string) y le invierte el significado lógico
  (`true↔false`, `null↔no-null`, vacío↔no-vacío, `n↔-n`) preservando
  el TIPO. Apunta a un bug real de diseño: código que asume que un
  campo "siempre" es true/no-vacío/positivo sin validar el caso
  contrario.
- `interleave` -- mezcla el documento con otro documento real del
  corpus (si ambos son dicts, une claves alternando la fuente; si son
  listas, intercala elementos). Si los tipos no combinan, no fuerza
  nada.
- `seq`/`loop`/`choice` -- combinadores reales: secuencia, repetición
  N veces, elección aleatoria entre alternativas.

15 tests deterministicos (seed fija, sin red) en `test_operator_tree.py`.

## `seed_from_operator_tree.py`

CLI que toma documentos JSON semilla reales, evalúa la expresión N
veces (cruzando cada mutante con los ya generados, para que
`interleave` tenga variedad real después de las primeras iteraciones),
y escribe cada resultado como un archivo de corpus.

## Experimento real: A/B contra `zabbix_zbxjson_open` (2026-08-16)

**Metodología**: 4 documentos semilla realistas (formato real del
protocolo trapper de Zabbix: `{"request":"sender data","data":[...]}`
y variantes). Grupo control: solo esos 4 seeds crudos. Grupo
tratamiento: los mismos 4 seeds + 200 mutantes generados con
`seq(loop(interleave,3), choice(transpose, semantic_inverse))`.
Campaña real de 20s, 1 worker, mismo binario
(`build/zabbix_zbxjson/fuzz_zbxjson`), sin tocar el corpus real de
producción (directorios temporales aparte).

**Resultado real, HONESTO (no un "ganador" claro)**:

| | INITED (arranque) | Final (20s) | ejecuciones reales |
|---|---|---|---|
| Control (4 seeds crudos) | cov 217, ft 991 | cov 222, ft 1035, corp 410 | ~3.1M |
| Tratamiento (204 seeds) | cov 63, ft 215 | cov 224, ft 1018, corp 401 | ~2.0M |

Cobertura final prácticamente empatada (224 vs 222), *features*
levemente menor en el tratamiento (1018 vs 1035), y **~35% menos
ejecuciones reales** en el mismo tiempo real -- el costo real de cargar
y deduplicar 204 archivos de semilla al arrancar le come presupuesto de
tiempo real a la campaña, un confound real que esta corrida de una sola
vez no aísla. Interesante también: el arranque (`INITED`) del control
ya mostraba cov 217 con solo 4 archivos -- muy cerca del máximo
alcanzado en toda la campaña (222), sugiriendo que esta función
específica satura cobertura rápido con seeds realistas simples, dejando
poco margen real donde una técnica de mutación más sofisticada pueda
mostrar diferencia en una ventana de 20s.

**Conclusión honesta**: esta corrida única y corta **no muestra una
ventaja clara** de la mutación estructural sobre el havoc de bytes
puro de libFuzzer para esta función específica -- ni la contradice del
todo (cov final levemente mayor). No alcanza para una conclusión
firme. Un experimento riguroso necesitaría: (1) igualar por
EJECUCIONES reales en vez de tiempo de pared (para que el costo de
carga inicial no contamine la comparación), (2) repetir con distintas
semillas de RNG y promediar (una sola corrida no tiene significancia
estadística), y (3) probarlo contra un target con más profundidad de
parseo real donde el parseo de bytes puro tenga más dificultad para
llegar a estados estructuralmente interesantes (candidato real:
`fpc_unmarshal_values`, que ya tiene un memory leak real documentado
encontrado por parseo profundo de JSON anidado).

## Uso

```
venv/bin/python3 novel_fuzzing/seed_from_operator_tree.py \
  --seed-json seeds.json \
  --expr "seq(loop(interleave,3), choice(transpose, semantic_inverse))" \
  --count 200 --out-dir /tmp/mutant_corpus

venv/bin/python3 -m pytest novel_fuzzing/ -v
```

## Lo que falta (honesto)

- No está conectado a ningún target del daemon 24/7 todavía -- sigue
  siendo un experimento standalone, no una feature integrada.
- El experimento A/B de arriba es una sola corrida, no concluyente --
  ver "Conclusión honesta".
- Solo cubre documentos JSON -- la notación (`transpose`,
  `semantic_inverse`) podría generalizarse a otros formatos
  estructurados (protobuf, el AST de un lenguaje), no se intentó acá.
