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

## Experimento real #2, corregido: A/B contra `fpc_unmarshal_values` (2026-08-16)

El primer experimento (contra `zbxjson`, más abajo) tenía dos problemas
metodológicos reales, encontrados corriendo esto de nuevo con más
cuidado:

1. **Confound de tiempo de carga**: comparar por tiempo de pared fijo
   (`-max_total_time`) le daba ventaja injusta al control, porque
   cargar/deduplicar 204 archivos de semilla al arrancar le come
   presupuesto real de tiempo a la campaña de tratamiento. **Corregido**
   comparando por EJECUCIONES exactas (`-runs=500000` para ambos
   grupos), eliminando el confound.
2. **Bug real en `generate_seeds()`**: la primera versión agregaba cada
   mutante generado al pool que `interleave` usa para la MUTACIÓN
   SIGUIENTE -- con `loop(interleave,3)` compuesto 200 veces, el
   tamaño de los documentos crecía sin control (un input real llegó a
   ~495KB desde seeds de <100 bytes, la campaña se volvió
   impracticable, `exec/s` cayó de varios miles a ~460). **Corregido**:
   `interleave` mezcla siempre contra los seeds ORIGINALES, nunca
   contra mutantes ya generados -- tamaño acotado confirmado en vivo
   (máximo real 371 bytes con el fix, vs 495KB antes). Ver
   `test_seed_from_operator_tree.py`.

**Metodología, ronda 2**: mismos 4 seeds base (ahora formato real de
`unmarshal_values`: `[{"key":"...", "value":"<base64>"}]`), 200
mutantes por grupo de tratamiento, **5 repeticiones con distinta
semilla de RNG** (no una sola corrida), **500,000 ejecuciones exactas**
por corrida (`-runs=500000`, no tiempo de pared), 1 worker,
`ASAN_OPTIONS=detect_leaks=0` (este target tiene un memory leak YA
documentado y conocido -- `findings/2026-08-15_..._leak.md` -- que si
no se desactiva aborta la campaña en los primeros cientos de
ejecuciones sin llegar a explorar nada más, igual que en su config real
de `orchestrator/targets.json`).

**Resultado real, promedio de 5 corridas**:

| métrica | control (4 seeds crudos) | tratamiento (204 seeds) |
|---|---|---|
| `cov` (cobertura de código) | 369.2 | 369.6 |
| `ft` (features, métrica más fina de libFuzzer) | 1552.4 | 1577.8 |

`cov` prácticamente empatado (+0.1%). `ft` con ventaja modesta para el
tratamiento (+1.6% en promedio, gana en 3 de 5 semillas de RNG) --
señal real pero chica, no un resultado contundente. Ningún crash NUEVO
en ninguna de las 10 corridas (más allá del leak ya conocido,
desactivado a propósito).

**Conclusión honesta, ronda 2**: con la metodología corregida (iso-
ejecuciones, 5 repeticiones, target con más profundidad real de
parseo), la mutación estructural muestra una ventaja **pequeña y
consistente en `ft`, pero no en `cov`** -- ni un resultado nulo ni un
"ganador" claro. Es una señal real de que sembrar con documentos
estructuralmente diversos ayuda a encontrar más *feature counters*
internos (probablemente combinaciones de campos/valores que el havoc
puro tarda más en descubrir por azar), pero no alcanza para decir que
encuentra código nuevo más rápido en esta ventana de ejecuciones. Un
efecto real pero modesto, medido con rigor -- no una demostración
contundente de la idea, tampoco su descarte.

## Experimento real #3, misma metodología corregida: A/B contra `zabbix_zbxjson_open` (2026-08-16)

Pregunta real que quedó abierta después del experimento #2: ¿el efecto
chico y positivo en `ft` generaliza a otro parser JSON, o es específico
de `fpc_unmarshal_values`? Misma metodología rigurosa (5 repeticiones,
`-runs=500000` exactas, seeds realistas del protocolo trapper de
Zabbix) aplicada de nuevo contra `zabbix_zbxjson_open` -- el mismo
target del experimento #1, pero esta vez sin los confounds de tiempo de
pared ni el bug de crecimiento del generador.

**Resultado real, promedio de 5 corridas**:

| métrica | control (4 seeds crudos) | tratamiento (204 seeds) |
|---|---|---|
| `cov` | 217.6 | 217.2 (**-0.18%**) |
| `ft` | 880.0 | 872.0 (**-0.91%**) |

Acá el tratamiento **NO gana** -- prácticamente empatado en `cov`, y
levemente NEGATIVO en `ft` (gana en solo 2 de 5 semillas en ambas
métricas). El efecto positivo visto en `fpc_unmarshal_values` **no
generaliza** a este target.

**Conclusión honesta, comparando los dos targets con la misma
metodología rigurosa**: el efecto de la mutación estructural no es
universal -- depende del target. Hipótesis real, no comprobada, que
surge de comparar ambos resultados: `zabbix_zbxjson_open` ya satura
cobertura muy rápido con seeds realistas simples (el experimento #1
mostró que 4 seeds crudos ya alcanzan `cov≈217` de un máximo cercano a
`≈222` visto en corridas más largas -- casi todo el espacio explorable
en esta ventana de ejecuciones ya está cubierto por el motor de
cobertura de libFuzzer solo, sin importar qué tan diversas sean las
semillas iniciales). `fpc_unmarshal_values` tiene más profundidad real
de parseo (array anidado, decodificación base64, inserción en
`std::map`) -- ahí sí queda margen real donde sembrar con documentos
estructuralmente diversos (booleanos invertidos, campos transpuestos)
ayuda a alcanzar combinaciones de estado que el havoc de bytes puro
tarda más en encontrar por azar. Esta hipótesis explicaría ambos
resultados de forma consistente, pero necesitaría un tercer target con
profundidad intermedia para confirmarse -- no se probó acá.

## Experimento real #4, tercer target de profundidad intermedia: A/B contra `fpc_parson_json_parse_string` (2026-08-16)

Prueba directa de la hipótesis del experimento #3: `json_parse_string`
(parson, harness de `fpc_parson`) comparte el MISMO formato de entrada
que `unmarshal_values` (array de `{"key":..., "value":...}`) y camina
el array leyendo 2 campos string por objeto -- pero sin el paso de
decodificación base64 ni inserción en `std::map` que sí tiene
`unmarshal_values`. Profundidad real intermedia entre `zbxjson`
(solo abre/valida el JSON, no camina nada) y `unmarshal_values`
(camina + decodifica + inserta). Misma metodología rigurosa exacta (5
repeticiones, `-runs=500000`, mismo formato de seeds).

**Resultado real, promedio de 5 corridas**:

| métrica | control (4 seeds crudos) | tratamiento (204 seeds) |
|---|---|---|
| `cov` | 230.6 | 231.2 (**+0.26%**, gana 3/5) |
| `ft` | 1252.4 | 1258.6 (**+0.50%**, gana 4/5) |

## Experimento real #5, segunda dimensión -- ANIDAMIENTO del input, no profundidad de procesamiento (2026-08-16)

Los experimentos #1-#4 variaron cuánto CÓDIGO procesa cada campo del
JSON (profundidad de *procesamiento*). Esta es una dimensión distinta:
qué tan anidada está la ESTRUCTURA del input en sí (profundidad de
*anidamiento*) -- un array de objetos con 6 niveles de anidamiento
adentro es un input "más profundo" aunque el harness solo lea 2 campos
string de él, igual que los anteriores.

**No hizo falta un harness nuevo**: `json_parse_string()` (parson) es
un parser recursivo real -- parsea CUALQUIER nivel de anidamiento antes
de que el harness llegue a mirar nada, así que anidar la estructura
real ejercita más recursión real del parser (`parse_object`/
`parse_array`/`parse_value` llamándose entre sí), sin importar qué
haga el harness con el resultado. Mismo binario
(`build/fpc_parson/fuzz_parson`) que el experimento #4 -- se reusó
directo.

**Seeds reales, 4 documentos** (mismo formato `{"key":..., "value":...}`
que el harness necesita para su chequeo de tipo, con un campo extra
`"meta"`/`"extra"`/`"cfg"`/`"chain"` anidado 4-6 niveles que el harness
ignora pero el parser sí tiene que atravesar completo -- ej.
`{"key":"z","value":"3","chain":{"n1":{"n2":{"n3":{"n4":{"n5":"bottom"}}}}}}`).
Misma metodología rigurosa exacta (5 repeticiones, `-runs=500000`).

**Resultado real, promedio de 5 corridas**:

| métrica | control (4 seeds anidados crudos) | tratamiento (204 seeds) |
|---|---|---|
| `cov` | 231.2 | 231.4 (**+0.09%**, gana 2/5) |
| `ft` | 1203.2 | 1272.8 (**+5.78%**, gana **5/5**) |

**El efecto más grande y más consistente de los 5 experimentos** --
`ft` sube casi 6%, y el tratamiento gana TODAS las repeticiones (a
diferencia de cualquier otro experimento, donde siempre hubo al menos
una semilla de RNG donde perdía). Verificado que no es un artefacto de
crashes/leaks silenciados: se re-corrieron las 10 corridas buscando
explícitamente `ERROR`/`SUMMARY`/`Sanitizer`/`crash`/`leak-` en la
salida completa -- ninguna anomalía real, el efecto es puramente de
cobertura/exploración.

## Los 5 experimentos juntos -- dos dimensiones reales, ambas apuntan en la misma dirección

| experimento | dimensión variada | Δ `cov` | Δ `ft` |
|---|---|---|---|
| `zabbix_zbxjson_open` | procesamiento mínimo, sin anidamiento | -0.18% | -0.91% |
| `fpc_parson` (flat) | procesamiento intermedio, sin anidamiento | +0.26% | +0.50% |
| `fpc_unmarshal_values` | procesamiento máximo (base64+map), sin anidamiento | +0.11% | +1.64% |
| `fpc_parson` (anidado) | procesamiento intermedio, **anidamiento real 4-6 niveles** | +0.09% | **+5.78%** |

Dos hallazgos reales, no uno: (1) más CÓDIGO procesando cada campo
ayuda un poco (patrón monótono ya documentado en los primeros 3), y
(2) el ANIDAMIENTO estructural del input ayuda bastante más -- el
efecto más grande de los 5 experimentos, y el único con victoria
unánime en las 5 repeticiones. Consistente con el mecanismo propuesto,
pero ahora con una segunda variable real: cuanta más ESTRUCTURA tiene
el árbol JSON (no solo cuánto código lo procesa), más terreno real
donde el havoc de bytes puro tarda en tropezar por azar con la
combinación correcta, y donde transponer/invertir semánticamente
valores YA anidados encuentra estados nuevos más rápido.

**Cautela honesta que sigue aplicando**: son 5 corridas (4 targets/
variantes distintas), efectos que van de -1% a +6%, sin significancia
estadística formal calculada (solo promedios de 5 repeticiones por
condición) -- señal real y patrón consistente en dos dimensiones
independientes, no una ley demostrada. El anidamiento parece ser la
dimensión que más importa de las dos probadas hasta ahora.

## Experimento real #1 (metodología con confounds, ver arriba): A/B contra `zabbix_zbxjson_open` (2026-08-16)

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
  siendo un experimento standalone, no una feature integrada. Con el
  experimento #5 (+5.78% en `ft`, victoria unánime 5/5), hay un caso
  real -- no solo incipiente -- para ofrecerlo como opción de seeding
  específica para targets que parsean JSON con anidamiento real
  (candidatos reales del propio registro:
  `fabric_config_newenvelope`, `fabric_gateway_parsetransactionenvelope`,
  cualquier target futuro que parsee protobuf/JSON anidado). Sigue sin
  alcanzar para integrarlo como default GENERAL del scheduler (el
  experimento #1/#3 con `zbxjson` mostró efecto nulo/negativo para
  targets sin anidamiento real) -- la señal apunta a una mejora
  CONDICIONAL, no universal.
- **Dos hipótesis reales, con soporte empírico de 5 corridas, no una
  ley demostrada**: (1) más código procesando cada campo ayuda un poco
  (patrón monótono, experimentos #1-#4); (2) más anidamiento
  ESTRUCTURAL del input ayuda bastante más (experimento #5, el efecto
  más grande y consistente de los cinco). Sin significancia
  estadística formal calculada. Si se sigue esto, el siguiente paso
  real sería aislar las dos variables (probar anidamiento profundo
  SIN aumentar el procesamiento, y viceversa, en el mismo target) para
  saber si son efectos independientes o el mismo fenómeno visto desde
  dos ángulos.
- Solo cubre documentos JSON -- la notación (`transpose`,
  `semantic_inverse`) podría generalizarse a otros formatos
  estructurados (protobuf, el AST de un lenguaje), no se intentó acá.
