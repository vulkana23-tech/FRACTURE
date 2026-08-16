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

**Cautela honesta que aplicaba en ese momento**: 5 corridas, efectos de
-1% a +6%, señal real pero condicional -- ver experimento #6 abajo,
que cambia esta conclusión.

## Experimento real #6, aislando las dos variables: anidamiento + procesamiento profundo JUNTOS (2026-08-16)

Pregunta directa que quedó abierta: si el anidamiento solo (experimento
#5, `fpc_parson`) da +5.78% en `ft`, y el procesamiento profundo solo
(experimento #2, `fpc_unmarshal_values` con seeds PLANOS) da +1.64%,
¿qué pasa si las DOS condiciones están presentes en el mismo target?
¿Se suman (~7%), o pasa algo distinto?

**Metodología**: mismos seeds anidados del experimento #5 (4-6 niveles,
campo extra que el harness ignora pero el parser atraviesa completo),
adaptados al formato real de `unmarshal_values` (`"value"` como base64
válido, ya que esta función SÍ decodifica ese campo). Mismo binario
(`build/fpc_unmarshal_values/fuzz_unmarshal_values`, con
`ASAN_OPTIONS=detect_leaks=0`, mismo motivo real que el experimento
#2). Misma metodología rigurosa exacta (5 repeticiones, `-runs=500000`).

**Resultado real, promedio de 5 corridas**:

| métrica | control (4 seeds anidados) | tratamiento (204 seeds) |
|---|---|---|
| `cov` | 361.4 | 368.4 (**+1.94%**, gana **5/5**) |
| `ft` | 1296.0 | 1587.8 (**+22.52%**, gana **5/5**) |

**El efecto más grande de los 6 experimentos, por lejos** -- y la
primera vez que `cov` (no solo `ft`) se mueve de forma consistente y
notable. Verificado que no es un artefacto de crashes/leaks
silenciados, mismo chequeo explícito que el experimento #5, ninguna
anomalía real encontrada.

**El hallazgo real, no obvio**: el efecto NO es aditivo, es
SUPERLINEAL. Anidamiento solo: +5.78% en `ft`. Procesamiento profundo
solo: +1.64% en `ft`. Sumados ingenuamente: ~7.4%. Real, juntos:
**+22.52%** -- más de 3 veces la suma ingenua de los dos efectos por
separado. Interpretación mecanística razonable (no probada
rigurosamente, pero coherente con los 6 resultados): cuando el input
tiene TANTO anidamiento estructural COMO procesamiento profundo por
campo, el espacio de estados "interesantes" del programa crece de
forma combinatoria (una combinación específica de valores anidados
QUE ADEMÁS decodifican a un base64 válido y se insertan en el mapa) --
un espacio que el havoc de bytes puro tiene que descubrir por fuerza
bruta en dos dimensiones a la vez, mientras que sembrar con documentos
ya estructuralmente diversos (transpuestos/invertidos) recorta ambas
dimensiones de una vez.

## Los 6 experimentos juntos -- tabla final

| target / variante | procesamiento | anidamiento | Δ `cov` | Δ `ft` |
|---|---|---|---|---|
| `zabbix_zbxjson_open` | ninguno | no | -0.18% | -0.91% |
| `fpc_parson` (plano) | superficial | no | +0.26% | +0.50% |
| `fpc_unmarshal_values` (plano) | profundo (base64+map) | no | +0.11% | +1.64% |
| `fpc_parson` (anidado) | superficial | **sí** | +0.09% | +5.78% |
| `fpc_unmarshal_values` (anidado) | profundo | **sí** | **+1.94%** | **+22.52%** |

**Conclusión real, con más confianza que en cualquier punto anterior de
esta serie**: la mutación estructural (`novel_fuzzing`) SÍ tiene un
caso real -- no solo especulativo -- para targets que combinan parseo
de estructuras anidadas CON procesamiento real por campo (el patrón
más común en parsers de protocolos reales: JSON/protobuf con objetos
anidados que además se validan/transforman/insertan en estructuras).
Sigue sin ser una mejora universal (`zbxjson`, sin ninguna de las dos
condiciones, sigue mostrando efecto nulo/negativo) -- la recomendación
honesta es ofrecerla como opción de seeding CONDICIONAL, activada para
targets que el investigador ya sabe que parsean estructuras anidadas
con lógica real detrás, no como default del scheduler.

**Cautela honesta que aplicaba en ese momento**: 6 corridas, patrón
fuerte y consistente -- ver experimento #7 abajo, el primero fuera de
la familia JSON, que encuentra un límite real de la técnica.

## Experimento real #7, primer target real de PROTOBUF (no JSON): A/B contra `fabric_config_newenvelope` (2026-08-16)

Los experimentos #1-#6 fueron todos JSON. `fabric_config_newenvelope`
(`NewEnvelope([]byte) (*cb.Envelope, error)`, `hyperledger/fabric-config`)
es un candidato real del propio registro que parsea **protobuf**, no
JSON -- deserializa un `cb.ConfigUpdate` real, cuyo campo
`ConfigGroup.Groups` es un mapa RECURSIVO de sí mismo (`map[string]*ConfigGroup`)
-- el árbol de configuración de canal real de Hyperledger Fabric, con
anidamiento real de producción, no sintético.

**Trabajo nuevo real, no una repetición**: el álgebra de operadores no
se pudo reusar tal cual (opera sobre `dict`/`list` de Python vía el
módulo `json`) -- se reimplementó en Go (`transpose`/`semantic_inverse`/
`interleave` operando sobre `*cb.ConfigGroup`/`*cb.ConfigUpdate` reales,
mismo criterio exacto que la versión Python) porque Go's fuzzing nativo
usa su propio formato de corpus (`go test fuzz v1\n[]byte(%q)`, no
archivos de bytes crudos) y la deserialización real necesita
`proto.Unmarshal` real.

**Dos problemas metodológicos reales encontrados armando esto, ambos
corregidos antes de confiar en un resultado**:
1. Go's fuzzer nativo mantiene una CACHÉ GLOBAL de corpus interesante
   (`$GOCACHE/fuzz/<paquete>/<FuzzFunc>/`) que persiste ENTRE corridas
   -- y el propio daemon de este proyecto ya venía fuzzeando este
   mismo target real durante horas, contaminando cualquier comparación
   sin limpiarla antes de cada corrida. Corregido limpiando esa caché
   explícitamente antes de cada una de las 10 corridas.
2. `go test -run=FuzzXxx -coverprofile=...` (sin `-fuzz`) por default
   solo instrumenta el PAQUETE bajo test (`configtx`, 1752
   statements) -- el trabajo real de deserialización pasa DENTRO de
   `google.golang.org/protobuf` (una dependencia), invisible a esa
   métrica por default. Los primeros intentos dieron el mismo
   "1.4%" exacto en las 10 corridas -- resultado sospechosamente
   idéntico que reveló el problema. Corregido con
   `-coverpkg=./...,google.golang.org/protobuf/...` (16595 statements
   reales en alcance).

**Metodología final**: 4 seeds reales (árboles `ConfigGroup` de 2-4
niveles, incluido un caso vacío real), 200 mutantes por grupo de
tratamiento vía la expresión real
`seq(loop(interleave,3), choice(transpose, semantic_inverse))`
reimplementada en Go, `-fuzztime=500000x` (ejecuciones exactas, mismo
criterio que `-runs` de libFuzzer), 5 repeticiones con distinta
semilla de RNG, corpus del fuzzer promovido a `testdata/fuzz/` después
de cada corrida antes de medir cobertura final.

**Resultado real, promedio de 5 corridas, PRIMER resultado negativo y
consistente de la serie**:

| métrica | control (4 seeds crudos) | tratamiento (204 seeds) |
|---|---|---|
| cobertura real (`configtx` + `google.golang.org/protobuf`) | 10.10% | 9.83% (**-2.70%**, gana **0/5**) |

Ninguna anomalía real (sin `--- FAIL` en ninguna de las 10 corridas,
chequeado explícitamente).

**Interpretación real, distinta a la de los experimentos JSON**: la
mutación estructural PIERDE acá, de forma consistente. Hipótesis
razonable (no verificada rigurosamente, pero mecánicamente coherente):
mi implementación de `transpose`/`semantic_inverse`/`interleave`
siempre pasa por `proto.Marshal` sobre un struct de Go válido -- por
construcción, NUNCA puede producir bytes con formato wire inválido
(varints truncados, tipos de wire incorrectos, longitudes que no
calzan). El havoc de bytes puro de `go test -fuzz`, en cambio, muta
los BYTES YA MARSHALEADOS directamente -- y en un formato binario denso
como protobuf, la mayoría de esas mutaciones SÍ producen bytes con
formato wire inválido, que ejercitan las rutas de manejo de errores
REALES del unmarshaler (justamente el código que la instrumentación de
cobertura ampliada ahora sí ve, dentro de la dependencia
`google.golang.org/protobuf`). JSON es un
formato de texto mucho más permisivo -- muchas mutaciones de bytes
siguen siendo JSON sintácticamente válido (o casi), así que ese
"espacio de bytes inválidos" es más chico y menos relevante ahí. Un
mutador que SOLO opera en el árbol ya deserializado, como este, nunca
explora ese espacio -- en un formato de texto permisivo eso no importa
mucho (el havoc lo cubre igual, y la estructura aporta lo suyo); en un
formato binario denso, ese espacio es una fracción real y grande de la
cobertura alcanzable, y quedarse afuera de él cuesta más de lo que la
diversidad estructural aporta.

**Esto no invalida los experimentos #1-#6** -- son honestos y reales
para JSON. Lo que aporta el experimento #7 es un límite real de la
técnica: el beneficio depende del formato de serialización, no solo de
la profundidad/anidamiento del contenido. Para formatos binarios
densos, la mutación a nivel de bytes sigue siendo más valiosa que la
mutación estructural pura -- la combinación ideal (no probada acá)
sería probablemente MEZCLAR ambas: usar el mutador estructural para
generar semillas de ALTO NIVEL, pero dejar que el motor de bytes
(libFuzzer/`go test -fuzz`) siga mutando esas semillas a nivel de
bytes también, en vez de tratarlas como fijas.

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
  experimento #7 (protobuf real, -2.70%, pierde 0/5), la señal ya NO
  es "ofrecerlo como opción general para targets con anidamiento" --
  el límite real es el FORMATO de serialización, no solo el
  anidamiento del contenido. Para JSON con anidamiento+procesamiento
  real (experimento #6), hay un caso fuerte. Para protobuf
  (experimento #7), pierde consistentemente -- no integrar esto para
  `fabric_config_newenvelope`/`fabric_gateway_parsetransactionenvelope`
  tal como está.
- **Hallazgo real más importante de toda la serie**: el efecto de
  anidamiento + procesamiento profundo JUNTOS en JSON (+22.52%) es
  SUPERLINEAL, no la suma de anidamiento solo (+5.78%) más
  procesamiento solo (+1.64%, ≈7.4% sumado ingenuamente).
- **Segundo hallazgo real, igual de importante**: el beneficio de la
  mutación estructural depende del formato de serialización, no solo
  del contenido. JSON es un formato de texto permisivo -- el havoc de
  bytes puro ya cubre bien el "espacio de bytes casi-válidos", así que
  la estructura aporta valor real encima. Protobuf es un formato
  binario denso -- la mayoría de las mutaciones de bytes producen
  wire-format INVÁLIDO, que ejercita rutas de error reales del
  unmarshaler; un mutador que solo opera en el árbol ya deserializado
  (como este) nunca visita ese espacio, y perderlo cuesta más de lo
  que la diversidad estructural aporta.
- Sin significancia estadística formal calculada en ninguno de los 7
  experimentos (promedios de 5 repeticiones cada uno).
- **Idea real para el futuro, no implementada**: la combinación más
  prometedora sería estructural + bytes, no una u otra -- usar el
  mutador estructural para generar semillas de alto nivel
  estructuralmente diversas, pero dejar que el motor de bytes
  (libFuzzer/`go test -fuzz`) las siga mutando a nivel de bytes
  también (en vez de tratarlas como fijas). Esto debería capturar el
  beneficio de ambos mundos -- diversidad estructural Y exploración de
  wire-format inválido -- pero no se probó, es una hipótesis para una
  ronda futura.
