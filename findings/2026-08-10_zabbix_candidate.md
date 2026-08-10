# zabbix -- nuevo programa activado, primer candidato C/C++ real

**Estado**: programa activado en SPECTRE, repo real de código C/C++
confirmado. Todavía sin harness/fuzz test escrito -- próximo paso
natural de FRACTURE.

## Por qué este programa

De 471 programas ya descubiertos por SPECTRE (vía el feed público) pero
sin activar, `zabbix` (HackerOne) fue el elegido: software de
monitoreo real escrito en C, con `paga bounties` explícito, y política
real que dice literalmente *"This program is solely focused on finding
vulnerabilities in the Zabbix monitoring solution itself"* -- exacto lo
que FRACTURE busca (bugs en el propio código, no en infraestructura
ajena).

## Activación real

```
docker exec spectre-worker python3 scrips/bugbounty_review.py watch zabbix
```

`refresh_hackerone_program` real trajo 11 scope assets (vía API real de
HackerOne). Encontrado en el camino: el asset `SOURCE_CODE` que devuelve
HackerOne es `https://www.zabbix.com/download_sources` -- una PÁGINA de
descargas, no una URL de repo git clonable directo. Ninguna herramienta
existente (Trivy, reachability_check, `select_targets.py` de FRACTURE)
sabe manejar esto tal cual -- hubo que buscar el repo real a mano.

**`policy_parsed.automated_scanning` quedó en "unclear"** -- el parser
con LLM (Ollama) tardó los 120s completos del timeout sin responder,
casi seguro por contención de recursos real (había fuzzing con 16 cores
+ CodeQL corriendo en paralelo en ese momento). Decisión de diseño
explícita: **FRACTURE no necesita este gate** -- a diferencia de
SPECTRE, nunca toca la infraestructura viva del programa, solo compila
y fuzzea localmente el código fuente que ellos mismos publican. Se
activó igual sin esperar a que el parser reintente.

## Repo real confirmado (no el link de la pagina de descargas)

`github.com/zabbix/zabbix` -- confirmado en vivo vía API real de
GitHub que es el monorepo oficial (descripción coincide exacta:
"Real-time monitoring of IT components and services..."). Desglose
real de lenguajes (`/languages`, no la clasificación por defecto que
muestra "Go Template" por volumen de plantillas):

- C: 20.7MB
- C++: 134KB
- PHP: 31.2MB (frontend web, no interesa para fuzzing de memoria)
- Go: 1.9MB
- resto: templates, docs, config

Repo grande (2GB total) -- va a hacer falta identificar un subdirectorio
o función específica dentro del código C real (no todo el repo) antes
de escribir un harness, mismo criterio ya usado con
`fabric-amcl`/`fabric-ca`/`fabric-config`.

## Candidato real confirmado (2026-08-10)

Clon parcial real del repo (`git clone --filter=blob:none --sparse
--depth 1` + `sparse-checkout set src`, 38MB en vez de los 2GB
completos -- mucho más manejable para explorar) para leer el código C
real y trazar el flujo real de datos, mismo criterio ya usado con
`fabric-ca`/`ServeHTTP`.

**Función**: `zbx_json_open(const char *buffer, struct zbx_json_parse *jp)`
-- `src/libs/zbxjson/json.c:648`. Internamente llama a
`zbx_json_validate()` (mismo archivo), que a su vez corre el parser
real de descenso recursivo en `src/libs/zbxjson/json_parser.c`.

**Reachability confirmada leyendo el código real** (no asumida): el
handler del protocolo *trapper* del servidor Zabbix (puerto 10051 por
defecto, el mismo puerto donde llegan agentes/`zabbix_sender`/proxies)
llama a esta función como lo PRIMERO que hace con los bytes crudos
recién leídos del socket:

```c
// src/libs/zbxtrapper/trapper.c:1265-1271, dentro de process_trap()
if ('{' == *s)	/* JSON protocol */
{
	struct zbx_json_parse	jp;
	...
	if (SUCCEED != zbx_json_open(s, &jp))
	{
		zbx_send_response(sock, FAIL, zbx_json_strerror(), ...);
```

`s` es el buffer recibido directo del socket -- cero transformación
previa, cero validación previa. Exactamente el patrón de "input externo
real, primer parser que lo toca" que buscamos, y ese protocolo
concreto (trapper) tiene historial real de CVEs en Zabbix.

**Viabilidad de harness (revisado, no implementado aún)**: la librería
es chica y bastante autocontenida --
`src/libs/zbxjson/{json.c,json_parser.c,jsonobj.c}` (2311 líneas
combinadas). Dependencias de compilación: `json_parser.h`, `jsonpath.h`,
`zbxnum.h` (json.c) y `jsonobj.h`, `zbxalgo.h` (json_parser.c) --
`zbxalgo` es una lib de utilidades (vectores/hashsets), sin dependencia
de red/DB, compila aislada. No se necesita levantar ningún servidor
Zabbix real ni tocar su infraestructura -- coherente con la disciplina
de FRACTURE.

## Harness real generado y compilado (2026-08-10)

`harness_gen/generate_harness.py` (Ollama/qwen3-coder:30b) timeouteó
(180s) contra el header público completo `zbxjson.h` -- 260 líneas son
macros `ZBX_PROTO_TAG_*` sin relación al parser, probablemente
confundieron/sobrecargaron al modelo corriendo en CPU con contención de
otros procesos. Escrito a mano en su lugar (`orchestrator/fuzz_harnesses/zabbix_zbxjson_open_harness.c`)
-- firma real mínima (`int zbx_json_open(const char *buffer, struct
zbx_json_parse *jp)`), sin necesidad de IA para algo esta chico.

**Aislar la librería del resto del monorepo fue el trabajo real**: el
build oficial de Zabbix usa autotools (`./configure` genera
`config.h` con macros `HAVE_*_H` reales del sistema) -- en vez de correr
el `./configure` completo (pull de dependencias opcionales pesadas:
PCRE2, OpenSSL, etc.), se escribió un `config.h` mínimo a mano
declarando solo los `HAVE_*_H` de headers POSIX/glibc que genuinamente
existen en este Linux (mismo resultado que autoconf detectaría en este
sistema, sin inventar nada). Iterando contra errores reales del
linker (no supuestos) se armó la lista mínima de fuentes reales
necesarias: `zbxjson/{json,json_parser,jsonobj}.c` +
`zbxstr/str.c` + `zbxalgo/*.c` + `zbxcommon/{common_log,common_str,misc,components_strings_representations}.c`
+ `zbxnum/num.c`. Dos funciones (`zbx_jsonpath_compile`/`_clear`) se
stubbearon (nunca las ejecuta `zbx_json_open`, solo están linkeadas
porque comparten unidad de compilación con `json.c`; arrastrar
`jsonpath.c` real hubiera sumado `zbxregexp`/`zbxvariant`/`zbxexpr` sin
necesidad real). Receta completa reproducible en
`orchestrator/fuzz_harnesses/zabbix_zbxjson_open_build.sh` +
`_config.h`.

**Compiló y linkeó limpio** con `clang -fsanitize=fuzzer,address`.
Smoke test real: 2.7M ejecuciones en 16s (~171k exec/s), sin crash en
esa corrida corta.

**Corrida real lanzada**: 8 workers en paralelo (`-jobs=8 -workers=8`),
30 minutos (`-max_total_time=1800`), en
`/opt/fracture/build/zabbix_zbxjson/` (build/corpus/crashes, todo
gitignored).

## Resultado de la corrida (2026-08-10, 30 min, 8 workers)

**~1.64 mil millones de ejecuciones combinadas, cero crashes, cero
errores de ASan.** `crashes/` vacío, ningún log de worker con
`ERROR`/`crash`/`leak`/`abort`. `zbx_json_open()` sobrevivió una
campaña real de fuzzing sin encontrar un bug de memoria en esta
primera pasada -- no es evidencia de que el código esté libre de
bugs, solo de que esta corrida puntual no encontró ninguno con este
corpus semilla mínimo (3 seeds a mano: `{}`, un mensaje real de sender
data, y texto no-JSON).

**Efecto colateral real detectado durante esta corrida**: los 8
workers a ~99% CPU cada uno (de 18 cores totales del VPS) le sacaron
CPU a Ollama el tiempo suficiente como para que un chequeo de
política real de SPECTRE (`bugbounty_refresh_scope_and_policy`, sobre
el programa `crypto` de HackerOne) timeoutee y caiga a un fallback
`"unclear"`, disparando una alerta CRÍTICA falsa de "scanning pasó de
permitido a otra cosa". Confirmado el diagnóstico reintentando el
mismo parse a mano dos veces: con el fuzzer corriendo, timeout exacto
de 120.1s (mismo fallback); apenas terminó el fuzzer, el mismo call
real tardó 25.3s y devolvió correctamente `"allowed"` -- corregido en
la base de SPECTRE. **Nota operativa para corridas futuras de
FRACTURE**: correr fuzzing pesado (muchos workers) compite de verdad
por CPU con Ollama compartido entre SPECTRE y FRACTURE en este mismo
VPS -- vale la pena considerar `nice`/`cpuset` o coordinar horarios
si se repite.

## Corpus ampliado + campaña larga (2026-08-10, 90 min, 8 workers)

Corpus semilla ampliado de 3 a 55 entradas reales, generadas a partir
del código fuente real (no inventadas): estructuras reales del
protocolo trapper leídas de `send_buffer.c` (sender data) y
`trapper.c` (los valores reales de `request` que el servidor
reconoce -- agent data, active checks, proxy heartbeat, proxy config,
zabbix.stats, history.push), más casos límite deliberados (unicode,
bytes de control, números extremos/científicos, anidamiento profundo
hasta 500 niveles, arrays/objetos anchos de 2000 elementos, JSON
malformado a propósito -- comas colgantes, llaves desbalanceadas,
claves duplicadas, BOM). Script real:
`gen_corpus.py` (no commiteado, generador puntual). libFuzzer
minimizó el corpus heredado de la corrida anterior (41k archivos,
muchos redundantes) a 504 entradas cubriendo la misma cobertura (224
regiones / 1137 features) antes de arrancar la campaña larga.

**Mitigación aplicada por el efecto colateral de la corrida anterior**:
esta vez se lanzó con `nice -n 10` para no volver a competir de más
por CPU con Ollama.

**Resultado real**: **~6.18 mil millones de ejecuciones combinadas**
(8 workers × 90 min), **cero crashes, cero errores de ASan**. El
corpus final quedó en 49.742 entradas (de 504 iniciales) -- muchas
nuevas rutas de cobertura descubiertas por la mutación real, ninguna
disparó un bug de memoria. Confirmado además que el `nice` funcionó:
cero eventos de `policy`/alertas críticas en los logs de SPECTRE
durante toda la corrida (vs. el incidente real de crypto.com en la
corrida anterior), y Ollama respondió en 35ms justo después de
terminar.

**Conclusión honesta**: dos campañas reales (30 min + 90 min, ~7.8B
ejecuciones combinadas) sin encontrar un crash en `zbx_json_open`.
Esto reduce la confianza en que haya un bug de memoria trivial de
alcanzar con mutación pura desde este corpus semilla, pero NO es
prueba de ausencia de bugs -- el parser real (`json_parser.c`) es
recursivo-descendente con profundidad acotada explícitamente (`depth`
como parámetro), lo cual probablemente ya mitiga stack overflow por
anidamiento (varios de los seeds de anidamiento profundo fueron
`REDUCE`ados/descartados por no aportar cobertura nueva, sugiriendo
que el limite de profundidad se activa temprano y de forma segura).

**Próximo paso natural (no implementado)**: este target ya está
razonablemente explorado por ahora -- mejor invertir el próximo ciclo
de fuzzing en un target C/C++ nuevo (otro programa, u otra función
dentro de zabbix con menos cobertura ya probada) en vez de seguir
extendiendo la misma campaña sin nueva señal.
