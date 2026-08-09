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

## Próximo paso (no implementado todavía)

Generar el harness real con `harness_gen/generate_harness.py` contra
`zbx_json_open` (firma simple: `const char *` -> ideal para
`LLVMFuzzerTestOneInput`), compilar con
`clang -fsanitize=fuzzer,address` igual que se validó con cJSON, y
correr el fuzzer real. Pendiente de confirmación explícita del usuario
antes de arrancar (paso de trabajo nuevo, no solo la búsqueda de
programa que se pidió hoy).
