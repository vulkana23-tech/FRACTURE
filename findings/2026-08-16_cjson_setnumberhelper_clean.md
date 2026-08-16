# cJSON — `cJSON_SetNumberHelper()` (fix real de NULL pointer deref) — resultado limpio, primer pipeline C/C++ dirigido por parche

**Estado**: campaña real corrida (4 workers, 30s, ~107M ejecuciones
totales), **sin crash**. Resultado honesto, no un bug -- pero valida
extremo a extremo `targets/patch_directed_c_harness.py`, el último
lenguaje que faltaba conectar (Go, Rust y JVM ya lo estaban).

## Cómo se encontró el candidato

Vía `targets/find_patch_directed_candidates.py` contra
`DaveGamble/cJSON`: el commit real `b2890c8d76` ("fix: prevent NULL
pointer dereference in cJSON_SetNumberHelper (#991)", 2026-03-12)
agregó un chequeo de NULL real antes de desreferenciar el objeto en
`cJSON_SetNumberHelper`.

## Bug real encontrado en el pipeline nuevo, corregido en el momento

El primer intento en vivo NO probó `cJSON_SetNumberHelper` -- el commit
también toca `tests/misc_tests.c` (convención real de cJSON: test en el
mismo commit que el fix), y el contexto de un hunk ahí
(`cjson_functions_should_not_crash_with_null_pointers`, una función de
TEST) se coló como candidato antes que la función real. El modelo, con
buen criterio, ignoró el nombre inexistente en el header y generó un
harness igual -- VÁLIDO (compila, corre, no crashea), pero fuzzeando
`cJSON_Parse` en general, no la función real del fix. Ver
`targets/README.md` para el detalle completo del fix (filtro de
nombres con forma de función de test, `_LOOKS_LIKE_TEST_FUNCTION_RE`).

## El harness (segundo intento, corregido)

Generado y validado por IA (Ollama) en el **primer intento real** una
vez arreglado el extractor
(`orchestrator/fuzz_harnesses/cjson_setnumberhelper_harness.c`):

```c
cJSON *item = cJSON_CreateNumber(0.0);
double num = *(double *)data;
cJSON_SetNumberHelper(item, num);
cJSON_Delete(item);
```

Construye un objeto cJSON real (`cJSON_CreateNumber`) y le pasa un
`double` arbitrario del fuzzer a la función objetivo -- exactamente la
superficie del fix real (el puntero podía ser NULL antes del chequeo
agregado).

## Resultado real

Campaña real de 30s, 4 workers: **~107M ejecuciones reales, sin
crash**. El chequeo de NULL real (`b2890c8d76`) parece sólido para esta
función. Cobertura estable rápido (`cov: 15, ft: 16`) -- función chica,
esperable. Registrado como target 26 real del registro
(`cjson_setnumberhelper`) para exploración continua vía el daemon 24/7.
