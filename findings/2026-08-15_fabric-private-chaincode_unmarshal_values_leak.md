# fabric-private-chaincode: memory leak real en `unmarshal_values` (LeakSanitizer, severidad baja)

**Estado**: confirmado en vivo (LeakSanitizer, no supuesto). Severidad
baja -- leak, no corrupción de memoria.

## Cómo se encontró

Vía `targets/find_patch_directed_candidates.py` (fuzzing dirigido por
parche): el commit real `1e92847744` ("Fix null pointer issuer in
unmarshal_values", 2025-03-29) agregó chequeos de NULL a esta función,
y el commit siguiente (`18e0ef90d3`, un día después) sumó un test de
stress dedicado -- señal real de que los propios mantenedores ya
consideran esta función superficie sensible. Se construyó un harness
nuevo (`orchestrator/fuzz_harnesses/fpc_unmarshal_values_harness.c++`)
que replica la función COMPLETA tal cual está hoy (post-fix), a
diferencia del harness de parson ya existente en este proyecto que
solo cubre `json_parse_string()`.

## El bug real

`ecc_enclave/enclave/shim.cpp`, función `unmarshal_values`:

```c++
JSON_Value* root = json_parse_string(json_bytes);
if (json_value_get_type(root) != JSONArray)
{
    LOG_ERROR("Shim: Cannot parse values");
    return -1;   // <-- root nunca se libera acá
}
```

Cualquier input donde el JSON top-level parseable pero NO sea un
array (ej. `{"key":"a"}`, o un objeto con `"key"` presente pero sin
`"value"` -- el early-return de más abajo tampoco libera `root`)
pierde el `JSON_Value*` real asignado por `json_parse_string()`.
Confirmado en vivo con AddressSanitizer/LeakSanitizer:

```
Direct leak of 694 byte(s) in 13 object(s) allocated from:
    ... json_parse_string -> ... -> unmarshal_values_standalone
Input real que lo dispara: [{"key":"a"}]
```

## Reachability real

Misma cadena ya documentada para el harness de parson
(`fpc_parson_json_parse_string_harness.c`):
`ecc_enclave/enclave/shim.cpp:181` recibe bytes directo de un OCALL
(`ocall_get_state_by_partial_composite_key`) -- datos provistos por el
HOST NO CONFIABLE, parseados DENTRO del enclave SGX. Un host
malicioso/bugueado que llame repetidamente con JSON malformado de esta
forma específica puede acumular leaks reales dentro del enclave.

## Por qué severidad baja, no alta

- No es corrupción de memoria (no hay lectura/escritura fuera de
  límites) -- es un leak de heap.
- SGX enclaves tienen memoria limitada, así que un leak sostenido
  *podría* escalar a agotamiento de memoria del enclave bajo abuso
  sostenido (DoS-class), pero eso es un salto real, no confirmado acá
  -- no se hizo un experimento de agotamiento de memoria real en esta
  ronda.
- No se reportó todavía al proyecto real (fabric-private-chaincode) --
  este documento es el registro interno del hallazgo, no un reporte
  enviado.

## Nota aparte encontrada revisando el código real

`common/base64/base64.cpp` (la función `base64_decode` que esta misma
función `unmarshal_values` llama sobre el campo `"value"`) tiene un
uso real de memoria sin inicializar en el manejo del último 1-2
caracteres de un base64 sin padding (`char_array_4[1]`/`[2]` nunca
asignados antes de usarse en la conversión a `char_array_3`). No se
filtra a la salida observable en los casos revisados a mano (los loops
de append tienen los límites correctos), así que ASAN no lo va a
marcar -- haría falta MemorySanitizer, que este proyecto todavía no
tiene como fixture real (ver `triage/README.md`). Anotado acá para no
perderlo, no investigado más a fondo en esta ronda.
