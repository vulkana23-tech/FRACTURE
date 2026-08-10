# CONFIRMADO: heap-buffer-overflow real en el parseo JSON dentro del enclave SGX de fabric-private-chaincode

**Estado: bug de memoria real y reproducible, confirmado con ASan.
Reachability real desde el modelo de amenaza del propio proyecto
(host no confiable → enclave). NO reportado todavía a Hyperledger --
pendiente de decisión.**

## Resumen de una línea

`unmarshal_values()` (`ecc_enclave/enclave/shim.cpp`, dentro del
enclave SGX) llama `json_parse_string()` (parson) sobre un buffer que
el host NO CONFIABLE llena vía una ocall, sin ninguna garantía de que
contenga un terminador `'\0'` -- si el JSON tiene un string sin cerrar
(ej. falta la comilla de cierre), el parser escanea sin límite más
allá del buffer real, leyendo memoria fuera de sus bordes.

## Cómo se llegó a esto

Surgió de una observación al leer el código real para el finding
anterior (`2026-08-10_fabric-private-chaincode_parson.md`):
`unmarshal_values` recibe `json_len` pero nunca lo usa; llama
`json_parse_string(json_bytes)` confiando en que haya un `'\0'` en
algún lado. El usuario pidió específicamente rastrear el código del
lado del HOST para ver si garantiza el terminador.

**Lado enclave** (`ecc_enclave/enclave/shim.cpp:178-183`):
```cpp
int unmarshal_values(std::map<std::string,std::string>& values,
                      const char* json_bytes, uint32_t json_len)
{
    JSON_Value* root = json_parse_string(json_bytes);  // json_len IGNORADO
    ...
```
llamada desde (`shim.cpp:248-262`), con el buffer real:
```cpp
uint8_t json[262144];
ocall_get_state_by_partial_composite_key(comp_key, json, sizeof(json), &len, ctx->u_shim_ctx);
unmarshal_values(values, (const char*)json, len);
```

**Lado host, implementación de referencia**
(`ecc/chaincode/enclave/shim.go:144-171`):
```go
//export get_state_by_partial_composite_key
func get_state_by_partial_composite_key(...) {
    ...
    data := buf.Bytes()  // el JSON real armado en Go
    ...
    C._cpy_bytes(values, (*C.uint8_t)(C.CBytes(data)), C.uint32_t(len(data)))
    C._set_int(values_len, C.uint32_t(len(data)))
}
```
Copia **exactamente `len(data)` bytes reales**, nunca agrega un
terminador. `values_len` sí se reporta correcto -- pero el enclave
JAMÁS lo usa (confirmado arriba). El resto del buffer de 262144 bytes
del lado enclave queda con lo que hubiera antes ahí.

## Por qué esto SÍ importa en el modelo de amenaza real de SGX

El punto entero de un enclave SGX es que el código de adentro sigue
siendo seguro **aunque el host que lo rodea esté totalmente
comprometido/sea malicioso**. La ocall es exactamente el límite donde
cruza el control: el host arma el buffer y decide qué poner en él. Un
host malicioso real podría, sin ningún esfuerzo, devolver un JSON con
un string sin cerrar (ej. `[{"key":"a","value":"x`, sin comilla ni
corchetes de cierre) -- eso es indistinguible de un mensaje legítimo
truncado a nivel de la firma de la función, y `json_parse_string` no
tiene forma de saber dónde termina el buffer real.

## Confirmación empírica (no solo lectura de código)

Escribí un segundo harness (`fpc_parson_nullterm_harness.c`, distinto
del harness original que sí null-termina siempre) que reproduce el
escenario real con la mayor fidelidad posible sin correr en hardware
SGX real:

```c
#define FPC_REAL_BUFFER_SIZE 262144  // el mismo tamano real de shim.cpp

char *buf = malloc(FPC_REAL_BUFFER_SIZE);
size_t prefix_len = min(size, FPC_REAL_BUFFER_SIZE);
memcpy(buf, data, prefix_len);              // lo que el host "real" escribe
memset(buf + prefix_len, 'A', FPC_REAL_BUFFER_SIZE - prefix_len);  // sin '\0' en ningun lado -- host malicioso
json_parse_string(buf);
```

**Resultado: crasheó en el PRIMER intento** de smoke test (input:
`[{"key":"a","value":"value}]`, un string `value` sin comilla de
cierre):

```
==501440==ERROR: AddressSanitizer: heap-buffer-overflow on address ... 
READ of size 1 at 0x7bda8c771800 thread T0
    #0 skip_quotes parson.c
    #1 get_quoted_string parson.c
    #2 parse_string_value parson.c
    #3 parse_value parson.c
    #4 parse_object_value parson.c
    #5 parse_value parson.c
    #6 parse_array_value parson.c
    #7 parse_value parson.c
    #8 json_parse_string
SUMMARY: AddressSanitizer: heap-buffer-overflow parson.c in skip_quotes

0x7bda8c771800 is located 0 bytes after 262144-byte region
```

100% reproducible (`./fuzz_parson_nullterm crash-4874792252af7bc300b7a5ca2ad26c289b6f8195`
da el mismo resultado cada vez). Crash guardado en
`orchestrator/fuzz_harnesses/fpc_parson_nullterm_crash_example.bin`.

## Causa raíz exacta (leída, no supuesta)

`skip_quotes` (`common/json/parson.c:762-778`) SÍ chequea `'\0'`
correctamente:
```c
while (**string != '\"') {
    if (**string == '\0') {
        return JSONFailure;
    }
    ...
    SKIP_CHAR(string);
}
```
**No es un bug de lógica en parson** -- el chequeo está bien escrito.
El problema real es que parson, por diseño de su API pública
(`json_parse_string(const char *string)`, sin parámetro de longitud),
es una API de "string C terminado en null" clásica -- eso es válido
y normal PARA CUALQUIER LLAMADOR QUE GARANTICE el terminador. El bug
real está en cómo `fabric-private-chaincode` la usa: llama esta API
justo en el límite de confianza más sensible del proyecto (host no
confiable -> enclave) sin garantizar esa precondición.

## Alcance más amplio (no verificado, pero razonablemente inferido)

`skip_quotes` es solo UNA de varias funciones internas de parson que
hacen scans similares carácter-por-carácter buscando un delimitador o
`'\0'` (números, espacios en blanco, etc. -- ver `parson.c` en
general). Es probable que existan variantes del mismo bug alcanzables
con otros tipos de JSON malformado/truncado (ej. número sin cerrar,
objeto sin `}` de cierre). No se investigó cada una por separado --
el harness `fpc_parson_nullterm_harness.c` ya queda listo en el repo
para seguir buscando variantes si se quiere invertir más tiempo.

## Severidad -- honesto, sin sobre-reclamar

- **Confirmado**: lectura fuera de límites (heap-buffer-overflow) real
  y determinística, disparable con JSON truncado/malformado.
- **Confirmado por lectura de código**: la ruta real hacia el enclave
  (`unmarshal_values`) no tiene ninguna protección contra esto -- ni
  usa `json_len`, ni el host garantiza el terminador.
- **NO confirmado todavía** (fuera del alcance de este harness, que
  corre fuera de SGX): el comportamiento EXACTO dentro de un enclave
  SGX real -- si termina en un crash limpio del enclave (DoS) o si,
  al leer memoria de stack adyacente del enclave que "por suerte"
  contenga bytes parseables, podría terminar filtrando fragmentos de
  memoria privada del enclave hacia afuera (ej. si esos bytes leídos
  de más terminan siendo devueltos como parte de un `value` de un
  par key/value) -- esto último sería el escenario de mayor impacto
  real (fuga de confidencialidad, justo lo que SGX promete evitar) y
  necesitaría verificarse con el SDK real de Intel SGX (simulación o
  hardware real), que no está instalado en este VPS.

## Próximo paso (no implementado, pendiente de decisión)

1. Si se quiere reportar a Hyperledger: este es un caso sólido --
   reachability real, reproducible, causa raíz identificada con
   precisión. Se podría reportar ya mismo con lo que hay, dejando
   explícito que el impacto exacto dentro de SGX real no fue
   verificado.
2. Si se quiere profundizar antes de reportar: instalar el SGX SDK
   (modo simulación, sin hardware SGX real) para confirmar el
   comportamiento exacto dentro del enclave -- inversión de tiempo
   más grande, fuera del alcance de esta sesión.
3. Buscar más variantes del mismo bug (otros scans sin límite en
   parson.c) con el mismo harness.
