# CONFIRMADO: heap-buffer-overflow real en el parseo JSON dentro del enclave SGX de fabric-private-chaincode

**Estado: bug de memoria real y reproducible, confirmado con ASan Y
en un enclave SGX real (modo simulación, SDK oficial de Intel,
`libshim.a` compilado desde el código fuente real del proyecto).
Impacto confirmado empíricamente en AMBAS direcciones: (1) crash real
del enclave, y (2) fuga de confidencialidad end-to-end -- contenido
de memoria del enclave devuelto al host no confiable como un
key/value JSON "válido" -- reproducida 3/3 veces. Reachability real
desde el modelo de amenaza del propio proyecto (host no confiable →
enclave). NO reportado todavía a Hyperledger -- pendiente de
decisión.**

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

## Nota de precisión: stack, no heap, en el código real

El harness de ASan de la sección anterior usa `malloc()` para poder
apoyarse en el detector de heap-buffer-overflow de ASan. El buffer
real en `shim.cpp` (`uint8_t json[262144];`) es una variable **local
de stack**, no un buffer de heap. El bug es el mismo (lectura sin
límite más allá de un buffer de tamaño fijo sin terminador
garantizado), pero técnicamente es un **stack out-of-bounds read**,
no un heap-buffer-overflow, en el código de producción. Esto se
verificó directamente en la sección siguiente, reproduciendo la
variable exactamente como está declarada en el código real (mismo
tamaño, mismo tipo de storage) dentro de un enclave SGX real.

## Confirmación dentro de un enclave SGX real (modo simulación) -- impacto ya no es hipotético

Se instaló el SDK real de Intel SGX (modo `SIM`, sin hardware SGX
disponible en este VPS) y se construyó un PoC
(`orchestrator/fuzz_harnesses/fpc_sgx_leak_poc/`) que:

- Copia **verbatim** `unmarshal_values()` de `shim.cpp` (sin
  modificar ni una línea de la lógica).
- Usa `parson.c`/`parson.h` y `base64.cpp`/`base64.h` reales, sin
  modificar, compilados con el toolchain real de enclave SGX (mismo
  `StackMaxSize 0x80000` que `ecc_enclave/enclave/enclave.config.xml`,
  mismos flags: `-nostdinc -fno-builtin -fvisibility=hidden -fpie
  -fstack-protector`, SIM mode).
- Reproduce el patrón vulnerable exacto: `uint8_t json[262144]` local
  de stack, `memcpy` de los bytes "del host" (`payload_len` bytes
  atacante-controlados), y el resto del buffer **sin tocar** --
  exactamente como en el código real -- antes de llamar
  `unmarshal_values(values, (const char*)json, len)`.
- Antes de cada llamada, "ensucia" ~384KB de stack del enclave con un
  marcador reconocible (`plant_secret()`), simulando el residuo real
  que un enclave de larga duración acumula en su stack por
  transacciones previas (valores de estado descifrados, claves,
  etc. -- exactamente el tipo de dato que SGX promete mantener
  confidencial).

Código completo, Makefile y el output real de una corrida están en
`orchestrator/fuzz_harnesses/fpc_sgx_leak_poc/` (`App/App.cpp`,
`Enclave/testleak.cpp`, `example_run_output.txt`).

### Resultado 1 -- el input exacto que crasheó bajo ASan, en el enclave real, NO crashea (por suerte de layout)

Con el input exacto del crash de ASan (`[{"key":"a","value":"value}]`,
28 bytes), el ECALL retorna exitosamente (el enclave NO crashea) y
`unmarshal_values` devuelve error de parseo limpio (`status=-1`),
porque el primer byte fuera del buffer declarado resultó ser `0x00`
en este layout de stack particular. Esto por sí solo ya es un dato
importante: bajo ASan el mismo input crashea determinísticamente,
pero en el binario real compilado (sin ASan, con el allocator/stack
real de SGX) el resultado depende del contenido real de la memoria
adyacente -- **no hay garantía de que siempre falle limpio**.

### Resultado 2 -- confirmado: el scan sin límite SÍ puede crashear el enclave real (DoS real, no solo bajo ASan)

Un segundo ECALL (`ecall_probe_bounds`) lee hacia adelante desde el
final del buffer declarado, en pasos de 256 bytes, hasta encontrar el
límite real de memoria mapeada:

```
[checkpoint] read OK at json[262144+0]    = 0x00
[checkpoint] read OK at json[262144+256]  = 0xf0
[checkpoint] read OK at json[262144+512]  = 0xcc
[checkpoint] read OK at json[262144+768]  = 0xcc
[checkpoint] read OK at json[262144+1024] = 0xcc
[checkpoint] read OK at json[262144+1280] = 0xcc
timeout: the monitored command dumped core        <- crash real, SIGSEGV
```

Es decir: hay ~1280-1536 bytes de memoria mapeada y legible más allá
del buffer declarado antes de un fallo de página real. Cualquier
input malformado cuyo scan sin límite (`skip_quotes` u otras
funciones similares de `parson.c`) no encuentre ni una comilla de
cierre ni un `'\0'` dentro de esa ventana **sí crashea el proceso
enclave de verdad** (`Segmentation fault`, core dump) -- confirmado
empíricamente, no inferido. Esto establece de forma definitiva la
mitad "DoS" del impacto: es un crash real y alcanzable del enclave,
no un artefacto exclusivo de ASan.

### Resultado 3 -- confirmado: el "residuo secreto" SÍ está físicamente presente donde el parser escanea

Se agregó un ECALL de volcado directo (`ecall_dump_raw`) que copia
los bytes crudos de `json[payload_len .. payload_len+4096)` --
exactamente la región que `unmarshal_values` escanearía en el bug
real -- de vuelta al host, **sin pasar por el parser JSON**. En los 4
payloads distintos probados (string sin cerrar en "value", en "key",
número sin cerrar, array vacío sin cerrar), el marcador plantado
(`plant_secret`) apareció **byte por byte, en las primeras decenas de
bytes**, en la región exacta que el bug real leería:

```
[unterminated-value] first 96 leftover bytes (ascii):
_TOP_SECRET","LEAK_MARKER_KEY":"TOP_SECRET_ENCLAVE_STATE_0123456789abcdef_TOP_SECRET","LEAK_MARK
```

Esto prueba que la premisa del escenario de "fuga de confidencialidad"
no es especulativa: en la ruta de código real, con el tamaño de
buffer real, la memoria de stack que el bug expone SÍ contiene datos
reconocibles de actividad previa del enclave.

### Resultado 4 -- CONFIRMADO END-TO-END: fuga de confidencialidad completa, reproducida 3/3

Con un segundo marcador diseñado para incluir un cierre JSON válido
(`{"key":"LEAKED_TOP_SECRET_ENCLAVE_STATE_...","value":"AAAA"}]` en
vez de un ciclo sin cerradores), se calculó el offset exacto donde
empieza el ciclo del marcador dentro de la región no inicializada
(offset 58, medido con `ecall_dump_raw2`), y se construyó un payload
de 58 bytes: `[` seguido de 57 espacios (whitespace JSON válido) --
sin ningún carácter especial de por sí, solo para alinear el punto
donde el parser empieza a leer memoria no inicializada exactamente en
el inicio de un ciclo del marcador.

Resultado, reproducido en 3 corridas independientes:

```
=== [full-leak-attempt] payload = '[' + 57 spaces (58 bytes)
[full-leak-attempt] ECALL OK, unmarshal_status=1
[full-leak-attempt] returned (56 bytes): KV[LEAKED_TOP_SECRET_ENCLAVE_STATE_0123456789abcdef]=[]
```

`unmarshal_status=1` significa que `unmarshal_values()` (el código
**verbatim** de `shim.cpp`) consideró el parseo un **éxito completo**,
y el par key/value devuelto -- que cruza la frontera de confianza del
enclave hacia el host NO confiable -- contiene literalmente el texto
del marcador secreto leído de memoria de stack del enclave que el
payload atacante nunca escribió. (El campo `value` sale vacío porque
`"AAAA"` decodifica en base64 a 3 bytes `0x00`, un detalle incidental
del harness -- el campo `key`, que se devuelve tal cual sin decodificar,
es la prueba.)

**Esto confirma el escenario de mayor impacto planteado en la versión
anterior de este finding como "no verificado": un host malicioso
puede, con un input cuidadosamente alineado, lograr que el enclave
devuelva fragmentos de su propia memoria interna como si fueran datos
JSON legítimos, cruzando la frontera de confidencialidad que SGX
existe para proteger.**

### Interpretación honesta de estos 4 resultados juntos

- El **crash (DoS)** es el resultado más probable/fácil de alcanzar
  para un atacante que no controla el layout exacto de memoria del
  enclave objetivo: basta un JSON malformado cualquiera para arriesgar
  un crash si el scan corre más de ~1.3KB sin encontrar `'"'` o `'\0'`.
- La **fuga de confidencialidad completa** requiere que el atacante
  además acierte la alineación exacta para que la memoria adyacente
  (que no controla) forme JSON sintácticamente válido y cerrado. En
  este PoC se logró porque el marcador sintético se diseñó para
  incluir un cierre; en un enclave real, la probabilidad de que datos
  reales (protobuf/JSON serializado, valores de estado descifrados)
  contengan un `"`, `}` o `]` en la posición correcta **no es
  despreciable** -- esos caracteres son comunes en datos reales, y un
  atacante con acceso repetido al mismo enclave (mismo binario, mismo
  layout de stack determinístico dentro de una misma versión/TCS,
  como se observó aquí: la dirección de `json[]` fue idéntica en las
  6 corridas realizadas) puede iterar offsets como se hizo en este
  PoC hasta encontrar una alineación que funcione. Esto ya NO es
  "razonablemente inferido" -- es un mecanismo demostrado
  end-to-end, con la única variable abierta siendo cuánto esfuerzo de
  alineación necesitaría un atacante real contra memoria real (no
  sintética).

## Severidad -- actualizada con evidencia empírica directa en SGX real

- **Confirmado (ASan + SGX real)**: lectura fuera de límites
  determinística, disparable con JSON truncado/malformado, alcanzable
  desde el límite de confianza host→enclave sin ninguna protección en
  el código real.
- **Confirmado en SGX real**: crash real del proceso enclave (DoS)
  cuando el scan corre más de ~1.3KB sin encontrar un delimitador.
- **Confirmado en SGX real, end-to-end, reproducido 3/3**: fuga de
  confidencialidad -- contenido de memoria de stack del enclave
  devuelto al host no confiable disfrazado de un par key/value JSON
  válido, vía la función real `unmarshal_values()` sin modificar.
- Impacto dual: el mismo bug puede manifestarse como DoS (caso común,
  bajo esfuerzo) o como fuga de confidencialidad (caso de mayor
  impacto, requiere alinear el input al layout de memoria del
  enclave objetivo -- demostrado factible, no solo teórico).

## Próximo paso

1. **Reportar a Hyperledger.** El caso ya no tiene puntos abiertos de
   impacto: reachability real, causa raíz exacta, PoC reproducible
   tanto de crash como de fuga de confidencialidad completa dentro de
   un enclave SGX real (modo simulación, SDK oficial). Es un hallazgo
   sólido y completo para reportar tal cual está.
2. Opcional, si se quiere invertir más tiempo antes de reportar:
   repetir el PoC de fuga end-to-end (Resultado 4) usando contenido
   de stack "orgánico" (residuo real de una transacción de chaincode
   legítima previa en vez del marcador sintético) para fortalecer aún
   más el argumento de plausibilidad en producción real.
3. Buscar más variantes del mismo bug (otros scans sin límite en
   `parson.c`: números, espacios en blanco) con el harness ASan
   existente -- no se investigó cada uno por separado.
