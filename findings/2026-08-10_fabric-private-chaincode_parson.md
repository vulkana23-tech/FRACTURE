# fabric-private-chaincode -- sexto target real, json_parse_string() (parson) DENTRO del enclave SGX

## Por qué este target

Sexto de los 12 candidatos de Hyperledger. Elegido a propósito por
tener C/C++ real (confirmado vía `/languages` de GitHub: 116KB C +
114KB C++, junto a Go) -- volver a la vía C/C++ después de zabbix, cuya
capa de red resultó demasiado costosa de aislar.

`fabric-private-chaincode` (FPC) permite ejecución confidencial de
chaincode usando Intel SGX (enclaves de hardware) -- el proyecto de
mayor sensibilidad de seguridad tocado hasta ahora en FRACTURE.

## Candidato real confirmado

**Librería**: `common/json/parson.c` + `parson.h` (2437 + 255 líneas,
"Parson", una librería JSON de un solo archivo, vendoreada). Confirmado
que **NO está en OSS-Fuzz** (chequeado contra la lista real de
`projects/` de `google/oss-fuzz` -- no aparece "parson" entre los ~20
proyectos relacionados a JSON que sí están).

**Función**: `json_parse_string(const char *string)`.

**Reachability real -- la más fuerte de todos los targets probados
hasta ahora**, confirmada leyendo el código real:

```cpp
// ecc_enclave/enclave/shim.cpp:178-181, dentro del ENCLAVE
int unmarshal_values(
    std::map<std::string, std::string>& values, const char* json_bytes, uint32_t json_len)
{
    JSON_Value* root = json_parse_string(json_bytes);
    if (json_value_get_type(root) != JSONArray) { ... }
    ...
```

llamada desde:

```cpp
// ecc_enclave/enclave/shim.cpp:248-262, tambien dentro del ENCLAVE
void get_public_state_by_partial_composite_key(...)
{
    uint8_t json[262144];
    ...
    ocall_get_state_by_partial_composite_key(comp_key, json, sizeof(json), &len, ctx->u_shim_ctx);
    ...
    unmarshal_values(values, (const char*)json, len);
}
```

`ocall_*` es una OCALL de SGX -- una llamada DESDE el enclave HACIA el
host que lo rodea. El modelo de amenaza de SGX asume explícitamente
que ese host puede estar totalmente comprometido; el buffer `json` que
llena la ocall es, por definición, **dato no confiable que el enclave
recibe desde afuera de su frontera de confianza**, y se parsea
DIRECTAMENTE dentro del enclave. Un bug de memoria acá no es "un bug
más" -- rompería exactamente la garantía de confidencialidad/integridad
que todo el proyecto FPC existe para dar.

**Detalle real observado (no confirmado como bug, documentado para no
perderlo)**: `unmarshal_values` recibe `json_len` como parámetro pero
**nunca lo usa** para el parseo -- llama `json_parse_string(json_bytes)`
tal cual, que internamente escanea hasta encontrar un `'\0'`, sin
respetar el límite explícito de `json_len`. Si el buffer llenado por
la ocall no está garantizado null-terminated dentro de esos `len`
bytes (no verificado -- dependería de la implementación real de la
ocall del lado del host, fuera del alcance de este harness), esto
podría causar una lectura fuera de los límites del buffer dentro del
enclave. No se investigó más a fondo porque el harness de este target
fuzzea `parson.c` de forma aislada (con un buffer que SÍ es
null-terminated por construcción, igual que el caso real feliz) -- si
se quisiera perseguir esto habría que fuzzear con longitudes
explícitas no confiables, un target distinto.

## Harness

`orchestrator/fuzz_harnesses/fpc_parson_json_parse_string_harness.c`
-- replica el mismo patrón real de `unmarshal_values` (parse -> validar
tipo array -> iterar objetos -> leer campos string "key"/"value"),
usando solo `parson.c` puro (sin las dependencias C++/cifrado
específicas de FPC, que no son parte de la superficie de parseo).

**Build mucho más simple que zabbix**: parson.c solo depende de
headers estándar de C (`stdio.h`, `stdlib.h`, `string.h`, `ctype.h`,
`math.h`, `errno.h`) -- cero config.h a mano, cero autotools, compiló
limpio a la primera con `clang -fsanitize=fuzzer,address`.

## Corrida

8 workers en paralelo, 60 minutos (`-max_total_time=3600`), `nice -n
10` (misma mitigación aplicada desde el incidente de crypto.com con
zabbix). Corpus semilla: casos reales del formato esperado (array de
`{"key":...,"value":...}`, valores base64) + casos límite (null,
array de tipos incorrectos, JSON truncado, valores muy largos).
Resultado se documenta acá cuando termine.
