/* Harness real de libFuzzer para unmarshal_values() (fabric-private-chaincode,
   ecc_enclave/enclave/shim.cpp) -- encontrado vía fuzzing dirigido por
   parche (targets/find_patch_directed_candidates.py): el commit real
   1e92847744 ("Fix null pointer issuer in unmarshal_values",
   2025-03-29) agregó chequeos de NULL para los campos "key"/"value" en
   esta MISMA función, y el commit siguiente (18e0ef90d3, un día
   después) agregó un test de stress dedicado -- señal real de que los
   propios mantenedores ya la consideran superficie sensible.

   Reachability real (documentada primero en
   fpc_parson_json_parse_string_harness.c, misma cadena real):
   ecc_enclave/enclave/shim.cpp:181, unmarshal_values(), recibe bytes
   directo de un OCALL (ocall_get_state_by_partial_composite_key) --
   datos provistos por el HOST NO CONFIABLE, parseados DENTRO del
   enclave SGX.

   A diferencia del harness de parson ya existente (que solo cubre
   json_parse_string(), la parte de TOKENIZADO), este cubre la funcion
   COMPLETA tal cual esta HOY (post-fix, con los chequeos de NULL ya
   aplicados) -- incluye el paso real de base64_decode() sobre el
   campo "value" y la insercion en el std::map, que el harness de
   parson no ejercita. base64_decode() nunca tuvo su propio harness en
   este proyecto -- lectura manual del código real
   (common/base64/base64.cpp, ~120 líneas, sin dependencias SGX)
   encontró un uso real de memoria sin inicializar en el manejo de los
   últimos 1-2 caracteres de un base64 sin padding (char_array_4[1]/[2]
   nunca asignados antes de usarse en la conversión) -- no se filtra a
   la salida observable en los casos revisados a mano, pero es UB real
   que MemorySanitizer detectaría (este proyecto no tiene fixture real
   de MSan todavía, ver triage/README.md -- este haría un buen
   candidato futuro).

   unmarshal_values_standalone() de abajo es una copia FIEL de la
   función real tal cual está en shim.cpp hoy (mismo control de flujo,
   mismos chequeos) -- nunca se incluye shim.cpp directo porque arrastra
   headers específicos de SGX (enclave_t.h, sgx_thread.h, mbusafecrt.h)
   que no son parte de la superficie de parseo real. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include "parson.h"
#include "base64.h"

#define COND2ERR(cond) if (cond) goto err;

static int unmarshal_values_standalone(
    std::map<std::string, std::string>& values, const char* json_bytes, uint32_t json_len)
{
    JSON_Value* root = json_parse_string(json_bytes);
    if (json_value_get_type(root) != JSONArray)
    {
        if (root) json_value_free(root);
        return -1;
    }

    JSON_Array* pairs = json_value_get_array(root);
    COND2ERR(pairs == NULL);

    for (int i = 0; i < json_array_get_count(pairs); i++)
    {
        JSON_Object* pair = json_array_get_object(pairs, i);
        const char* key = json_object_get_string(pair, "key");
        if (key == NULL)
        {
            return -1;
        }
        const char* b64value = json_object_get_string(pair, "value");
        if (b64value == NULL)
        {
            return -1;
        }
        std::string value = base64_decode(b64value);
        values.insert({key, value});
    }
    json_value_free(root);
    return 1;

err:
    if (root) json_value_free(root);
    return -1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* json_parse_string() real requiere un buffer null-terminated (no
       toma un largo explicito) -- mismo fix ya documentado en
       fpc_parson_json_parse_string_harness.c, se repite aca por la
       misma razon real: libFuzzer no garantiza que `data` venga
       terminado en null. */
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    std::map<std::string, std::string> values;
    unmarshal_values_standalone(values, buf, (uint32_t)size);

    free(buf);
    return 0;
}
