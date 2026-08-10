/* Harness real de libFuzzer para json_parse_string() (parson, vendoreada
   en common/json/parson.c de hyperledger/fabric-private-chaincode) --
   NO cubierta por OSS-Fuzz (confirmado contra la lista real de
   projects/ del repo google/oss-fuzz).

   Reachability real, confirmada leyendo el codigo real (no supuesta):
   ecc_enclave/enclave/shim.cpp:181, funcion unmarshal_values(), llama
   exactamente esta secuencia (parse -> validar tipo array -> iterar
   objetos -> leer campos string "key"/"value") sobre bytes que vienen
   de un OCALL (ecc_enclave/enclave/shim.cpp:254,
   ocall_get_state_by_partial_composite_key) -- es decir, datos
   provistos por el HOST NO CONFIABLE y parseados DENTRO del enclave
   SGX. Este es exactamente el limite de seguridad que un TEE (trusted
   execution environment) esta disenado para proteger: el modelo de
   amenaza de SGX asume que el host/OS que rodea al enclave puede estar
   totalmente comprometido, asi que un bug de memoria en el parseo dentro
   del enclave rompe la garantia de confidencialidad/integridad que todo
   el proyecto ofrece.

   Este harness replica el mismo patron real de unmarshal_values
   (parson puro, sin las dependencias C++/cifrado especificas de FPC
   que no son parte de la superficie de parseo). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parson.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	JSON_Value *root = json_parse_string(buf);
	if (root != NULL && json_value_get_type(root) == JSONArray)
	{
		JSON_Array *pairs = json_value_get_array(root);
		if (pairs != NULL)
		{
			size_t count = json_array_get_count(pairs);
			for (size_t i = 0; i < count; i++)
			{
				JSON_Object *pair = json_array_get_object(pairs, i);
				if (pair == NULL)
					continue;
				const char *key = json_object_get_string(pair, "key");
				const char *value = json_object_get_string(pair, "value");
				(void)key;
				(void)value;
			}
		}
	}
	if (root != NULL)
		json_value_free(root);

	free(buf);
	return 0;
}
