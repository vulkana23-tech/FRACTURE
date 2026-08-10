/* Segundo harness, distinto del primero (fpc_parson_json_parse_string_harness.c):
   ese harness prueba la robustez GENERAL de parson sobre input bien
   formado (siempre null-terminated por el propio harness). Este harness
   prueba una hipotesis puntual encontrada leyendo el codigo real:

   - Enclave (ecc_enclave/enclave/shim.cpp:181): unmarshal_values()
     llama json_parse_string(json_bytes) sin usar json_len para nada, y
     sin agregar un '\0' explicito -- confia en que YA haya uno en
     algun lado del buffer real json[262144].
   - Host (ecc/chaincode/enclave/shim.go:169-170): la implementacion de
     referencia copia EXACTAMENTE len(data) bytes reales (sin agregar
     terminador) hacia el buffer de la ocall -- el resto del buffer de
     262144 bytes queda con lo que hubiera antes ahi, memoria del lado
     NO CONFIABLE.

   json_parse_string(), por diseno de su firma (const char*, sin
   parametro de longitud), asume string C terminado en '\0' -- eso no
   es un bug de parson en si, el problema es que shim.cpp usa esa API
   justo en el limite de confianza mas importante del sistema (datos
   que cruzan desde el host no confiable hacia el enclave) sin ninguna
   garantia real de que el terminador exista.

   Este harness simula el escenario mas fiel posible sin correr en SGX
   real: reserva un buffer del MISMO tamano exacto que el array real
   del enclave (262144 bytes, ver shim.cpp:249), copia el input de
   fuzzing al principio (lo que un host arma como JSON real), y llena
   el resto con un filler que NO es '\0' en ningun lado del buffer --
   exactamente lo que un host malicioso (el modelo de amenaza real de
   SGX) podria hacer. Si parson lee mas alla de este buffer del tamano
   exacto del array real, ASan lo va a atrapar como heap-buffer-overflow
   real, sin ambiguedad. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parson.h"

#define FPC_REAL_BUFFER_SIZE 262144

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf = malloc(FPC_REAL_BUFFER_SIZE);
	if (buf == NULL)
		return 0;

	size_t prefix_len = size < FPC_REAL_BUFFER_SIZE ? size : FPC_REAL_BUFFER_SIZE;
	if (prefix_len > 0)
		memcpy(buf, data, prefix_len);
	/* Filler deliberadamente SIN '\0' -- simula host malicioso que no
	   null-termina en ningun lado del buffer completo. */
	memset(buf + prefix_len, 'A', FPC_REAL_BUFFER_SIZE - prefix_len);

	JSON_Value *root = json_parse_string(buf);
	if (root != NULL)
		json_value_free(root);

	free(buf);
	return 0;
}
