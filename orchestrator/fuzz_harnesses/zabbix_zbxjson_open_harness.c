/* Harness real de libFuzzer para zbx_json_open() (src/libs/zbxjson/json.c,
   declarada en include/zbxjson.h) -- el parser JSON real que el protocolo
   trapper del servidor Zabbix (puerto 10051) usa como PRIMERA operacion
   sobre bytes crudos recibidos del socket (ver
   src/libs/zbxtrapper/trapper.c:1270, process_trap()). Reachability
   confirmada leyendo el codigo real, documentado en
   findings/2026-08-10_zabbix_candidate.md.

   Escrito a mano (no generado por IA) porque el header publico
   completo (zbxjson.h) es ~260 lineas de macros ZBX_PROTO_TAG_* sin
   relacion al parser, y confundio/timeouteo al modelo local; la firma
   real que importa es minima: */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct zbx_json_parse
{
	const char	*start;
	const char	*end;
};

int	zbx_json_open(const char *buffer, struct zbx_json_parse *jp);
const char	*zbx_json_strerror(void);

/* json.c tiene zbx_json_open_path() en la misma unidad de compilacion
   (llama a zbx_jsonpath_compile/clear reales de jsonpath.c) pero
   nuestro target zbx_json_open() nunca la ejecuta -- jsonpath.c arrastra
   zbxregexp/zbxvariant/zbxexpr, ninguno necesario para lo que este
   harness fuzzea. Stubs solo para satisfacer al linker; codigo muerto,
   nunca corren. */
typedef struct { int dummy; } zbx_jsonpath_t;
int zbx_jsonpath_compile(const char *path, zbx_jsonpath_t *jsonpath) { (void)path; (void)jsonpath; return -1; }
void zbx_jsonpath_clear(zbx_jsonpath_t *jsonpath) { (void)jsonpath; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	struct zbx_json_parse jp;
	zbx_json_open(buf, &jp);

	free(buf);
	return 0;
}
