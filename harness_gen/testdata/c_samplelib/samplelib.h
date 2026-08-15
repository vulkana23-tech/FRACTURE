#ifndef SAMPLELIB_H
#define SAMPLELIB_H
#include <stddef.h>

/* Devuelve un puntero DENTRO de data (nunca copia) a los bytes despues
   del prefijo de longitud -- caller nunca tiene que liberar nada. */
const unsigned char *samplelib_parse_len_prefixed(const unsigned char *data, size_t size, size_t *out_len);

#endif
