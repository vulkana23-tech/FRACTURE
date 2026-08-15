#include "samplelib.h"

const unsigned char *samplelib_parse_len_prefixed(const unsigned char *data, size_t size, size_t *out_len) {
    if (size < 1) {
        *out_len = 0;
        return NULL;
    }
    size_t len = data[0];
    if (len > size - 1) {
        *out_len = 0;
        return NULL;
    }
    *out_len = len;
    return data + 1;
}
