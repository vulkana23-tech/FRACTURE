// Harness real generado y validado por targets/patch_directed_c_harness.py
// (primer intento, IA via Ollama, ver harness_gen/generate_harness.py) --
// candidato encontrado por find_patch_directed_candidates.py contra
// DaveGamble/cJSON, commit real b2890c8d76 ("fix: prevent NULL pointer
// dereference in cJSON_SetNumberHelper (#991)"). El primer intento de
// esta corrida en vivo se coló con un candidato de test (ver
// targets/README.md, "cjson_functions_should_not_crash..." de
// tests/misc_tests.c) -- corregido el extractor para excluirlo, esta
// es la version que SI apunta a la funcion real del fix.
#include "cJSON.h"
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have at least one double value in the input
    if (size < sizeof(double)) {
        return 0;
    }

    // Create a cJSON object to test with
    cJSON *item = cJSON_CreateNumber(0.0);
    if (!item) {
        return 0;
    }

    // Use the first double from the input data as the number to set
    double num = *(double *)data;

    // Call the target function
    cJSON_SetNumberHelper(item, num);

    // Clean up
    cJSON_Delete(item);
    return 0;
}
