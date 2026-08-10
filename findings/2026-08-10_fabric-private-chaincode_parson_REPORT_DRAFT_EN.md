# Missing NUL-termination guarantee before json_parse_string() leads to enclave-side out-of-bounds read, crash, and confidentiality leak (ecc_enclave/enclave/shim.cpp)

**Reported by:** sharkoon

## Summary

`unmarshal_values()` in `ecc_enclave/enclave/shim.cpp` calls parson's
`json_parse_string()` on a fixed-size, stack-allocated buffer
(`uint8_t json[262144]`) that is filled by an **untrusted host** via
an ocall, with no guarantee that the buffer is NUL-terminated.
`json_parse_string()` is a classic NUL-terminated-C-string API; if the
JSON returned by the host is malformed or truncated (e.g. a string
value missing its closing quote), parson's internal scanning
functions (e.g. `skip_quotes`) read past the end of the data the host
actually wrote, into whatever memory happens to follow on the enclave
stack.

I built a proof of concept using the real Intel SGX SDK (simulation
mode — no SGX-capable hardware was available in my test environment)
that links the **verbatim, unmodified** `unmarshal_values()` function
against the real `parson.c` and `base64.cpp`, compiled with the same
toolchain flags and `enclave.config.xml` (`StackMaxSize 0x80000`) as
the real enclave build. This PoC empirically confirms, inside an
actual compiled enclave binary (not just under a userspace
sanitizer):

1. **A real enclave process crash (DoS)** when the unbounded scan
   runs past the last mapped page of enclave memory.
2. **A full, reproducible, end-to-end confidentiality leak**: with a
   precisely aligned malformed-JSON payload, `unmarshal_values()`
   returns success and hands back adjacent enclave stack memory,
   disguised as a legitimate parsed JSON key/value pair, across the
   trusted/untrusted boundary — undermining the core confidentiality
   guarantee SGX exists to provide.

Both outcomes are reachable from the project's own stated threat
model: the host is untrusted, and the enclave is expected to remain
safe even if the surrounding host process is fully compromised.

## Affected component

- Repository: `hyperledger/fabric-private-chaincode`
- Branch/commit analyzed: `main` @ `716cde030b78a9826c822c68bbf63a0c05a4c916`
- File: `ecc_enclave/enclave/shim.cpp`
- Functions: `unmarshal_values()` (line 178), reached via
  `get_public_state_by_partial_composite_key()` (line 245) and
  `get_state_by_partial_composite_key()` (line 216, for the encrypted
  state path — same underlying call)

## Root cause

**Enclave side** (`ecc_enclave/enclave/shim.cpp:178-211`):

```cpp
int unmarshal_values(
    std::map<std::string, std::string>& values, const char* json_bytes, uint32_t json_len)
{
    JSON_Value* root = json_parse_string(json_bytes);   // json_len is never used
    if (json_value_get_type(root) != JSONArray)
    {
        LOG_ERROR("Shim: Cannot parse values");
        return -1;
    }
    ...
```

Called from (`ecc_enclave/enclave/shim.cpp:245-262`):

```cpp
void get_public_state_by_partial_composite_key(
    const char* comp_key, std::map<std::string, std::string>& values, shim_ctx_ptr_t ctx)
{
    uint8_t json[262144];  // 128k needed for 1000 bids
    uint32_t len = 0;

    ocall_get_state_by_partial_composite_key(comp_key, json, sizeof(json), &len, ctx->u_shim_ctx);
    if (len > sizeof(json))
    {
        char s[] = "Enclave: len greater than json buffer size";
        LOG_ERROR("%s", s);
        throw std::runtime_error(s);
    }

    unmarshal_values(values, (const char*)json, len);
}
```

Note the existing check only guards against `len` being **larger**
than the buffer (an overflow on the write side, presumably already
bounded by the ocall marshalling itself). There is no check that
`json[len]` is `'\0'`, and `json_len`/`len` is never used to bound
the subsequent parse.

**Host side, reference implementation**
(`ecc/chaincode/enclave/shim.go:144-171`):

```go
//export get_state_by_partial_composite_key
func get_state_by_partial_composite_key(...) {
    ...
    data := buf.Bytes()  // the actual JSON assembled in Go
    ...
    C._cpy_bytes(values, (*C.uint8_t)(C.CBytes(data)), C.uint32_t(len(data)))
    C._set_int(values_len, C.uint32_t(len(data)))
}
```

The host copies **exactly `len(data)` real bytes** and never appends
a terminator. `values_len` is reported correctly, but the enclave
never uses it to bound the parse. The remainder of the 262144-byte
enclave-side buffer retains whatever was already there.

Since the host is explicitly the untrusted party in FPC's threat
model, an attacker controlling (or having compromised) the host peer
process can trivially return a truncated/malformed JSON payload
through this ocall — e.g. an array with a string value that is
missing its closing quote — which is indistinguishable, at the
function-signature level, from a legitimately truncated message.

`skip_quotes` (`common/json/parson.c:762-778`) itself is correctly
written — it does check for `'\0'` while scanning:

```c
while (**string != '\"') {
    if (**string == '\0') {
        return JSONFailure;
    }
    ...
    SKIP_CHAR(string);
}
```

This is not a logic bug inside parson: `json_parse_string(const char
*string)` is, by design, a classic NUL-terminated-string API, which
is a valid contract for any caller that guarantees the terminator.
The bug is that `fabric-private-chaincode` calls this API at its most
security-sensitive trust boundary (untrusted host → enclave) without
ensuring that precondition holds.

## Proof of Concept

### 1. Userspace / AddressSanitizer confirmation (not SGX)

A harness (`fpc_parson_nullterm_harness.c`) reproduces the buffer
size and fill pattern of the real code, using a heap allocation (for
ASan's heap-buffer-overflow detector) rather than a stack allocation
(the real code uses a fixed-size local array — this harness variant
trades exact storage class for ASan's stronger heap-overflow
detection):

```c
#define FPC_REAL_BUFFER_SIZE 262144  // same size as shim.cpp

char *buf = malloc(FPC_REAL_BUFFER_SIZE);
size_t prefix_len = min(size, FPC_REAL_BUFFER_SIZE);
memcpy(buf, data, prefix_len);              // what a "real" host writes
memset(buf + prefix_len, 'A', FPC_REAL_BUFFER_SIZE - prefix_len);  // no '\0' anywhere -- malicious host
json_parse_string(buf);
```

Input `[{"key":"a","value":"value}]` (an unclosed `"value"` string)
crashes deterministically on the first attempt:

```
==501440==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at 0x7bda8c771800 thread T0
    #0 skip_quotes parson.c
    #1 get_quoted_string parson.c
    #2 parse_string_value parson.c
    #3 parse_value parson.c
    #4 parse_object_value parson.c
    #5 parse_value parson.c
    #6 parse_array_value parson.c
    #7 parse_value parson.c
    #8 json_parse_string
SUMMARY: AddressSanitizer: heap-buffer-overflow parson.c in skip_quotes

0x7bda8c771800 is located 0 bytes after 262144-byte region
```

100% reproducible.

### 2. Real SGX enclave confirmation (simulation mode)

**Environment:** Intel SGX SDK 2.27.100.1 (Ubuntu 22.04/jammy
packages: `libsgx-urts`, `libsgx-launch`, etc.), `SGX_MODE=SIM` (no
SGX-capable hardware was available for this test — noted as a
limitation below). Enclave built with the project's real
`enclave.config.xml` values (`StackMaxSize 0x80000`) and the same
compiler flags used by the real `ecc_enclave` build (`-nostdinc
-fno-builtin -fvisibility=hidden -fpie -fstack-protector`).

`unmarshal_values()` is copied **verbatim** into the PoC enclave
(`Enclave/testleak.cpp`); `parson.c`/`parson.h` and
`base64.cpp`/`base64.h` are the real, unmodified upstream sources.
The vulnerable call site is reproduced exactly:

```cpp
uint8_t json[262144];  // same size, same local/stack storage as shim.cpp
uint32_t len = payload_len < sizeof(json) ? payload_len : (uint32_t)sizeof(json);
memcpy(json, payload, len);
// json[len .. 262143] intentionally left untouched, exactly like the real code
return unmarshal_values(values, (const char*)json, len);
```

Before each call, a wide swath (~384 KB) of enclave stack is dirtied
with a recognizable marker string, standing in for the residue a
long-running enclave accumulates from prior legitimate transactions
(decrypted state values, keys, etc. — precisely the class of data
SGX is meant to keep confidential).

**Result A — real crash confirmed.** Reading forward from the end of
the declared buffer in 256-byte steps:

```
[checkpoint] read OK at json[262144+0]    = 0x00
[checkpoint] read OK at json[262144+256]  = 0xf0
[checkpoint] read OK at json[262144+512]  = 0xcc
[checkpoint] read OK at json[262144+768]  = 0xcc
[checkpoint] read OK at json[262144+1024] = 0xcc
[checkpoint] read OK at json[262144+1280] = 0xcc
timeout: the monitored command dumped core        <- real SIGSEGV, enclave process crash
```

Roughly 1280–1536 bytes past the declared buffer remain mapped and
readable before a genuine page fault crashes the process. Any
malformed input whose unbounded scan does not find a closing quote
or `'\0'` within that window crashes the real enclave process — this
is an empirically confirmed DoS, not an artifact of a sanitizer.

**Result B — leak substrate confirmed.** A direct raw-memory dump of
`json[payload_len .. payload_len+4096)` (the exact region the
vulnerable scan reads over), bypassing the JSON parser entirely,
shows the planted marker present byte-for-byte, within the first
tens of bytes, across four different malformed-JSON payload shapes
(unterminated string value, unterminated key, unterminated number,
minimal unterminated array).

**Result C — full end-to-end leak, reproduced 3/3.** Using a second
marker that includes a self-closing JSON terminator
(`{"key":"LEAKED_TOP_SECRET_ENCLAVE_STATE_...","value":"AAAA"}]`),
the exact offset where a marker cycle begins in the leftover memory
was measured (offset 58) and a payload was crafted to align to it:
`'['` followed by 57 spaces (valid JSON whitespace, 58 bytes total,
no attacker-supplied structural characters beyond `[`). Result,
reproduced across three independent runs:

```
=== [full-leak-attempt] payload = '[' + 57 spaces (58 bytes)
[full-leak-attempt] ECALL OK, unmarshal_status=1
[full-leak-attempt] returned (56 bytes): KV[LEAKED_TOP_SECRET_ENCLAVE_STATE_0123456789abcdef]=[]
```

`unmarshal_status == 1` means `unmarshal_values()` — the real,
unmodified function — considered this a **fully successful parse**,
and the returned key/value pair, which crosses the enclave's trust
boundary back to the untrusted host, literally contains marker text
read from enclave stack memory that the attacker-controlled payload
never wrote.

Full PoC source (`App/App.cpp`, `Enclave/testleak.cpp`,
`Enclave/parson.c`, `Enclave/base64.cpp`, EDL, Makefile, and a full
example run log) is attached / available on request.

## Impact

- **Denial of Service (confirmed):** a malicious or compromised host
  peer can crash the enclave process by returning a malformed/
  truncated JSON payload through the
  `get_state_by_partial_composite_key` /
  `get_public_state_by_partial_composite_key` ocall path. No
  privileged access to enclave internals is required — only the
  ability to control the ocall's return buffer, which is exactly
  what FPC's threat model assumes a compromised host can do.
- **Confidentiality leak (confirmed end-to-end):** adjacent enclave
  stack memory — which in a real, long-running enclave would contain
  residue from prior legitimate transactions (decrypted state
  values, keys) — can be returned to the untrusted host disguised as
  legitimate parsed transaction data, via a payload aligned to the
  surrounding memory layout. This directly undermines the
  confidentiality guarantee that is SGX's and FPC's core value
  proposition.

## Limitations / what is *not* claimed

- Testing was done in **SGX simulation mode**, since no SGX-capable
  hardware was available. Simulation mode uses the same trusted
  runtime (tRTS) and stack-management code as hardware mode, so the
  memory-safety behavior should be representative, but this has not
  been verified against real hardware (EPC-backed) enclaves.
- The "secret" recovered in the PoC is a synthetic marker planted by
  the PoC itself, not a real value extracted from a live chaincode
  deployment. This demonstrates the leak *mechanism* end-to-end; it
  does not demonstrate extraction of a specific real-world secret
  from a production deployment.
- The alignment offset used in Result C was computed with white-box
  access to enclave memory (a direct diagnostic dump). A real
  attacker without that access would need to determine a working
  offset through blind means (e.g. repeated queries, observing
  crash/no-crash or response-length signals) — this was not
  attempted and its practical difficulty against a real deployment
  is not characterized here.
- `skip_quotes` is one of several character-by-character scanning
  functions in `parson.c` that rely on encountering either a target
  delimiter or `'\0'` (e.g. number parsing, whitespace skipping).
  Other call sites were not individually audited and may share the
  same class of issue.

## Suggested fix

The buffer size and the actual written length (`len`/`json_len`) are
both already available at the call site. The minimal fix is to
enforce the NUL-terminated-string precondition explicitly before
calling `json_parse_string()`, e.g. in
`get_public_state_by_partial_composite_key()`:

```cpp
if (len >= sizeof(json))
{
    // existing "len > sizeof(json)" check already covers len > sizeof(json);
    // this also rejects len == sizeof(json), which leaves no room for a terminator
    throw std::runtime_error("Enclave: len leaves no room for NUL terminator");
}
json[len] = '\0';
unmarshal_values(values, (const char*)json, len);
```

A more robust long-term fix would be to stop relying on parson's
NUL-terminated-string API at this trust boundary entirely — either by
patching parson's scan functions to take and respect an explicit
buffer-length bound, or switching to a length-bounded JSON parser for
any input that originates from the untrusted host.

## Reproduction

I'm happy to provide the complete PoC (enclave + app source, Makefile,
and full run logs) in whatever form is most convenient for your
process — attached to this report, or as a link to a private
repository, whichever you prefer.

Please let me know if you'd like any additional detail, and how
you'd like to handle disclosure timing/credit.
