"""Tests contra fixtures REALES -- cada .txt en testdata/ es la salida
cruda de un binario de verdad compilado con clang -fsanitize=... (o
rustc para el panic de Rust) y corrido hasta crashear, no texto escrito
a mano. Ver triage/README.md para como se generaron."""

import os

from classify_sanitizer_crash import extract_crash_info

_TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


def _load(fname: str) -> str:
    with open(os.path.join(_TESTDATA, fname), "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def test_asan_heap_buffer_overflow_is_high_severity():
    info = extract_crash_info(_load("asan_heap_buffer_overflow_real.txt"))
    assert info is not None
    assert info["sanitizer"] == "AddressSanitizer"
    assert info["bug_type"] == "heap-buffer-overflow"
    assert info["severity"] == "high"
    assert info["top_frame"] is not None
    assert "main" in info["top_frame"]
    assert "asan_heap_overflow.c:8" in info["top_frame"]
    # Nunca un frame de plomeria del sanitizer/libc como top_frame.
    assert "__asan_" not in info["top_frame"]
    assert "vsnprintf" not in info["top_frame"]


def test_asan_use_after_free_is_high_severity_and_skips_interceptor_frames():
    info = extract_crash_info(_load("asan_use_after_free_real.txt"))
    assert info is not None
    assert info["bug_type"] == "heap-use-after-free"
    assert info["severity"] == "high"
    # printf_common/printf son plomeria del interceptor de ASAN -- el
    # primer frame real tiene que ser `main`, no eso.
    assert info["top_frame"].startswith("main")


def test_ubsan_signed_overflow_is_needs_review_not_high():
    info = extract_crash_info(_load("ubsan_signed_overflow_real.txt"))
    assert info is not None
    assert info["sanitizer"] == "UndefinedBehaviorSanitizer"
    assert "overflow" in info["bug_type"].lower()
    # UB real, pero no se puede afirmar explotabilidad solo con esto --
    # a diferencia de heap-buffer-overflow, que si es señal fuerte.
    assert info["severity"] == "needs_review"


def test_rust_panic_index_out_of_bounds_is_high_severity():
    info = extract_crash_info(_load("rust_panic_index_oob_real.txt"))
    assert info is not None
    assert info["sanitizer"] is None
    assert info["bug_type"] == "rust-panic"
    assert "index out of bounds" in info["message"]
    assert info["severity"] == "high"
    # core::panicking/__rustc:: son plomeria interna -- el primer frame
    # real tiene que ser la funcion del propio target.
    assert "parse_len_prefixed" in info["top_frame"]
    assert "core::panicking" not in info["top_frame"]
    joined = " ".join(info["target_frames"])
    assert "rust_panic::main" in joined


def test_controlled_abort_without_returncode_hint_is_indistinguishable_from_clean():
    # Sin el returncode real, un abort() que no imprime nada reconocible
    # (el texto "Aborted (core dumped)" es del job control de bash, NO
    # esta en lo que subprocess.run() captura de verdad -- confirmado
    # generando este fixture con `> archivo 2>&1` real) es indistinguible
    # de una corrida limpia con solo el texto.
    info = extract_crash_info(_load("controlled_abort_no_sanitizer_real.txt"))
    assert info is None


def test_controlled_abort_with_returncode_hint_is_needs_review_not_high():
    # 134 = 128 + SIGABRT(6), el exit code real que devolvio el binario
    # de prueba (confirmado en vivo, no supuesto).
    info = extract_crash_info(_load("controlled_abort_no_sanitizer_real.txt"), returncode=134)
    assert info is not None
    # Sin ERROR: AddressSanitizer/UBSAN/panic real -- solo un abort()
    # explicito del propio programa, mismo criterio que un panic() con
    # mensaje propio en classify_go_panic.py: asercion intencional, no
    # necesariamente un bug de memoria.
    assert info["sanitizer"] is None
    assert info["severity"] == "needs_review"


def test_lsan_real_leak_is_low_severity():
    # Fixture real: leak real y confirmado en produccion (2026-08-15,
    # ver findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md)
    # -- no un caso sintetico, es el LeakSanitizer real de correr
    # fuzz_unmarshal_values contra `[{"key":"a"}]`.
    info = extract_crash_info(_load("lsan_unmarshal_values_leak_real.txt"))
    assert info is not None
    assert info["sanitizer"] == "LeakSanitizer"
    assert info["bug_type"] == "memory-leak"
    # Leak real, pero no corrupcion de memoria -- severidad baja, no alta.
    assert info["severity"] == "low"
    assert "json_object_init" in info["top_frame"]


def test_msan_real_uninitialized_use_is_detected():
    # Regresion real del bug encontrado armando ESTE fixture
    # (2026-08-15): MemorySanitizer imprime "WARNING: MemorySanitizer:"
    # por default, NUNCA "ERROR:" (confirmado ademas que
    # MSAN_OPTIONS=halt_on_error=1 no cambia el prefijo) -- el regex
    # viejo (solo "ERROR:") perdia CUALQUIER hallazgo real de MSan en
    # silencio. Fixture real: uso de memoria sin inicializar real en
    # base64_decode (char_array_4[1] nunca asignado antes de leerse
    # con un base64 de 1 caracter sin padding, "A") -- el mismo bug
    # anotado a mano leyendo el codigo en
    # findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md,
    # confirmado en vivo con -fsanitize=memory real.
    info = extract_crash_info(_load("msan_base64_decode_uninitialized_real.txt"))
    assert info is not None
    assert info["sanitizer"] == "MemorySanitizer"
    assert info["bug_type"] == "use-of-uninitialized-value"
    assert "base64_decode" in info["top_frame"]


def test_returns_none_for_clean_output():
    clean = "running 1 test\ntest fuzz_target::run ... ok\n\ntest result: ok. 1 passed\n"
    assert extract_crash_info(clean) is None


def test_stack_hash_is_deterministic_and_ignores_addresses():
    fixture = _load("asan_heap_buffer_overflow_real.txt")
    info1 = extract_crash_info(fixture)
    # Mismo bug, direcciones de memoria distintas (simula ASLR entre
    # corridas) -- el hash de dedup NO puede cambiar por esto solo.
    fixture_diff_addresses = fixture.replace("0x502000000020", "0x999999999999")
    info2 = extract_crash_info(fixture_diff_addresses)
    assert info1["stack_hash"] == info2["stack_hash"]


def test_different_bug_types_get_different_hashes():
    hbo = extract_crash_info(_load("asan_heap_buffer_overflow_real.txt"))
    uaf = extract_crash_info(_load("asan_use_after_free_real.txt"))
    assert hbo["stack_hash"] != uaf["stack_hash"]


def test_jazzer_java_exception_is_real_and_medium_severity():
    # Fixture real: crash real encontrado con Jazzer en el primer
    # target JVM de este proyecto (fabric-chaincode-java, ver
    # findings/2026-08-16_fabric-chaincode-java_parseattributes_uncaught_exception.md).
    # Java es memory-safe -- nunca "high" (eso es para corrupcion de
    # memoria real en C/Rust), pero SI es un bug de robustez real
    # (excepcion no declarada que la funcion de parseo no atrapa).
    info = extract_crash_info(_load("jazzer_illegalargument_asn1_real.txt"))
    assert info is not None
    assert info["sanitizer"] is None
    assert info["bug_type"] == "java-exception:java.lang.IllegalArgumentException"
    assert info["severity"] == "medium"
    # ClientIdentity.parseAttributes tiene que quedar en los frames
    # reales -- es el codigo real del target, no plomeria del JDK.
    joined = " ".join(info["target_frames"])
    assert "ClientIdentity.parseAttributes" in joined
    # java.base/jdk.internal.reflect es plomeria del JDK -- nunca top_frame.
    assert "jdk.internal.reflect" not in info["top_frame"]


def test_jazzer_frames_scoped_to_real_crash_not_mixed_with_handled_exception_noise():
    # Regresion real (2026-08-16, corrida real con 18 workers de Jazzer
    # en paralelo): Jazzer loguea el stack trace de CUALQUIER excepcion
    # que observa via instrumentacion, incluidas las que el harness ya
    # atrapa como esperadas (org.json.JSONException, muchas veces por
    # corrida) -- sin acotar por "DEDUP_TOKEN:", esos frames de ruido
    # se mezclaban con los del crash real que si se propago.
    noisy_text = (
        "\tat org.json.JSONTokener.syntaxError(JSONTokener.java:581)\n"
        "\tat org.json.JSONObject.<init>(JSONObject.java:221)\n"
        "\n"
        "== Java Exception: java.lang.IllegalArgumentException: invalid pad bits detected\n"
        "\tat org.bouncycastle.asn1.ASN1BitString.createPrimitive(Unknown Source)\n"
        "\tat org.hyperledger.fabric.contract.ClientIdentity.parseAttributes(ClientIdentity.java:111)\n"
        "DEDUP_TOKEN: abc123\n"
        "== libFuzzer crashing input ==\n"
    )
    info = extract_crash_info(noisy_text)
    assert info is not None
    joined = " ".join(info["target_frames"])
    assert "JSONTokener" not in joined
    assert "JSONObject" not in joined
    assert "ClientIdentity.parseAttributes" in joined
