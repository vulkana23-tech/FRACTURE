"""Tests deterministicos, sin red -- parsean fragmentos de codigo
reales (extraidos/adaptados de los diffs reales ya investigados a
mano) directo en memoria via tree-sitter."""

from ast_function_boundary import (
    changed_line_numbers_post_patch,
    enclosing_function_signatures,
    language_for_path,
)


# Version simplificada pero fiel a la firma real de la clase
# `jsg::Function` (cloudflare/workerd) -- el caso REAL que motivo este
# modulo: `git show` anclaba el contexto del hunk a `class
# Function<Ret(Args...)> {` en vez de a `Ret operator()(jsg::Lock& jsl,
# Args... args)`, porque el metodo esta definido inline dentro del
# cuerpo de una clase template en un header.
_WORKERD_STYLE_HEADER = b"""namespace jsg {
template <typename Ret, typename... Args>
class Function<Ret(Args...)> {
public:
  Ret operator()(jsg::Lock& jsl, Args... args) {
    KJ_IF_MAYBE(impl, maybeImpl) {
      return (*impl)(jsl, kj::fwd<Args>(args)...);
    }
    JSG_FAIL_REQUIRE(TypeError, "Function was destroyed");
  }
private:
  kj::Maybe<Impl> maybeImpl;
};
}  // namespace jsg
"""


def test_language_for_path_maps_known_extensions():
    assert language_for_path("src/workerd/jsg/function.h") == "cpp"
    assert language_for_path("gossip/state/state.go") == "go"
    assert language_for_path("fuzz/fuzz_targets/read_many.rs") == "rust"
    assert language_for_path("ClientIdentity.java") == "java"
    assert language_for_path("README.md") is None


def test_enclosing_function_finds_real_method_not_containing_template_class():
    # Linea 9 real: "JSG_FAIL_REQUIRE(TypeError, ...)" -- dentro del
    # metodo, no de la clase.
    sigs = enclosing_function_signatures("jsg/function.h", _WORKERD_STYLE_HEADER, {9})
    assert len(sigs) == 1
    assert "operator()" in sigs[0]
    assert "jsg::Lock& jsl" in sigs[0]
    assert "class Function" not in sigs[0]  # el bug real que esto corrige


def test_enclosing_function_includes_outer_real_method_despite_kj_macro_confusing_parser():
    # Patron REAL de cloudflare/workerd/src/workerd/jsg/function.h (el
    # commit 644f2c1598 real): los macros KJ_SWITCH_ONEOF/KJ_CASE_ONEOF
    # (forma "NOMBRE(args) { ... }") enganan a tree-sitter-cpp sin
    # preprocesar -- los parsea como definiciones de funcion ANIDADAS
    # dentro del operator() real. Quedarse solo con el nodo MAS CHICO
    # que contiene la linea devolvia el macro (ruido), perdiendo la
    # firma real. Se corrigio devolviendo TODA la cadena de ancestros,
    # no solo el mas especifico -- confirmado en vivo contra el
    # archivo real del repo (ver targets/README.md).
    src = b"""namespace jsg {
template <typename Ret, typename... Args>
class Function<Ret(Args...)> {
public:
  Ret operator()(jsg::Lock& jsl, Args... args) {
    KJ_SWITCH_ONEOF(impl) {
      KJ_CASE_ONEOF(native, Ref<NativeFunction>) {
        auto ref = native.addRef();
        return (*ref)(jsl, kj::fwd<Args>(args)...);
      }
    }
  }
};
}  // namespace jsg
"""
    # Linea real cambiada: "auto ref = native.addRef();"
    sigs = enclosing_function_signatures("jsg/function.h", src, {8})
    assert any("operator()" in s and "jsg::Lock& jsl" in s for s in sigs), (
        f"la firma real de operator() deberia estar en la cadena de ancestros, se encontro: {sigs}"
    )


def test_enclosing_function_returns_empty_for_line_outside_any_function():
    # Linea 11 real: "private:" -- dentro de la clase pero fuera de
    # cualquier metodo.
    sigs = enclosing_function_signatures("jsg/function.h", _WORKERD_STYLE_HEADER, {11})
    assert sigs == []


def test_enclosing_function_unsupported_language_returns_empty_not_raises():
    assert enclosing_function_signatures("README.md", b"# hola", {1}) == []


def test_enclosing_function_go_method_with_receiver():
    src = b"""package chaincode

type Token struct{}

func (t *Token) sub(balance int, quantity int) (int, error) {
	if balance < quantity {
		return 0, errors.New("insufficient balance")
	}
	return balance - quantity, nil
}
"""
    sigs = enclosing_function_signatures("token_erc20.go", src, {7})
    assert len(sigs) == 1
    assert "func (t *Token) sub(balance int, quantity int)" in sigs[0]


def test_changed_line_numbers_post_patch_real_hunk_format():
    diff = (
        "@@ -7,6 +7,8 @@ class Function<Ret(Args...)> {\n"
        "   Ret operator()(jsg::Lock& jsl, Args... args) {\n"
        "     KJ_IF_MAYBE(impl, maybeImpl) {\n"
        "       return (*impl)(jsl, kj::fwd<Args>(args)...);\n"
        "+      // nueva linea real\n"
        "     }\n"
        "+    JSG_FAIL_REQUIRE(TypeError, \"Function was destroyed\");\n"
        "   }\n"
    )
    assert changed_line_numbers_post_patch(diff) == {7, 8, 9, 10, 11, 12, 13, 14}


def test_changed_line_numbers_post_patch_pure_deletion_hunk_ignored():
    # "+0" del lado post -- borrado puro, no hay linea nueva real para anclar.
    diff = "@@ -10,3 +9,0 @@ void foo() {\n-  old_line();\n"
    assert changed_line_numbers_post_patch(diff) == set()
