#!/usr/bin/env bash
# Receta real de build para bits_t::convert() (coinbase/cb-mpc) --
# variante/regresion sobre el fix real ec9a818f74 ("fix: Prevent
# buffer overflow in converter (#54)"). Encontrado via
# targets/find_patch_directed_candidates.py, harness escrito a mano
# (contexto ya investigado a fondo, generar con IA hubiera sido mas
# lento que escribirlo directo).
#
# Subconjunto real minimo de src/cbmpc/core/ -- confirmado que alcanza
# corriendolo en vivo (sin necesitar el resto de la libreria de
# criptografia real de cb-mpc).
#
# Uso: correr desde un directorio de trabajo vacio.
#   FRACTURE_CBMPC_BUILD_DIR=/algun/dir bash cbmpc_bits_convert_build.sh
set -euo pipefail

BUILD_DIR="${FRACTURE_CBMPC_BUILD_DIR:-./cbmpc_build}"
HARNESS_SRC="$(dirname "$(readlink -f "$0")")/cbmpc_bits_convert_harness.cpp"
TARGET_DIR="/opt/fracture/build/cbmpc_bits_convert"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -d repo ]; then
	echo "Clonando coinbase/cb-mpc..."
	git clone --depth 1 https://github.com/coinbase/cb-mpc repo
fi

mkdir -p "$TARGET_DIR/corpus" "$TARGET_DIR/crashes"

clang++ -fsanitize=fuzzer,address -g -O1 -std=c++17 \
	-Irepo/include -Irepo/include-internal \
	"$HARNESS_SRC" \
	repo/src/cbmpc/core/buf.cpp repo/src/cbmpc/core/buf128.cpp repo/src/cbmpc/core/buf256.cpp \
	repo/src/cbmpc/core/convert.cpp repo/src/cbmpc/core/error.cpp repo/src/cbmpc/core/strext.cpp \
	-o "$TARGET_DIR/fuzz_bits_convert"

echo "Binario real: $TARGET_DIR/fuzz_bits_convert"
