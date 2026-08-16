#!/usr/bin/env bash
# Receta real de build para cJSON_SetNumberHelper (DaveGamble/cJSON) --
# candidato encontrado via targets/patch_directed_c_harness.py (primer
# pipeline C/C++ dirigido por parche de este proyecto, ver
# targets/README.md), harness generado y validado por IA (Ollama) en
# el primer intento real.
#
# Uso: correr desde un directorio de trabajo vacio.
#   FRACTURE_CJSON_BUILD_DIR=/algun/dir bash cjson_setnumberhelper_build.sh
set -euo pipefail

BUILD_DIR="${FRACTURE_CJSON_BUILD_DIR:-./cjson_build}"
HARNESS_SRC="$(dirname "$(readlink -f "$0")")/cjson_setnumberhelper_harness.c"
TARGET_DIR="/opt/fracture/build/cjson_setnumberhelper"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -d repo ]; then
	echo "Clonando DaveGamble/cJSON..."
	git clone --depth 1 https://github.com/DaveGamble/cJSON repo
fi

mkdir -p "$TARGET_DIR/corpus" "$TARGET_DIR/crashes"

clang -fsanitize=fuzzer,address -g -O1 \
	-Irepo \
	"$HARNESS_SRC" repo/cJSON.c \
	-o "$TARGET_DIR/fuzz_setnumberhelper"

echo "Binario real: $TARGET_DIR/fuzz_setnumberhelper"
