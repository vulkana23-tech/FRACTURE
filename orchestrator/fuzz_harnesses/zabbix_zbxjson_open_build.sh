#!/usr/bin/env bash
# Receta real de compilacion para el harness de zbx_json_open() (zabbix).
# No es parte del build oficial de Zabbix (autotools/./configure) --
# aisla solo la libreria de parseo JSON (src/libs/zbxjson) + sus
# dependencias reales minimas (zbxstr, zbxalgo, zbxcommon, zbxnum),
# sin levantar servidor/DB/red de Zabbix.
#
# Uso: correr desde un directorio de trabajo vacio.
#   FRACTURE_ZABBIX_BUILD_DIR=/algun/dir bash zabbix_zbxjson_open_build.sh
set -euo pipefail

BUILD_DIR="${FRACTURE_ZABBIX_BUILD_DIR:-./zabbix_zbxjson_build}"
HARNESS_SRC="$(dirname "$(readlink -f "$0")")/zabbix_zbxjson_open_harness.c"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -d src ]; then
	echo "Clonando zabbix/zabbix (sparse, solo include/ + libs necesarias)..."
	rm -rf .zabbix_sparse_tmp
	git clone --filter=blob:none --sparse --depth 1 \
		https://github.com/zabbix/zabbix.git .zabbix_sparse_tmp
	git -C .zabbix_sparse_tmp sparse-checkout set \
		include src/libs/zbxjson src/libs/zbxalgo src/libs/zbxstr \
		src/libs/zbxnum src/libs/zbxcommon
	cp -r .zabbix_sparse_tmp/include .
	cp -r .zabbix_sparse_tmp/src .
	rm -rf .zabbix_sparse_tmp
	find include src -name "Makefile.am" -delete
fi

# config.h minimo hecho a mano (NO generado por ./configure real) --
# solo declara HAVE_*_H para headers POSIX/glibc que genuinamente
# existen en un Linux moderno, replicando lo que autoconf detectaria
# en este mismo tipo de sistema.
if [ ! -f config.h ]; then
	cp "$(dirname "$(readlink -f "$0")")/zabbix_zbxjson_open_config.h" config.h
fi

cp "$HARNESS_SRC" harness.c

clang -fsanitize=fuzzer,address \
	-I. -Iinclude -Iinclude/common \
	harness.c \
	src/libs/zbxjson/json.c \
	src/libs/zbxjson/json_parser.c \
	src/libs/zbxjson/jsonobj.c \
	src/libs/zbxstr/str.c \
	src/libs/zbxalgo/*.c \
	src/libs/zbxcommon/common_log.c \
	src/libs/zbxcommon/common_str.c \
	src/libs/zbxcommon/misc.c \
	src/libs/zbxcommon/components_strings_representations.c \
	src/libs/zbxnum/num.c \
	-o fuzz_zbxjson

echo "Binario real: $BUILD_DIR/fuzz_zbxjson"
