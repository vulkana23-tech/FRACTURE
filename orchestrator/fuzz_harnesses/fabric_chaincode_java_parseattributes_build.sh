#!/usr/bin/env bash
# Receta real de build para el target JVM de ClientIdentity.parseAttributes()
# (fabric-chaincode-java). build/ esta gitignoreado (igual que los demas
# targets de este proyecto) -- este script reconstruye
# build/jvm_targets/fabric_chaincode_java/ desde cero si hace falta.
#
# Requiere: JDK 21 (openjdk-21-jdk-headless), jazzer standalone 0.30.0+
# en PATH (ver https://github.com/CodeIntelligenceTesting/jazzer/releases,
# jazzer-linux-x86-64.tar.gz).
#
# Uso: correr desde un directorio de trabajo vacio.
#   FRACTURE_FCJ_BUILD_DIR=/algun/dir bash fabric_chaincode_java_parseattributes_build.sh
set -euo pipefail

BUILD_DIR="${FRACTURE_FCJ_BUILD_DIR:-./fcj_build}"
HARNESS_SRC="$(dirname "$(readlink -f "$0")")/fabric_chaincode_java_parseattributes_harness.java"
TARGET_DIR="/opt/fracture/build/jvm_targets/fabric_chaincode_java"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -d repo ]; then
	echo "Clonando fabric-chaincode-java..."
	git clone --depth 1 https://github.com/hyperledger/fabric-chaincode-java repo
fi

# Init script de Gradle real que imprime el classpath de runtime real
# del modulo fabric-chaincode-shim -- forma confiable de extraer los
# jars de dependencias reales sin adivinar coordenadas Maven a mano.
cat > print_classpath.gradle <<'EOF'
allprojects {
    tasks.register("printRuntimeClasspath") {
        doLast {
            if (project.path == ":fabric-chaincode-shim") {
                println "CLASSPATH_START"
                println sourceSets.main.runtimeClasspath.asPath
                println "CLASSPATH_END"
            }
        }
    }
}
EOF

cd repo
CLASSPATH=$(./gradlew -I ../print_classpath.gradle :fabric-chaincode-shim:compileJava :fabric-chaincode-shim:printRuntimeClasspath -q \
	| sed -n '/CLASSPATH_START/,/CLASSPATH_END/p' | sed '1d;$d')
cd ..

mkdir -p "$TARGET_DIR/lib" "$TARGET_DIR/classes" "$TARGET_DIR/corpus" "$TARGET_DIR/crashes"

# Solo los .jar reales (las clases propias del modulo se copian aparte,
# no vienen como .jar) -- confirmado en vivo que la JVM carga clases
# perezosamente, asi que un classpath minimo (solo lo que
# ClientIdentity/parseAttributes realmente importa) alcanza sin
# arrastrar toda la closure transitiva (grpc/opentelemetry/etc, que
# fabric-chaincode-shim si necesita para OTRAS partes no relacionadas).
echo "$CLASSPATH" | tr ':' '\n' | grep '\.jar$' | while read -r jar; do
	cp -f "$jar" "$TARGET_DIR/lib/"
done

cp -r repo/fabric-chaincode-shim/build/classes/java/main/. "$TARGET_DIR/classes/"
cp -r repo/fabric-chaincode-shim/build/resources/main/. "$TARGET_DIR/classes/" 2>/dev/null || true

cp "$HARNESS_SRC" "$TARGET_DIR/FuzzParseAttributes.java"
FULL_CP=".:$(find "$TARGET_DIR/lib" -name '*.jar' | tr '\n' ':')${TARGET_DIR}/classes"
javac -cp "$FULL_CP" -d "$TARGET_DIR/classes" "$TARGET_DIR/FuzzParseAttributes.java"

echo "Target real: $TARGET_DIR (classes/ + lib/*.jar listos para run_jvm_fuzzer.py)"
