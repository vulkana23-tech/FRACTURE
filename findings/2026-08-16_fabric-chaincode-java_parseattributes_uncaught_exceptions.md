# fabric-chaincode-java: excepciones sin capturar reales en `ClientIdentity.parseAttributes` (Jazzer, severidad media)

**Estado**: confirmado en vivo (Jazzer/JVM, no supuesto). Severidad
media -- excepción sin capturar que rompe el manejo de errores
declarado de la función, no corrupción de memoria (Java es
memory-safe).

## Cómo se encontró

Primer target JVM real de este proyecto (motivado por la ausencia de
engine JVM documentada como pendiente en `orchestrator/README.md`).
`ClientIdentity` (`fabric-chaincode-java/fabric-chaincode-shim`) es el
equivalente Java del mismo patrón real ya fuzzeado en este proyecto en
Go (`attrmgr.GetAttributesFromCert`/`GetAttributesFromIdemix`,
`fabric-chaincode-go`) y C++ (`unmarshal_values`,
`fabric-private-chaincode`): atributos de identidad codificados como
JSON dentro de una extensión de certificado X.509, parseados por
código propio del proyecto en 3 lenguajes distintos, cada uno con su
propia implementación independiente.

`parseAttributes(byte[] extensionValue)` es un método **privado** de
instancia. Se construyó un harness de Jazzer
(`orchestrator/fuzz_harnesses/` -- ver `FuzzParseAttributes.java`,
target real en `build/jvm_targets/fabric_chaincode_java/`) que crea
una instancia de `ClientIdentity` **sin correr su constructor real**
(vía `sun.reflect.ReflectionFactory`, técnica estándar de Java para
bypass de constructor -- verificado que es seguro porque
`parseAttributes` no toca ningún campo de instancia, todos son
`private final` sin usar en el método) y lo invoca directo por
reflection con bytes del fuzzer.

## El bug real

`ClientIdentity.parseAttributes` declara `throws IOException` y atrapa
explícitamente `JSONException`, pero **no atrapa las excepciones reales
que BouncyCastle lanza sobre ASN.1 malformado**, que son
`IllegalArgumentException`/`IllegalStateException` (unchecked, se
propagan solas). Confirmado en vivo: Jazzer encontró la primera
excepción real en **menos de 1 segundo** de fuzzing, y con una campaña
de 15-20s corriendo 18 workers en paralelo encontró **al menos 3
tipos distintos**:

- `IllegalArgumentException: invalid pad bits detected`
  (`ASN1BitString.createPrimitive`)
- `IllegalArgumentException: truncated BIT STRING detected`
  (`ASN1BitString.createPrimitive`, vía `ASN1StreamParser`)
- `IllegalStateException: object implicit - explicit expected.`
  (`ASN1TaggedObject.getExplicitBaseObject`, vía `ASN1External`)

Todos alcanzables con el mismo stack real:
`ASN1InputStream.readObject → ClientIdentity.parseAttributes`.

## Reachability real

`extensionValue` viene de `cert.getExtensionValue(FABRIC_CERT_ATTR_OID)`
en el constructor real de `ClientIdentity`, sobre un `X509Certificate`
extraído de un `SignedIdentity` protobuf que llega de
`stub.getCreator()` -- la identidad de quien invoca la transacción. Un
certificado emitido por una MSP (Membership Service Provider) del
canal Fabric con una extensión ASN.1 malformada en ese OID específico
haría que **cualquier chaincode Java que llame `new ClientIdentity(stub)`
o cualquiera de sus métodos** (el propio código de aplicación del
chaincode, no solo el shim) reciba una excepción no declarada/no
documentada -- rompe el contrato de la función tal cual está
documentado (`@throws IOException`, nada más).

## Por qué severidad media, no alta

- Java es memory-safe -- no hay corrupción de memoria posible acá,
  a diferencia de los hermanos C++ (`unmarshal_values`) y Rust de este
  proyecto.
- Es real DoS-class: una excepción no capturada que se propaga fuera
  de una función de parseo puede romper la ejecución del chaincode
  (dependiendo de cómo el framework de chaincode real maneje
  excepciones no capturadas en la capa de invocación -- no se
  investigó ese comportamiento específico en esta ronda).
- No se reportó todavía al proyecto real (fabric-chaincode-java) --
  este documento es el registro interno del hallazgo.

## Nota técnica: 2 bugs propios encontrados construyendo el pipeline

1. `run_jvm_fuzzer.py` pasaba `--artifact_prefix` (doble guion) en vez
   de `-artifact_prefix` (un guion, formato real de libFuzzer que
   Jazzer pasa por debajo) -- Jazzer fallaba con "Unknown arguments"
   y la corrida nunca arrancaba de verdad. Quedó escondido en el
   primer smoke test porque ya había un crash viejo en `artifact_dir`
   de la investigación manual, así que "crashes=1" parecía éxito real.
2. Jazzer loguea el stack trace de CUALQUIER excepción que observa vía
   su instrumentación de bytecode, incluidas las que el harness ya
   atrapa como esperadas (`org.json.JSONException`, decenas de veces
   por corrida) -- escanear el texto completo del output mezclaba esos
   frames de ruido con los del crash real. Corregido acotando la
   extracción de frames a la ventana real entre `== Java Exception:` y
   `DEDUP_TOKEN:` (el delimitador real que Jazzer imprime por cada
   bloque de excepción).

Ambos con test de regresión real -- ver `triage/README.md` y
`orchestrator/README.md`.
