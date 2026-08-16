# fabric-chaincode-java: NullPointerException real en `JSONTransactionSerializer.convert` (Jazzer, severidad media)

**Estado**: confirmado en vivo (Jazzer/JVM). Severidad media -- excepción
sin capturar, no corrupción de memoria (Java es memory-safe).

## Cómo se encontró

Segundo target JVM real de este proyecto, y primer target generado
**automáticamente** con `harness_gen/generate_jvm_harness.py` (el
primero, `ClientIdentity.parseAttributes`, se escribió a mano -- ver
`findings/2026-08-16_fabric-chaincode-java_parseattributes_uncaught_exceptions.md`).
`JSONTransactionSerializer.fromBuffer(byte[], TypeSchema)` es un
método **público** que deserializa los argumentos reales de una
invocación de transacción de chaincode -- superficie directamente
alcanzable desde una transacción real, sin necesitar reflection para
llegar a ella (a diferencia de `parseAttributes`).

## El bug real

```
java.lang.NullPointerException: Cannot invoke "String.lastIndexOf(int)"
because "<local7>" is null
	at org.hyperledger.fabric.contract.execution.JSONTransactionSerializer.convert(JSONTransactionSerializer.java:237)
	at org.hyperledger.fabric.contract.execution.JSONTransactionSerializer.fromBuffer(JSONTransactionSerializer.java:157)
```

`fromBuffer` no captura `NullPointerException` -- solo bytes
específicos (probablemente un valor JSON `null` explícito, o un tipo
inesperado, donde el código real de `convert()` espera un `String` no
nulo antes de llamar `.lastIndexOf(int)` sobre él) hacen que la
deserialización de un argumento de transacción real crashee con una
excepción no declarada.

## Reachability real

`fromBuffer` es el método real que el shim de fabric-chaincode-java
usa para convertir los argumentos crudos de una invocación de
transacción (bytes que vienen de un cliente, sobre gRPC) al tipo real
que espera la función del chaincode. Cualquier chaincode Java que use
la serialización JSON default recibe este código en el camino crítico
de CADA invocación de transacción -- un cliente que arme una
transacción con un argumento JSON malformado de la forma específica
correcta puede crashear el manejo de esa transacción.

## Por qué severidad media, no alta

- Java es memory-safe -- no hay corrupción de memoria posible.
- Real DoS-class: una excepción no capturada en el camino de
  invocación de transacciones puede afectar la disponibilidad del
  chaincode (comportamiento exacto del framework ante esto no se
  investigó en esta ronda).
- No se reportó todavía al proyecto real -- este documento es el
  registro interno del hallazgo.

## Nota real sobre el generador

Este harness es el primero validado por
`harness_gen/generate_jvm_harness.py` (nuevo esta ronda) -- encontró
este bug real en el PRIMER intento de generación después de corregir 2
problemas reales encontrados generando el harness anterior (ver
`harness_gen/README.md`): el modelo eligió innecesariamente el patrón
de reflection para un método que es público (regla del prompt
reforzada para preferir siempre la llamada directa cuando el método es
público), y adivinó un método (`TypeSchema.setType(...)`) que no
existe en la API real (regla agregada: nunca adivinar métodos de una
clase cuyo código real no se le mostró al modelo).
