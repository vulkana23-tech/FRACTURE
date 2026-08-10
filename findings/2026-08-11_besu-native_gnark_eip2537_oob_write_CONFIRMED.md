# CONFIRMADO: heap-buffer-overflow de ESCRITURA real en los wrappers Go/cgo de gnark-jni (besu-native) -- output buffer nunca validado

**Estado: bug de memoria real y demostrado empíricamente (repro determinístico,
corrupción de heap confirmada con un canary real, glibc detectó la
corrupción y abortó al liberar memoria). Reachability desde el precompilado
EVM real de Besu verificada y descartada HOY -- el único caller *interno*
de Besu (`AbstractBLS12PrecompiledContract`) siempre reserva el tamaño
correcto. PERO: los métodos nativos de EIP-2537 están declarados
`public static native` en Java (a diferencia de los de EIP-196, que son
`private` y sí tienen un guardián explícito -- ver sección de
comparación) -- cualquier consumidor externo de `besu-native` como
librería puede llamarlos directo, hoy, sin ningún refactor de por medio.
NO reportado todavía.**

## Actualización: comparación directa con EIP-196 en el mismo repo -- la severidad real es mayor de lo que pensé al principio

Los propios autores de `besu-native` **ya conocen exactamente esta clase
de riesgo** -- lo documentaron explícitamente en `LibGnarkEIP196.java`:

```java
/**
 * SAFETY: This method validates output buffer size before calling native code to prevent JVM crashes from buffer overflows.
 * The native methods use JNA direct mapping without bounds checking.
 * ...
 */
public static int eip196_perform_operation(byte op, byte[] i, int i_len, byte[] output) {
    ...
    if (output.length < EIP196_PREALLOCATE_FOR_RESULT_BYTES) {
      return EIP196_ERR_CODE_INVALID_OUTPUT_LENGTH;   // <- chequeo real, del lado Java
    }
    ret = eip196altbn128G1Add(i, output, i_len);
    ...
}

private static native int eip196altbn128G1Add(...);   // <- PRIVATE, solo alcanzable via el guardian de arriba
```

`LibGnarkEIP196.java` marca los 3 métodos nativos como **`private`** y
los enruta TODOS a través de `eip196_perform_operation`, que sí valida
`output.length` antes de llamar. Comentario explícito en el código:
"Assumes output length bounds are already checked, otherwise can lead
to JVM crash".

`LibGnarkEIP2537.java`, en cambio, declara los 11 métodos nativos
(incluidas las 6 funciones vulnerables de este finding) como
**`public static native`**:

```java
public static native int eip2537blsG1Add(byte[] input, byte[] output, byte[] error, int inputSize, int output_len, int err_len);
```

No hay ningún guardián equivalente -- `eip2537_perform_operation` existe
como conveniencia, pero **nada impide que cualquier código Java con
`besu-native` en el classpath llame `LibGnarkEIP2537.eip2537blsG1Add`
directo**, sin pasar por ninguna validación, exactamente el escenario
que los mismos autores ya identificaron como peligroso y arreglaron
para EIP-196. `besu-native` es una librería reusable (artefacto Maven
publicado, no exclusivo de Besu) -- cualquier otro proyecto JVM que la
use para BLS12-381 hereda este riesgo hoy, sin necesitar ningún
refactor futuro de por medio.

## Por qué este target

Décimo target real de la sesión. Después de revisar `secp256k1_jni` y
`boringssl_jni` (bien escritos, validan longitudes explícitamente, y
además duplicarían cobertura de OSS-Fuzz sobre las librerías reales de
bitcoin-core/Google), encontré que `gnark/gnark-jni` -- el wrapper Go/cgo
de `besu-native` para los precompilados EIP-2537 (BLS12-381) y EIP-196
(BN254) de Ethereum -- tiene su código fuente real directo en el repo
(no en submódulo), lo que permite usar la misma infraestructura de
fuzzing/repro nativo de Go que ya usamos toda la sesión, sin tooling
nuevo.

## Candidato real confirmado

`gnark/gnark-jni/gnark-eip-2537.go`, función `eip2537blsG1Add` (y las
mismas del resto del archivo, ver más abajo):

```go
//export eip2537blsG1Add
func eip2537blsG1Add(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)
	// cOutputLen NUNCA se usa en el resto de la funcion
	...
	nonMontgomeryMarshalG1(result, javaOutputBuf)  // escribe 128 bytes sin chequear nada
	return 0
}
```

`nonMontgomeryMarshal` (la función real que escribe el resultado, usada
por `nonMontgomeryMarshalG1`/`nonMontgomeryMarshalG2`):

```go
func nonMontgomeryMarshal(xVal, yVal *fp.Element, output *C.char, outputOffset int) {
	...
	destAddr := uintptr(unsafe.Pointer(output)) + uintptr(outputOffset+64-xLen)
	destPtr := unsafe.Pointer(destAddr)
	C.memcpy(destPtr, srcPtr, C.size_t(xLen))   // memcpy crudo, sin bounds check
	...
	// repite para Y
}
```

Escribe directo con `C.memcpy` usando aritmética de punteros cruda sobre
el puntero `output` recibido, **sin verificar en ningún momento que el
buffer real tenga espacio** -- ni `eip2537blsG1Add` chequea
`cOutputLen`, ni `nonMontgomeryMarshal` recibe o respeta ningún límite
de tamaño.

La documentación de la propia función lo deja explícito como
precondición no forzada en código:

```
- JNI:
	- javaOutputBuf must be at least EIP2537PreallocateForG1 bytes to safely store the result
```

Esto es exactamente el mismo patrón que `unmarshal_values` en FPC
(precondición documentada, nunca verificada en código) -- pero acá es
una **escritura**, no una lectura: más grave, corrupción de heap real
en vez de fuga/crash.

## Alcance -- no es solo G1Add

`cOutputLen` aparece en la firma de 6 funciones exportadas
(`eip2537blsG1Add`, `eip2537blsG1MultiExp`, `eip2537blsG2Add`,
`eip2537blsG2MultiExp`, `eip2537blsMapFpToG1`, `eip2537blsMapFp2ToG2`)
pero **nunca se referencia en el cuerpo de ninguna de ellas** (grep
confirmado). La única función que sí lo captura en una variable
(`eip2537blsPairing`, vía `outputLen := int(cOutputLen)`) lo pasa a
`castBuffer()`, que hace las cosas *peor*, no mejor:

```go
func castBuffer(javaOutputBuf *C.char, length int) []byte {
	bufSize := length
	if bufSize < EIP2537PreallocateForResultBytes {
		bufSize = EIP2537PreallocateForResultBytes  // fuerza minimo 256 SIN IMPORTAR lo que declare el caller
	}
	return (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:bufSize:bufSize]
}
```

Si el caller declara un buffer más chico que 256 bytes, `castBuffer`
**ignora ese dato y trata igual el puntero como si tuviera 256 bytes
reales** -- el propio comentario de la función lo admite: "the caller
must ensure... that no writes occur beyond the actual buffer size
allocated by Java" -- es decir, la función no hace nada para
garantizarlo, solo lo documenta.

## Confirmación empírica (repro directo, no fuzzing)

PoC en `orchestrator/fuzz_harnesses/besu_gnark_g1add_oob_write_poc/`:
usa `gnark-crypto` real (`bls12381.Generators()`) para generar un punto
G1 real y válido en la curva, lo marshalea al formato EIP-2537 real
(128 bytes), arma un input válido de 256 bytes (dos copias del mismo
punto -- input perfectamente legítimo para `eip2537blsG1Add`), y llama
la función real y sin modificar con un `cOutputLen=16` (mucho menor a
los 128 documentados), sobre un buffer C real (`malloc`) de 16+64
bytes, con los 64 bytes posteriores llenos de un canary reconocible
(`0xCC`) antes de la llamada.

```
Input valido: 2 puntos G1 reales (256 bytes)
Output buffer declarado: 16 bytes (bien mas chico que los 128 documentados)
Canary de 64 bytes (0xCC) inmediatamente despues del buffer, en memoria C real...
eip2537blsG1Add retorno = 0 (0=exito, 1=error)
bytes del canary sobreescritos mas alla del buffer de 16: 48 de 64
*** CONFIRMADO: escritura fuera de limites, empieza en offset +0 mas alla del cOutputLen=16 declarado ***
hex de los primeros 32 bytes despues del buffer declarado:
0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62a
munmap_chunk(): invalid pointer
SIGABRT: abort
```

- La función retornó **éxito (0)**, no un error -- no hay ninguna señal
  de que algo salió mal desde el punto de vista del caller.
- **48 de los 64 bytes del canary fueron sobreescritos**, empezando
  inmediatamente en el primer byte después del buffer declarado.
- El proceso terminó en **`SIGABRT` real** al intentar liberar memoria
  más tarde (`munmap_chunk(): invalid pointer`) -- glibc detectó que
  los metadatos internos del heap habían sido corrompidos por la
  escritura fuera de límites. Esto es corrupción de heap real, no un
  crash cosmético.

100% determinístico, reproducido con `go run .` (sin fuzzing --
alcanzó con leer el código y armar un input válido con un buffer
chico a propósito).

## Reachability -- honesto, verificado en el repo real de Besu

Rastreado el único caller real hoy: `hyperledger/besu` (repo principal,
no besu-native) ->
`evm/src/main/java/.../AbstractBLS12PrecompiledContract.java:151`:

```java
final byte[] result = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_RESULT_BYTES];  // 256 bytes, siempre
```

**Hoy, en el código real de Besu, el único caller INTERNO que existe
siempre reserva 256 bytes** (el máximo posible, más que suficiente para
cualquiera de las 6 operaciones) -- por eso el bug NO es explotable vía
el precompilado EVM real en el Besu actual, corriendo tal cual viene.

Pero eso no es toda la historia. A diferencia de `LibGnarkEIP196.java`
(ver sección de comparación arriba), donde los métodos nativos son
`private` y solo alcanzables a través de un guardián real del lado
Java, **los 11 métodos nativos de `LibGnarkEIP2537.java` -- incluidas
las 6 funciones vulnerables -- están declarados `public static
native`**. `besu-native` es una librería reusable, publicada como
artefacto Maven independiente, no exclusiva de la instancia interna
de Besu. Cualquier código Java que la tenga en el classpath (otro
cliente, una herramienta de testing, un proyecto de terceros que
quiera BLS12-381) puede llamar `LibGnarkEIP2537.eip2537blsG1Add(...)`
directo, hoy, sin ningún refactor de por medio -- exactamente el
patrón que los propios autores de este repo ya identificaron como
peligroso y arreglaron para EIP-196, pero no para EIP-2537.

## Impacto

- **Corrupción de heap real (confirmada empíricamente)**: cualquier
  llamador de estas 6 funciones exportadas que reserve un buffer de
  salida más chico que lo documentado (128 o 256 bytes según la
  función) corrompe memoria adyacente con contenido derivado de una
  operación criptográfica real -- no es un simple crash limpio, es
  corrupción de metadatos del allocator.
- **DoS mínimo garantizado, corrupción de memoria en el peor caso**:
  en el ejemplo mostrado arriba terminó en `SIGABRT` (glibc detectó la
  corrupción), pero eso depende del layout de memoria en el momento --
  en otros contextos podría corromper datos adyacentes sin crashear
  inmediatamente, un escenario más peligroso todavía.
- **No explotable HOY vía el precompilado EVM de Besu** (el caller
  interno de Besu siempre usa el buffer máximo) -- **pero sí
  directamente alcanzable, hoy, por cualquier consumidor externo de
  `besu-native` como librería**, dado que la API pública no tiene
  ningún guardián (a diferencia de la API equivalente de EIP-196 en el
  mismo repo, que sí lo tiene).

## Causa raíz

`cOutputLen`/`outputLen` se documenta como precondición de seguridad
en cada una de las 6 funciones pero nunca se usa para rechazar un
buffer insuficiente antes de escribir -- ni siquiera la única función
que lo captura en una variable (`castBuffer`) lo respeta realmente,
al forzar un mínimo de 256 bytes sin importar lo que el caller haya
declarado. A diferencia de EIP-196 (mismo repo, mismo tipo de riesgo),
acá no hay ningún guardián del lado Java tampoco -- los métodos
nativos son `public`, no `private`.

## Próximo paso

1. **Confirmado**: `gnark-eip-196.go` (BN254/EIP-196) NO comparte el
   mismo problema de exposición -- sus 3 métodos nativos son `private`
   y están protegidos por un guardián real (`eip196_perform_operation`,
   que valida `output.length` antes de llamar). El código nativo en sí
   (`g1AffineEncode`, que escribe 64 bytes con `copy()` sin recibir
   ningún parámetro de longitud del output) es igual de inseguro por
   diseño que el de EIP-2537, pero está mitigado del lado Java para
   EIP-196 y NO para EIP-2537 -- esa asimetría es justamente la parte
   más reportable de este hallazgo.
2. Reportar a Hyperledger -- Besu está confirmado en el alcance
   elegible del programa real de HackerOne (`hackerone.com/hyperledger`,
   scope incluye `besu`/`besu-native`). El framing honesto y más fuerte
   es: "API pública insegura por diseño en código criptográfico nativo,
   con PoC de corrupción de heap real; el propio repo demuestra que los
   autores ya conocían y mitigaron esta clase exacta de riesgo para
   EIP-196, pero la misma protección falta en EIP-2537, cuyos métodos
   nativos vulnerables son además `public`, no `private` -- alcanzable
   hoy por cualquier consumidor externo de la librería, no solo por un
   hipotético refactor futuro de Besu" -- clasificable razonablemente
   como High, aunque la decisión final de severidad es del equipo de
   seguridad.
