# CONFIRMADO: heap-buffer-overflow de ESCRITURA real en los wrappers Go/cgo de gnark-jni (besu-native) -- output buffer nunca validado

**Estado: bug de memoria real y demostrado empíricamente (repro determinístico,
corrupción de heap confirmada con un canary real, glibc detectó la
corrupción y abortó al liberar memoria). Reachability desde el precompilado
EVM real de Besu verificada y descartada HOY (el único caller actual
siempre reserva el tamaño correcto) -- documentado como hallazgo de
robustez/defensa-en-profundidad real, no como exploit directo en
producción actual. NO reportado todavía.**

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

**Hoy, en el código real de Besu, el único caller que existe siempre
reserva 256 bytes** (el máximo posible, más que suficiente para
cualquiera de las 6 operaciones) -- por eso el bug NO es explotable vía
el precompilado EVM real en el Besu actual. Esto NO es una excusa para
no reportarlo: es exactamente el patrón "landmine sin activar" -- el
código nativo es memoria-insegro por diseño, y solo está a salvo
porque el único llamador conocido hoy cumple una precondición que el
código nunca hace cumplir. Cualquier refactor futuro, cualquier otro
consumidor de esta librería (es una librería nativa reusable, no
exclusiva de Besu), o cualquier binding alternativo que aloque el
buffer más ajustado (128 en vez de 256, que sería la optimización
"obvia" y razonable para alguien que no audite el código C/Go
subyacente) dispara corrupción de heap real.

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
- **No explotable HOY vía el precompilado EVM de Besu** (verificado,
  ver arriba) -- pero el defecto de diseño en la librería nativa es
  real e independiente de ese caller específico.

## Causa raíz

`cOutputLen`/`outputLen` se documenta como precondición de seguridad
en cada una de las 6 funciones pero nunca se usa para rechazar un
buffer insuficiente antes de escribir -- ni siquiera la única función
que lo captura en una variable (`castBuffer`) lo respeta realmente,
al forzar un mínimo de 256 bytes sin importar lo que el caller haya
declarado.

## Próximo paso

1. Confirmar el mismo patrón en `gnark-eip-196.go` (BN254/EIP-196) --
   no verificado todavía en esta sesión, mismo autor/estilo, muy
   probable que comparta el defecto.
2. Reportar a Hyperledger -- Besu está confirmado en el alcance
   elegible del programa real de HackerOne (`hackerone.com/hyperledger`,
   scope incluye `besu`/`besu-native`). El framing honesto es
   "defense-in-depth / API insegura por diseño en código criptográfico
   nativo, con PoC de corrupción de heap real, no explotable hoy vía
   el único caller conocido de Besu pero sí para cualquier otro
   consumidor de la librería" -- clasificable razonablemente, aunque
   la decisión final de severidad es del equipo de seguridad.
