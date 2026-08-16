# hyperledger/fabric-amcl — tercer panic real, esta vez en `DL_unpack_sig`

**Estado**: bug real y reproducible, mismo patrón de reachability que
`findings/2026-08-09_fabric-amcl-dilithium-panic.md` -- probablemente
NO submission-ready por el mismo motivo, documentado igual.

## Cómo se encontró

Validando el fix del segundo bug
(`2026-08-16_fabric-amcl-dilithium-pk-unpack-oob.md`): con el guard de
`pk` puesto, una campaña real de 45s encontró este TERCER bug, distinto
de los dos anteriores -- mismo patrón exacto, pero en `sig`, no en
`pk`.

## Causa raíz

`DL_unpack_sig` (`core/DILITHIUM.go:620-...`) indexa `sig[i]`/`sig[n]`
(vía `DL_nextword`) sin chequear que `sig` tenga el largo real
esperado -- el propio paquete ya define la constante correcta,
`DL_SIG_SIZE_2 = (DL_DEGREE*4*(17+1))/8 + 80 + 4 + 32` (2420 bytes
para la variante `_2`, exactamente el largo que el seed original del
harness ya usaba -- `make([]byte, 2420)` -- pero sin validarlo en
ningún lado antes del panic):

```go
func DL_unpack_sig(params []int, z [][DL_DEGREE]int32, ct []byte, h []byte, sig []byte) {
	...
	for i := 0; i < 32; i++ {
		ct[i] = sig[i]   // <- sin chequear len(sig) primero
	}
	var pos [2]int
	pos[0] = 32; pos[1] = 0
	for j := 0; j < el; j++ {
		for i := 0; i < DL_DEGREE; i++ {
			t = DL_nextword(lg+1, 0, sig, pos[:])  // <- indexa sig mas alla, mismo patron que DL_nextword ya visto en DL_unpack_pk
			...
```

**CWE-125: Out-of-bounds Read** (panic de Go, mismo mecanismo que los
dos hallazgos anteriores).

## Repro real

Input real que lo encontró el fuzzer (minimizado por el propio `go
test -fuzz`): `pk` válido (`DL_PK_SIZE_2` bytes), `sig` corto.

```
panic: runtime error: index out of range [1] with length 1
	.../core.DL_unpack_sig(...)
		core/DILITHIUM.go:630
	.../core.DL_verify(...)
		core/DILITHIUM.go:1203
	.../core.DL_verify_2(...)
		core/DILITHIUM.go:1265
```

## Reachability

Mismo argumento que los dos hallazgos anteriores de esta misma función
-- mismo entry point exportado (`DL_verify_2`), mismos consumidores
reales ya revisados (Lotus, Boost) sin un camino externo conocido que
pase un `sig` de largo incorrecto hoy. No se repite la investigación
completa por separado.

## Fix real aplicado (infraestructura de fuzzing)

`orchestrator/fuzz_tests/dilithium_verify_test.go` -- guard adicional
`len(sig) < DL_SIG_SIZE_2` (constante real del paquete), agregado
después del guard de `pk`. Validado en vivo: con ambos guards, 2
minutos de campaña real (~5.7M ejecuciones) sin ningún crash nuevo --
el target ya explora de verdad más allá de los 3 bugs ya conocidos, en
vez de quedarse trabado en el primero que encuentra cada vez.

## Suggested Fix (para la librería real, si algún día se reporta)

Mismo patrón que el finding anterior: `DL_unpack_sig` debería validar
`len(sig) >= DL_SIG_SIZE_2` (o el tamaño real correspondiente a los
parámetros `el`/`ck`/`omega`) al principio, devolviendo un error
explícito -- y dado que el mismo patrón (indexar sin chequear largo)
aparece en TRES lugares distintos del mismo archivo
(`DL_unpack_pk` x2, `DL_unpack_sig`), vale la pena revisar si
`DL_nextword`/`DL_nextbyte32`/funciones hermanas comparten el mismo
problema en otros llamadores no cubiertos todavía por este harness
(`DL_verify`/`DL_verify_3`/`DL_verify_5`, variantes de otros niveles
de seguridad Dilithium en el mismo archivo).
