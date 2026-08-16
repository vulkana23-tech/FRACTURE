# hyperledger/fabric-amcl — segundo panic real en `DL_unpack_pk` (pk de largo intermedio)

**Estado**: bug real y reproducible, mismo patrón de reachability que
`findings/2026-08-09_fabric-amcl-dilithium-panic.md` (ver ahí el
análisis completo) -- probablemente NO submission-ready por el mismo
motivo, documentado igual porque es un bug real y distinto del ya
conocido.

## Cómo se encontró

Encontrado arreglando la infraestructura de FRACTURE, no por una
sesión de fuzzing nueva: el target `fabric_amcl_dilithium_verify2`
llevaba desde 2026-08-09 (más de una semana) sin fuzzear de verdad --
el seed `f.Add([]byte{}, []byte{}, []byte{})` del harness dispara el
bug YA CONFIRMADO ese mismo día, y `go test -fuzz` para en el primer
panic que encuentra (venga de un seed o de una mutación real), así que
el daemon 24/7 solo re-descubría el mismo bug conocido en el primer
segundo de cada rotación, sin tiempo real para explorar nada más. Al
sacar ese seed y agregar un guard (`len(pk) < 32`, la causa raíz exacta
del bug original) para que el fuzzing pudiera seguir más allá, una
campaña real de apenas unos segundos encontró este SEGUNDO bug,
distinto.

## Causa raíz

`DL_unpack_pk` (`core/DILITHIUM.go:479-491`) copia los primeros 32
bytes de `pk` a `rho` (chequeado por el guard del bug anterior), pero
después sigue leyendo desde el byte 32 en adelante para desempaquetar
`t1` vía `DL_nextword` -- sin chequear que `pk` tenga los bytes
adicionales necesarios:

```go
func DL_unpack_pk(params []int, rho []byte, t1 [][DL_DEGREE]int16, pk []byte) {
	var pos [2]int
	pos[0] = 32; pos[1] = 0
	ck := params[3]
	for i := 0; i < 32; i++ {
		rho[i] = pk[i]
	}
	for j := 0; j < ck; j++ {
		for i := 0; i < DL_DEGREE; i++ {
			t1[j][i] = int16(DL_nextword(DL_TD, 0, pk, pos[:]))  // <- indexa pk mas alla del byte 32 sin chequear el largo real
		}
	}
}
```

`DL_nextword` (`core/DILITHIUM.go:431-455`) indexa `t[ptr]`/`t[ptr+i]`
directo, sin chequeo de límites -- si `pk` tiene exactamente 32 bytes
(o cualquier largo menor que el real esperado, `DL_PK_SIZE_2`, una
constante ya definida en el propio paquete: `32 + 4*DL_DEGREE*DL_TD/8`
= 1312 bytes para la variante `_2`), la primera lectura en
`ptr=32` ya está fuera de rango.

**CWE-125: Out-of-bounds Read** (se manifiesta como panic de Go, no
como lectura silenciosa de memoria ajena -- el runtime de Go chequea
límites de slice siempre).

## Repro real

```
Input: pk=make([]byte, 32), m=[]byte("mensaje de prueba"), sig=make([]byte, 2420)
```

(cualquier `pk` con `32 <= len(pk) < DL_PK_SIZE_2` (1312) reproduce el
mismo panic -- confirmado con el input real que encontró el fuzzer:
`pk` de 32 bytes de ceros ASCII)

```
panic: runtime error: index out of range [32] with length 32
	.../core.DL_nextword(...)
		core/DILITHIUM.go:435
	.../core.DL_unpack_pk(...)
		core/DILITHIUM.go:488
	.../core.DL_verify(...)
		core/DILITHIUM.go:1202
	.../core.DL_verify_2(...)
		core/DILITHIUM.go:1265
```

## Reachability

Mismo argumento y misma conclusión que el finding original
(`2026-08-09_fabric-amcl-dilithium-panic.md`) -- mismo punto de
entrada exportado (`DL_verify_2`/`DL_verify`), mismo perfil de
consumidores reales revisados (Lotus, Boost), sin un camino externo
conocido que llegue con un `pk` de largo distinto al esperado hoy. No
se repitió la investigación completa de reachability por separado
porque es literalmente el mismo entry point ya investigado -- si algún
consumidor real llega a usar `DL_verify_2` con datos externos,
CUALQUIERA de los dos bugs (este y el original) aplicaría igual.

## Fix real aplicado (a la infraestructura de fuzzing, no a la librería)

`orchestrator/fuzz_tests/dilithium_verify_test.go` -- guard
`len(pk) < DL_PK_SIZE_2` (la constante real del propio paquete, no un
número adivinado) antes de llamar a `DL_verify_2`. Nunca esconde el
bug (sigue reproducible con el input real de arriba), solo evita que
el target se quede trabado re-descubriéndolo en vez de fuzzear de
verdad. Validado en vivo: con el guard, una campaña de 2 minutos hizo
~5.7M ejecuciones reales sin crashear -- antes de este fix, el target
crasheaba en el primer segundo de CADA rotación desde 2026-08-09.

## Suggested Fix (para la librería real, si algún día se reporta)

`DL_unpack_pk` debería validar `len(pk) >= DL_PK_SIZE_2` (o el tamaño
real correspondiente al parámetro `ck`) al principio, devolviendo un
error explícito en vez de dejar que el panic de out-of-bounds se
propague.
