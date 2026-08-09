# hyperledger/fabric-amcl — panic real en verificación de firma Dilithium

**Estado**: candidato encontrado, **sin triagear todavía** (ver
"Falta antes de reportar" abajo) — no está confirmado como submission-ready.

## Resumen

`DL_verify_2` (y por extensión `DL_verify`/`DL_verify_3`/`DL_verify_5`,
todas las variantes de verificación de firma Dilithium en
`core/DILITHIUM.go`) crashea con un panic real de Go
(`index out of range`) cuando se le pasa una clave pública (`pk`) más
corta de 32 bytes — incluyendo el caso trivial de `pk` vacío.

## Causa raíz

`DL_unpack_pk` (`core/DILITHIUM.go:479-491`):

```go
func DL_unpack_pk(params []int, rho []byte, t1 [][DL_DEGREE]int16, pk []byte) {
	var pos [2]int
	pos[0] = 32; pos[1] = 0
	ck := params[3]
	for i := 0; i < 32; i++ {
		rho[i] = pk[i]   // <- sin chequear len(pk) >= 32 primero
	}
	...
```

Copia incondicional de los primeros 32 bytes de `pk` sin validar su
longitud antes. Un `pk` real de Dilithium2 tiene 1312+ bytes, así que
esto nunca pasa con una clave legítima — pero nada impide que un
llamador pase bytes arbitrarios (ej. un mensaje de red, una credencial
mal formada) sin validar el tamaño primero.

## Cómo se encontró

Fuzzing nativo de Go (`go test -fuzz`) contra `DL_verify_2(pk, m, sig []byte)`
-- ver `orchestrator/fuzz_tests/dilithium_verify_test.go`. El crash
salió en el PRIMER seed (`pk=[]byte{}, m=[]byte{}, sig=[]byte{}`), sin
necesitar ninguna mutación real del fuzzer -- reproducible con:

```
go test -run FuzzDLVerify2 -v ./core/
```

(requiere `go mod init`/`go mod tidy` primero -- el repo no tiene
`go.mod`, ver `orchestrator/run_go_fuzzer.py::_ensure_go_module`).

## Severidad real (evaluación honesta, sin exagerar)

- **Confirmado**: panic real, reproducible al 100%, con el input más
  trivial posible (bytes vacíos) — cero sofisticación necesaria.
- **NO confirmado todavía**: si `DL_verify_2`/`DL_verify` se llaman en
  algún camino real de Fabric con una `pk` que venga de una fuente
  externa no confiable (ej. una credencial idemix recibida de un peer),
  sin que el caller ya valide la longitud antes. Sin confirmar esto, es
  un panic real pero de impacto desconocido — podría ser DoS real
  (crash del proceso) o podría estar protegido en la práctica por un
  chequeo de longitud en una capa superior que todavía no revisamos.
- **NO confirmado**: si esto ya es un issue conocido/reportado
  públicamente (duplicado) — no se buscó en el issue tracker real de
  fabric-amcl todavía.

## Falta antes de reportar a Hyperledger

1. Rastrear los callers reales de `DL_verify_2`/`DL_verify` en el resto
   del ecosistema Fabric (idemix, fabric-ca, etc.) para confirmar si
   una `pk` corta puede llegar ahí desde una fuente externa sin
   validación previa.
2. Buscar en issues/PRs de `hyperledger/fabric-amcl` si esto ya se
   reportó antes.
3. Si se confirma reachability real, escribir un PoC minimo end-to-end
   (no solo el test unitario) antes de reportar via el programa de
   HackerOne de Hyperledger.
