# hyperledger/fabric-amcl — panic real en verificación de firma Dilithium

**Estado (2026-08-09, actualizado tras investigar reachability)**:
bug real y reproducible, pero **probablemente NO submission-ready** —
no se encontró ningún camino real en el ecosistema de Hyperledger que
llegue a este código hoy. Ver "Investigación de reachability" abajo
para el detalle completo. Se deja documentado igual (nunca se borra un
hallazgo, aunque termine en "no reportar") -- production data.

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

## Investigación de reachability (2026-08-09)

Rastreada la cadena real de dependencias (lectura directa de
`go.mod`/código fuente real, no asumida):

1. `fabric-amcl` es dependencia **indirecta** del repo principal
   `github.com/hyperledger/fabric` (confirmado leyendo `go.mod` real de
   `fabric`).
2. La dependencia **directa** real que la trae es
   `github.com/IBM/idemix` (el esquema de credenciales de privacidad de
   Fabric).
3. Pero `IBM/idemix` (clonado y revisado el código real) **solo usa
   fabric-amcl para las curvas de emparejamiento BN254 (`amcl.ECP`,
   `amcl.ECP2`, `amcl.Fp256bn`) -- el esquema idemix ACTUAL, no
   Dilithium**. Cero referencias a `DL_verify`/Dilithium en todo
   `IBM/idemix`.
4. Dentro del propio `fabric-amcl`, nada más en el repo llama a
   `DL_verify_2` -- es codigo de libreria puro, sin ningun caller
   interno tampoco.

**Conclusión**: el soporte de Dilithium (post-cuántico) en
`fabric-amcl` parece haberse agregado de forma anticipada/preventiva,
pero no se encontró ningún camino real, en el ecosistema Hyperledger
actual, que efectivamente invoque `DL_verify_2` con datos externos (ni
con datos de ningún tipo). Es decir: el bug es real, pero hoy parece
ser **código muerto** desde la perspectiva de impacto de seguridad --
la mayoría de los programas de bug bounty excluyen explícitamente
hallazgos en código inalcanzable/no usado.

**Lo que esto NO descarta** (límites reales de esta investigación, no
una prueba exhaustiva):
- Solo se revisaron `fabric` (repo principal) e `IBM/idemix`
  directamente -- Hyperledger tiene decenas de subproyectos, alguno
  distinto podría importar `fabric-amcl` y sí usar Dilithium.
- `fabric-amcl` es una librería de propósito general (pese al nombre)
  -- proyectos de terceros fuera del ecosistema Hyperledger podrían
  usarla, aunque eso ya quedaría fuera del scope del programa de
  bounty de Hyperledger específicamente.
- No se buscó en el issue tracker real de `fabric-amcl` si esto ya es
  conocido.

## Decisión

No se reporta a Hyperledger por ahora -- sin reachability confirmada,
no calificaría como hallazgo real en la mayoría de los programas. Se
deja documentado como aprendizaje real del primer ciclo completo de
FRACTURE: encontrar un crash es solo el primer paso, la reachability
es lo que separa un hallazgo real de una curiosidad técnica -- misma
lección que ya aprendimos hoy mismo con el triage de SPECTRE (VettedSec
REACHABLE vs. la función específica del CVE).
