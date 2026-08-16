// Fuzz real de DL_verify_2 (verificacion de firma Dilithium -- criptografia
// post-cuantica, NIST FIPS 204) en hyperledger/fabric-amcl. pk, m, sig son
// bytes crudos controlados por el atacante en un uso real (verificar una
// firma que llega de afuera) -- objetivo clasico de fuzzing: un bug de
// memoria o un bypass de verificacion aca es severidad alta.
//
// Elegido a mano (no autoseleccionado por IA todavia) tras revisar el
// codigo real del paquete y confirmar que es una funcion EXPORTADA que
// toma solo bytes, sin parametros internos extra que fuzzear (a
// diferencia de DL_verify, que ademas pide "params []int").
package core

import "testing"

func FuzzDLVerify2(f *testing.F) {
	// Bug real encontrado en produccion (2026-08-16): el seed
	// []byte{},[]byte{},[]byte{} dispara el panic real y ya CONFIRMADO
	// documentado en findings/2026-08-09_fabric-amcl-dilithium-panic.md
	// (pk vacio -> index out of range en DL_unpack_pk) -- `go test -fuzz`
	// trata el panic de un seed como fallo fatal de test ANTES de entrar
	// al loop real de fuzzing (falla en "gathering baseline coverage").
	// Sin sacar este seed, el target nunca llega a fuzzear de verdad:
	// cada corrida del daemon 24/7 volvia a crashear con el mismo bug ya
	// conocido en el primer segundo, desperdiciando el slot de rotacion
	// completo (confirmado en logs: mas de una semana sin explorar nada
	// nuevo desde que se documento el hallazgo). El bug real sigue
	// documentado y reproducible en el archivo de findings -- esto solo
	// saca el seed que lo dispara para que el fuzzing real pueda seguir
	// mas alla de el.
	f.Add(make([]byte, 1312), []byte("mensaje de prueba"), make([]byte, 2420))
	f.Fuzz(func(t *testing.T, pk, m, sig []byte) {
		// Dos bugs reales YA CONFIRMADOS y documentados, ambos en el
		// unpacking de pk dentro de DL_unpack_pk/DL_nextword (ninguno
		// chequea el largo real de pk antes de indexarlo):
		//   1. findings/2026-08-09_fabric-amcl-dilithium-panic.md --
		//      pk mas corto de 32 bytes: panic copiando rho.
		//   2. findings/2026-08-16_fabric-amcl-dilithium-pk-unpack-oob.md --
		//      pk entre 32 y DL_PK_SIZE_2 bytes: panic mas adelante,
		//      desempaquetando t1 (DL_nextword indexa mas alla de pk).
		// `go test -fuzz` para en el PRIMER panic que encuentra, sin
		// importar si viene de un seed o de una mutacion real -- sin
		// este guard, la mutacion real re-descubre el bug ya conocido
		// mas cercano en microsegundos y el target nunca tiene tiempo
		// real de explorar el resto del espacio de entrada en busca de
		// un bug DISTINTO (confirmado en vivo: con el guard de arriba
		// -- pk<32 -- el fuzzer encontro el SEGUNDO bug en <1s). El
		// guard usa DL_PK_SIZE_2 (constante real del propio paquete,
		// el tamano de clave publica ML-DSA-44/FIPS-204 real) en vez de
		// un numero mas chico adivinado -- nunca esconde ninguno de los
		// dos bugs (ambos siguen documentados y reproducibles aparte),
		// solo evita que este target se quede trabado re-descubriendolos
		// para siempre en vez de fuzzear de verdad.
		if len(pk) < DL_PK_SIZE_2 {
			return
		}
		// Tercer bug real encontrado en vivo validando el fix de arriba
		// (findings/2026-08-16_fabric-amcl-dilithium-sig-unpack-oob.md):
		// mismo patron exacto, esta vez en DL_unpack_sig -- sig mas corto
		// de DL_SIG_SIZE_2 (constante real del propio paquete) panickea
		// indexando sig[] sin chequear el largo primero.
		if len(sig) < DL_SIG_SIZE_2 {
			return
		}
		DL_verify_2(pk, m, sig)
	})
}
