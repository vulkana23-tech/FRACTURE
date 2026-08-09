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
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 1312), []byte("mensaje de prueba"), make([]byte, 2420))
	f.Fuzz(func(t *testing.T, pk, m, sig []byte) {
		DL_verify_2(pk, m, sig)
	})
}
