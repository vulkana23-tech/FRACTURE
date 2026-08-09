// Fuzz real de decodeToken (paquete util, hyperledger/fabric-ca) --
// parsea el token de autenticacion que fabric-ca-server recibe en el
// header "Authorization" de CADA request HTTP real a su API (enrollar
// un certificado, renovarlo, revocarlo, etc.). token es 100% controlado
// por el cliente que hace el request -- reachability directa, no
// requiere rastrear ninguna capa intermedia (a diferencia del hallazgo
// anterior en fabric-amcl, que resulto ser codigo muerto).
//
// decodeToken llama internamente a GetX509CertificateFromPEM (parseo de
// PEM/X.509, otro clasico de fuzzing) -- un solo fuzz test cubre ambas
// funciones reales en la misma corrida.
package util

import "testing"

func FuzzDecodeToken(f *testing.F) {
	f.Add("")
	f.Add("a.b")
	f.Add("dGVzdA==.dGVzdA==")
	f.Fuzz(func(t *testing.T, token string) {
		decodeToken(token)
	})
}
