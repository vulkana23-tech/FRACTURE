// Fuzz real de ssh.ParsePublicKey (golang.org/x/crypto/ssh, tier OT0 del
// OSS VRP de Google, github.com/golang/crypto). Parsea una clave publica
// SSH en formato wire real (RFC 4253 seccion 6.6) -- exactamente el tipo
// de dato que llega directo de la red durante un handshake SSH real: el
// host key que manda el servidor durante el key exchange, o la clave
// publica que manda un cliente al autenticarse con el metodo
// "publickey". Atacante-controlado sin ninguna capa intermedia --
// cualquier parte en cualquiera de los dos lados de una conexion SSH real
// puede mandar bytes arbitrarios ahi.
//
// Reachability real (no solo del harness): esta MISMA funcion la usa
// literalmente el propio paquete ssh en su handshake real
// (handshake.go / server.go de este mismo repo) para parsear el host
// key del peer -- no es un caso de uso hipotetico ni un helper interno,
// es la funcion publica documentada para exactamente este proposito.
package ssh

import "testing"

func FuzzParsePublicKey(f *testing.F) {
	// Seed real: una clave publica ed25519 valida, generada y
	// marshaleada con el propio paquete ssh.NewPublicKey().Marshal()
	// -- no un placeholder, un input que el parser real acepta limpio.
	f.Add([]byte{0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x40, 0x12, 0xb7, 0x0a, 0xf0, 0xdf, 0x2a, 0x7e, 0x40, 0x54, 0xbe, 0xcf, 0xf3, 0x8e, 0xaa, 0xb3, 0xca, 0x40, 0x7a, 0xe1, 0x00, 0x2c, 0x50, 0x0a, 0x6d, 0x14, 0x60, 0x05, 0x3b, 0x9c, 0x7f, 0x9a})
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, in []byte) {
		ParsePublicKey(in)
	})
}
