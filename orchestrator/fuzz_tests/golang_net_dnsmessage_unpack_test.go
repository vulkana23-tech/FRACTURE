// Fuzz real de (*dnsmessage.Message).Unpack (golang.org/x/net/dns/dnsmessage,
// tier OT0 del OSS VRP de Google, github.com/golang/net). Parsea un
// mensaje DNS binario completo (header + preguntas + registros de
// respuesta/autoridad/adicionales) -- clasico de fuzzing por el formato
// con punteros de compresion y campos de longitud variable, y
// atacante-controlado por diseno: cualquier respuesta DNS real que
// llega de la red (de un servidor DNS malicioso o un MITM) pasa por
// exactamente esta funcion antes de que el resto del programa vea un
// solo campo.
package dnsmessage

import "testing"

func FuzzMessageUnpack(f *testing.F) {
	// Seed real: un mensaje DNS valido (1 pregunta A + 1 respuesta A),
	// generado y empaquetado con el propio (*Message).Pack() del
	// paquete real -- no un placeholder.
	f.Add([]byte{0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22})
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, in []byte) {
		var m Message
		_ = m.Unpack(in)
	})
}
