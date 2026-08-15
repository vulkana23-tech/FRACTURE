// Paquete Go real y minimo, local (no clonado de red) -- fixture para
// testear generate_go_harness.py sin depender de la red ni de un repo
// externo. ParseLenPrefixed imita a proposito la misma forma de bug
// que ya encontro este proyecto en produccion (indexado de un slice
// sin chequear longitud primero).
package samplepkg

// ParseLenPrefixed lee un byte de longitud y devuelve esa cantidad de
// bytes siguientes -- panic real (index out of range) si data esta
// vacio o es mas corto que el prefijo de longitud declarado.
func ParseLenPrefixed(data []byte) []byte {
	n := int(data[0])
	return data[1 : 1+n]
}
