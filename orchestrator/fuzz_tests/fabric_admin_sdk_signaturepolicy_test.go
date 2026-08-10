// Fuzz real de NewApplicationPolicy / signaturePolicyEnvelopeFromString
// (paquete chaincode, hyperledger/fabric-admin-sdk) -- parser de DSL
// escrito a mano para políticas de endorsement tipo
// `OR('Org1MSP.member','Org2MSP.member')`. A diferencia de los targets
// anteriores (proto.Unmarshal, robusto por diseño contra bytes
// arbitrarios), acá el string pasa por TRES etapas de parseo propio:
//
//  1. expr.Compile()/expr.Run() (paquete expr-lang/expr) -- compila y
//     evalúa el string como una expresión, con and/or/outof mapeados a
//     funciones stub propias del archivo.
//  2. firstPass() -- segunda pasada sobre el string resultante via
//     otra evaluación de expr, agregando un ID a cada llamada outof.
//  3. secondPass() -- tercera pasada, esta vez construyendo el
//     *cb.SignaturePolicyEnvelope real con regexes propias
//     (`regex`/`regexErr`) sobre cada principal "ORG.ROLE".
//
// Tres pasadas de parseo manual encadenadas sobre el mismo string es
// exactamente el patrón con más probabilidad real de panics
// (índices, type assertions, regex, recursión) comparado con los
// wrappers de un solo proto.Unmarshal ya revisados en este mismo repo
// (protoutil/*.go, bien guardados, ver
// 2026-08-10_fabric-sdk-go_chconfig_extractconfig_CONFIRMED.md para
// contraste con el caso donde SÍ había un bug).
//
// Reachability: NewApplicationPolicy es la función pública que un
// administrador/deployer usa para fijar la política de endorsement a
// nivel aplicación al aprobar/commitear una definición de chaincode
// (chaincode lifecycle). Input de un operador/config, no de un
// atacante de red anónimo -- amenaza más débil que los targets
// anteriores, pero sigue siendo una superficie real de robustez
// (un policy string malformado no debería poder crashear el proceso
// administrador).
package chaincode

import "testing"

func FuzzNewApplicationPolicy(f *testing.F) {
	f.Add("")
	f.Add("OR('Org1MSP.member','Org2MSP.member')")
	f.Add("AND('Org1MSP.admin', OR('Org2MSP.member','Org3MSP.peer'))")
	f.Add("OutOf(2, 'Org1MSP.member','Org2MSP.member','Org3MSP.member')")
	f.Add("not a policy")
	f.Add("OR(")
	f.Add("OR('a.member')")
	f.Fuzz(func(t *testing.T, policy string) {
		_, _ = NewApplicationPolicy(policy, "")
	})
}
