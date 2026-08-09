/**
 * @name Funciones candidatas a fuzzing, alcanzables desde un handler HTTP real
 * @description Refinamiento de fuzz_candidates.ql: en vez de filtrar solo
 *              por firma (string/[]byte), sigue el grafo de llamadas REAL
 *              desde ServeHTTP (el metodo que implementa http.Handler,
 *              confirmado en vivo como el punto de entrada real de
 *              fabric-ca -- lib/serverendpoint.go) para quedarse solo con
 *              funciones genuinamente alcanzables desde una request de
 *              red, no cualquier funcion que reciba un string por
 *              casualidad (ej. un mensaje de error de fmt.Errorf).
 * @kind problem
 * @problem.severity recommendation
 * @id fracture/fuzz-candidates-reachable
 */

import go

// Cierre transitivo real del grafo de llamadas -- "reachable" es
// verdadero para cualquier funcion invocada (directa o indirectamente)
// desde el handler HTTP real, nunca asumido.
predicate reachableFromHTTPHandler(FuncDecl f) {
  f.getName() = "ServeHTTP"
  or
  exists(CallExpr call, FuncDecl caller |
    reachableFromHTTPHandler(caller) and
    call.getEnclosingFunction() = caller and
    call.getTarget() = f.getFunction()
  )
}

from FuncDecl f, Parameter p
where
  reachableFromHTTPHandler(f) and
  p = f.getAParameter() and
  (
    p.getType().getName() = "string" or
    p.getType().toString().matches("%byte%")
  ) and
  not f.getFile().getRelativePath().matches("%_test.go")
select f, "Candidata a fuzzing (alcanzable desde ServeHTTP): " + f.getName() + " recibe "
      + p.getName() + " " + p.getType().toString() + " (" + f.getFile().getRelativePath() + ")"
