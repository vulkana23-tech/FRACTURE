/**
 * @name Funciones candidatas a fuzzing
 * @description Funciones EXPORTADAS que reciben string o []byte -- forma
 *              de firma tipica de una funcion que procesa input externo
 *              (parseo de tokens, certificados, mensajes de red) y que
 *              go test -fuzz puede probar directo, sin necesitar
 *              construir un tipo complejo.
 * @kind problem
 * @problem.severity recommendation
 * @id fracture/fuzz-candidates
 */

import go

from FuncDecl f, Parameter p
where
  f.getName().regexpMatch("^[A-Z].*") and
  p = f.getAParameter() and
  (
    p.getType().getName() = "string" or
    p.getType().toString().matches("%byte%")
  )
select f, "Candidata a fuzzing: " + f.getName() + " recibe " + p.getName() + " " + p.getType().toString()
