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
  ) and
  // Exclusiones reales para bajar el ruido (420 -> menos, ver README):
  // nunca vendor/ (codigo de terceros, no del propio target), nunca
  // archivos _test.go (no son funciones de produccion), nunca los
  // paquetes cmd/tools (parseo de flags de linea de comandos, nunca
  // reciben input de RED -- distinto de "recibe un string" que la
  // heuristica de firma sola no distingue).
  not f.getFile().getRelativePath().matches("%vendor/%") and
  not f.getFile().getRelativePath().matches("%_test.go") and
  not f.getFile().getRelativePath().matches("cmd/%") and
  not f.getFile().getRelativePath().matches("tools/%")
select f, "Candidata a fuzzing: " + f.getName() + " recibe " + p.getName() + " " + p.getType().toString()
      + " (" + f.getFile().getRelativePath() + ")"
