# targets/

Selección de qué proyecto OSS fuzzear. Criterios (ver README.md raíz
para el detalle completo): scope de bounty real, poca cobertura de
fuzzing existente (chequear OSS-Fuzz primero), lenguaje memory-unsafe o
con superficie unsafe real.

## Estado real (2026-08-15)

`select_targets.py` ya estaba implementado (este README decía "sin
implementación todavía" pero estaba desactualizado, no el código --
mismo problema que se encontró en `harness_gen/README.md` esta misma
ronda, dos READMEs desactualizados de dos en dos no es casualidad, ver
nota abajo). Pipeline real: repos watched de SPECTRE (solo lectura,
nunca escribe ahí) → GitHub API (lenguaje real, archived) → OSS-Fuzz
(`project.yaml` real, no coincidencia de nombre) → tier por lenguaje.

**Agregado esta ronda**: ranking por actividad reciente
(`pushed_at`, que ya viene GRATIS en la misma respuesta de GitHub que
se pedía para lenguaje/archived -- sin llamada extra a la API, el rate
limit sin auth ya es apretado, 60/hora) -- dentro del mismo tier, un
repo con push reciente ordena primero. Señal barata para "código
probablemente sin fuzzear todavía": el piloto de CodeQL
(`targets/codeql_queries/README.md`) ya había concluido que seguir el
grafo de llamadas para esto pierde targets reales (dispatch por
interfaz) y cuesta 5+ minutos de preparación por repo -- esto no
reemplaza esa idea, es la alternativa barata que sí se puede correr
para TODOS los candidatos sin ese costo.

Corrida real contra la base de SPECTRE (2026-08-15): de 15 candidatos
reales que sobreviven los filtros duros, `fabric-samples`,
`fabric-lib-go`, `fabric-private-chaincode`, `fabric-protos-go` y
`cb-mpc-go` salieron con actividad reciente real (15-136 días) y
CERO harnesses todavía en `orchestrator/targets.json` -- candidatos
concretos, no teóricos, para la próxima ronda de `harness_gen/`.

## Uso

```
venv/bin/python3 targets/select_targets.py [--program handle]
```

## Nota sobre los READMEs de este repo

Dos de dos READMEs revisados a fondo esta ronda (`harness_gen/`, este)
decían "sin implementación todavía" con código real y funcionando
adentro. Vale la pena, en algún momento, auditar el resto
(`orchestrator/`, `triage/` ya se corrigieron esta ronda) en vez de
asumir que un README desactualizado significa que hay que empezar de
cero -- leer el código primero.

## Lo que falta (honesto)

- No hay heurística de "qué PATHS específicos tocó el push reciente"
  (parsers/serializers vs. CI/docs) -- eso sí necesitaría una llamada
  extra por repo (`/commits`) y comerse el rate limit más rápido. Con
  un `GITHUB_TOKEN` real (5000/hora en vez de 60) dejaría de ser un
  problema, pero eso requiere que el usuario decida configurar uno,
  no se asumió ni se generó ningún token en esta ronda.
