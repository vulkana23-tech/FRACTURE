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

## `find_patch_directed_candidates.py` -- fuzzing dirigido por parche

Complementa `select_targets.py` (qué REPO fuzzear) con "qué FUNCIÓN
específica priorizar dentro de un repo ya elegido": busca commits
recientes cuyo mensaje suene a seguridad (overflow, UAF, CVE, null
pointer, etc. -- inglés y español) y filtra los que en realidad son
bumps de dependencias/CI (que sí mencionan "CVE" en el mensaje pero no
tocan código propio). El código *alrededor* de un parche reciente es
donde más probablemente haya variantes del mismo bug o un fix
incompleto -- mucho más rápido que fuzzing ciego, y es una técnica
real de bug bounty (muchos programas pagan por "regresión"/"fix
incompleto"), no algo teórico.

**Dos iteraciones reales de filtro, probadas en vivo contra
`hyperledger/fabric-ca`** (documentado como caso de estudio en los
tests, no solo en este README):
1. Filtro por lista negra de archivos "ruido" (`go.mod`, `vendor/`,
   `.github/`) -- un archivo nuevo (`osv-scanner.toml`) la esquivó en
   la primera corrida real.
2. Cambiado a lista BLANCA: un commit solo es candidato si toca al
   menos un archivo con extensión de código fuente real, Y ese archivo
   no está bajo `vendor/`/`node_modules/`/`third_party/`/`docs/`
   (código vendoreado de terceros o tooling de docs, no lógica de la
   app). Mucho más robusto -- no necesita mantenimiento cada vez que
   aparece una herramienta de CI nueva.

**Resultado real contra `hyperledger/fabric-ca`** (4 años de
historial): 0 candidatos -- honesto, no un bug: TODO el historial de
seguridad real de ese repo fueron bumps de dependencias, correctamente
filtrados.

**Resultado real contra `cloudflare/workerd`** (1 año): encontró
fixes reales y recientes de use-after-free en
`src/workerd/api/streams/` (`Address UAF and safety bugs in pipe
handling`, `Fix use-after-free when a native jsg::Function frees
itself mid-call`) y en `src/workerd/api/node/zlib-util.c++` -- código
que este mismo proyecto **nunca harnesseó** (los 4 targets reales de
workerd en `orchestrator/fuzz_harnesses/` son dataurl/encoding/
formdata/mimetype, ninguno toca streams ni zlib). Candidato concreto y
de alta prioridad para la próxima ronda de `harness_gen/`, no
teórico.

## Uso

```
venv/bin/python3 targets/select_targets.py [--program handle]

venv/bin/python3 targets/find_patch_directed_candidates.py \
  --repo https://github.com/cloudflare/workerd --since-days 365

venv/bin/python3 -m pytest targets/ -v
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
- `find_patch_directed_candidates.py` no está conectado todavía a
  `harness_gen/` (el candidato de `workerd`/zlib-util.c++ que encontró
  hay que pasarlo a mano a `generate_go_harness.py`/
  `generate_harness.py`) -- ambos ya toman `--repo`/función objetivo
  por separado, conectarlos directo (que el output de uno alimente al
  otro sin copiar/pegar a mano) es una extensión natural, no se hizo
  en esta ronda porque `generate_go_harness.py` es para Go y el
  candidato real que salió es C++ (`generate_harness.py`, que todavía
  no tiene loop de validación real -- ver `harness_gen/README.md`).
