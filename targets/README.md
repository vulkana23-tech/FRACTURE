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

**Resultado real contra `cloudflare/workerd`** (1 año): encontró 8
commits reales relacionados a seguridad. **Corrección honesta post-
revisión manual (2026-08-15)**: los 3 candidatos revisados a fondo
(UAF en `streams/`, UAF en `jsg::Function`, bypass de flag RPC en
deserialización de wrapped-binding) resultaron ser **bugs de ciclo de
vida de V8/JS** (re-entrancy vía `toString()` de usuario, GC de
ArrayBuffers, semántica de capacidades RPC) -- no bugs de parseo de
bytes no confiables. Ese tipo de bug necesita ejecutar JS real dentro
del motor V8 en una secuencia específica de llamadas (exactamente lo
que los tests `autovuln-*.js`/`.wd-test` del propio workerd ya hacen),
no algo que un harness `bytes -> función` de libFuzzer pueda
encontrar. Se intentó generar un harness igual (`dale, arrancá con
harness_gen para el candidato de workerd`) y se descartó honestamente
en vez de forzar algo que no iba a funcionar -- ver
`harness_gen/README.md`. Conclusión real: el filtro actual (mensaje +
extensión de archivo) encuentra commits de seguridad reales, pero no
distingue la FORMA del bug (parseo de bytes vs. lógica/lifecycle de
runtime) -- ver "Lo que falta" abajo.

**Resultado real contra `hyperledger/fabric-private-chaincode`** (2
años): encontró el commit real `1e92847744` ("Fix null pointer issuer
in unmarshal_values", 2025-03-29) -- la MISMA función que ya motivó el
harness de parson existente en este proyecto, pero cubriendo mucho
menos que la función completa. Se construyó un harness nuevo
(`fpc_unmarshal_values_harness.c++`) que sí replica la función
completa (post-fix) -- encontró un memory leak real en el primer
intento (LeakSanitizer, `[{"key":"a"}]` sin campo `"value"` no libera
el `JSON_Value*`). Ver
`findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md`.
Este SÍ era la forma correcta de bug (parseo de bytes no confiables
dentro de un enclave SGX) -- contraste real y útil con el caso de
`workerd` de arriba.

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
- **No distingue la FORMA del bug** -- un commit puede mencionar "UAF"
  o "null pointer" de verdad y aun así ser un bug de lifecycle de V8/JS
  (necesita el motor JS real corriendo) en vez de un bug de parseo de
  bytes (fuzzeable con libFuzzer). El caso real de `workerd` de arriba
  es exactamente esto. No hay heurística barata conocida para
  distinguirlos solo del mensaje de commit -- hace falta leer el diff
  real (lo que se hizo a mano esta ronda) o, mejor señal automática:
  si la función tocada tiene `jsg::Lock`/`v8::` en su firma, es
  candidato a descartar de entrada. No implementado todavía.
- `find_patch_directed_candidates.py` no está conectado todavía a
  `harness_gen/` de forma automática (los candidatos reales que
  encontró se pasaron a mano a `generate_go_harness.py`/
  `generate_harness.py`) -- ambos ya toman `--repo`/función objetivo
  por separado, conectarlos directo (que el output de uno alimente al
  otro sin copiar/pegar a mano) es una extensión natural, no se hizo
  en esta ronda porque `generate_go_harness.py` es para Go y el primer
  candidato real que se investigó a fondo era C++ (`generate_harness.py`, que todavía
  no tiene loop de validación real -- ver `harness_gen/README.md`).
