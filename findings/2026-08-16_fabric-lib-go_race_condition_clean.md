# fabric-lib-go — `bccsp/factory` (fix real de race condition) — resultado limpio, nuevo pipeline de concurrencia

**Estado**: test de estrés de concurrencia real corrido (`go test
-race`), **sin carrera detectada** contra HEAD actual. Resultado
honesto, no un bug -- pero valida un pipeline completamente nuevo:
detección de race conditions vía el detector nativo de Go, primera vez
que este proyecto ataca esta CLASE de bug (no fuzzing de bytes).

## Cómo se encontró el candidato

Vía `targets/find_patch_directed_candidates.py` contra
`hyperledger/fabric-lib-go`: el commit real `8fe16c9967` ("Use
atomic.Pointer to prevent race condition in bccsp.Factory (#48)",
2026-03-24) reemplazó variables `bccsp.BCCSP` planas, escritas bajo
`sync.Once` pero leídas sin ninguna sincronización desde otra goroutine,
por `atomic.Pointer[bccsp.BCCSP]` -- una carrera de datos clásica
(escritura/lectura no sincronizada de un puntero de interfaz).

Esta clase de bug (`race condition`/`data race`/`deadlock`) ya la
detectaba `_SECURITY_KEYWORDS`, pero hasta ahora se descartaba siempre
como "no fuzzeable con libFuzzer" -- cierto para fuzzing de bytes, pero
Go trae su propio detector de razas (`-race`, ThreadSanitizer) que
encuentra esto ejercitando el código real bajo concurrencia, sin
ningún byte de entrada.

## Validación manual primero (antes de automatizar)

Un stress test escrito a mano (2 goroutines, `InitFactories`/
`GetDefault` lanzadas concurrentemente en la misma iteración) detectó
la carrera real en la versión PRE-fix (el commit padre de
`8fe16c9967`) en **0.027s**, y salió limpio en la versión POST-fix --
confirmó que la técnica funciona de verdad antes de construir el
pipeline automático (`harness_gen/generate_race_test.py` +
`targets/patch_directed_race_harness.py`).

## Dos bugs reales encontrados automatizando esto

1. **Funciones de test coladas**: el commit real también toca
   `factory_test.go` -- sin filtrar, se colaron 11 nombres (incluido
   `TestBootBCCSPConcurrent`, el propio test de regresión que el repo
   real escribió para esta carrera) en un solo prompt, y el modelo no
   compiló nada coherente en 3 intentos. Corregido filtrando por la
   convención real de Go (`^Test`).

2. **El más serio -- "compila y corre" no implica "puede detectar la
   carrera"**: con el filtro de arriba, el modelo generó un test que
   SÍ pasaba la validación (compilaba, corría, sin error) pero con 3
   oleadas SECUENCIALES de goroutines (`wg.Wait()` entre cada una).
   Reproducido el patrón exacto contra una carrera real conocida en un
   paquete Go mínimo, corrido 20 veces cada estructura: oleadas
   separadas = **0/20 detecciones**; mismas goroutines mezcladas en un
   solo lote = **20/20**. Un resultado "limpio" con esa estructura
   habría sido indistinguible de un falso negativo. Corregido con
   regla explícita en el prompt (con la evidencia real 0/20 vs 20/20)
   + un chequeo determinístico que cuenta `.Wait()` en el código
   generado y rechaza antes de compilar si hay más de uno.

## El test final (estructura correcta, primer intento post-fix)

`orchestrator/fuzz_tests/fabric_lib_go_factory_race_test.go`:

```go
func TestRaceConditions(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			config := GetDefaultOpts()
			InitFactories(config)
			GetDefault()
		}()
	}
	wg.Wait()
}
```

Un solo lote, `InitFactories` y `GetDefault` en la misma goroutine, un
único `wg.Wait()` al final -- exactamente la estructura que sí puede
detectar la carrera si existiera.

## Resultado real

Corrida real contra HEAD de `hyperledger/fabric-lib-go`: **sin carrera
detectada**. El fix real (`atomic.Pointer`) es sólido. No registrado en
`orchestrator/targets.json` (el daemon 24/7 corre campañas de corpus
continuo, un test de race no tiene corpus que crecer -- ver "lo que
falta" en `targets/README.md`); este pipeline queda como herramienta
on-demand de descubrimiento, no integrada al scheduler todavía.
