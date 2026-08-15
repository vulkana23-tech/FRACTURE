# orchestrator/

Corridas de fuzzing 24/7 en paralelo (18 cores disponibles en este
VPS), gestión de corpus persistente, rotación de objetivos.

## Estado real (2026-08-15)

Implementado y probado en vivo:

- `run_rust_fuzzer.py` / `run_go_fuzzer.py` — corren UNA campaña
  puntual contra un target ya preparado (compilan, ejecutan, devuelven
  runs/crashes reales). Ya existían antes de esta ronda.
- `run_c_fuzzer.py` — agregado esta ronda: generaliza la parte de
  C que SÍ es genérica (correr un binario de libFuzzer ya compilado,
  aislar logs por corrida, juntar crashes reales -- mismo bug de
  `fuzz-N.log` en cwd que Rust, porque es libFuzzer/compiler-rt, no
  algo de Rust). Compilar SIGUE siendo específico de cada target en C
  (no hay equivalente a `cargo fuzz build`) -- eso queda en
  `orchestrator/fuzz_harnesses/*_build.sh`, un script por target, como
  ya era. Registrados los 2 binarios de C que ya existían compilados
  (`fpc_parson`, `zabbix_zbxjson`) pero que hasta ahora nunca habían
  entrado al registro/scheduler -- corrían solo a mano. Sumado un
  tercero: `fpc_unmarshal_values` (nuevo harness, encontrado vía
  `targets/find_patch_directed_candidates.py` contra
  fabric-private-chaincode -- ver `findings/2026-08-15_fabric-private-chaincode_unmarshal_values_leak.md`,
  ya encontró un leak real). Campo opcional `extra_asan_options` por
  target en `targets.json` (ej. `"detect_leaks=0"`) -- opt-in, nunca
  cambia el comportamiento default de los demás targets de C.
- `scheduler.py` — la pieza que faltaba: loop real de sweeps sobre
  `targets.json` (19 targets reales: 8 Rust vía cargo-fuzz, 8 Go vía
  `go test -fuzz`, 3 C vía libFuzzer), con:
  - **Concurrencia acotada a los cores reales** (`--max-concurrent`,
    default 2 targets a la vez con `cores/max_concurrent` workers c/u
    — evita repartir 18 cores en migajas entre muchos targets a la
    vez).
  - **Corpus persistente — ya lo resuelve cada engine, confirmado en
    vivo, no hacía falta tocar nada**: Rust guarda en
    `<crate>/fuzz/corpus/<target>/` (directorio real, no un tmpdir);
    Go usa su cache nativa (`$GOCACHE/fuzz/<import path>/`,
    confirmado con `go env GOCACHE` que ya tenía entradas de corridas
    de sesiones anteriores) — sobrevive aunque `run_go_fuzzer.py`
    borre el clon temporal del repo al terminar, porque el corpus
    real nunca vivió ahí.
  - **Rotación real**: parsea `cov:` (Rust, de la línea `DONE` de
    libFuzzer) o `new interesting:` (Go, del reporter nativo) por
    ciclo. Un target sin cobertura nueva en 3 ciclos seguidos queda
    "estancado" y corre 1 de cada 3 sweeps en vez de todas — nunca se
    excluye del todo (no hay garantía real de que "estancado ahora"
    signifique "agotado para siempre").
  - **Resiliente**: una excepción en un target (build roto, timeout,
    repo caído) se loguea y el resto de la sweep sigue — probado
    forzando el escenario, no solo leído en el código.
  - **Alertas a disco** en `orchestrator/alerts/<target_id>/<ts>/` con
    los bytes/contenido real del crash + `summary.json`, e índice en
    `orchestrator/alerts/ALERTS.md` — el punto de entrada real para
    `triage/` (todavía sin terminar, ver roadmap) o revisión manual.
  - Registro (`targets.json`) con escritura atómica (`.tmp` +
    `os.replace`) para no corromper el estado de TODOS los targets si
    el proceso muere a mitad de un guardado.

- `fracture-orchestrator.service` (systemd, `/etc/systemd/system/`) —
  `Restart=always`, sobrevive reboots igual que el resto de los
  servicios de este VPS. `Nice=10` + ioprio best-effort a propósito:
  este mismo VPS corre SPECTRE contra targets web en vivo, fuzzing es
  100% CPU-bound y no debería robarle prioridad a eso.

Probado en vivo (no solo leído): sweep real de 4 targets (2 Rust + 2
Go) con concurrencia 2, ciclos de 20s — confirmó ejecuciones reales
contadas (1.9M/83M runs), parseo de cobertura real, y el mecanismo de
alerta de crash con un crash sintético inyectado a mano (bytes
preservados, `summary.json` + `ALERTS.md` generados correctamente). La
lógica de rotación por estancamiento también se validó por separado
(4 sweeps simuladas, target estancado corrió en la sweep #3 como se
esperaba, no en 1/2/4).

## Uso

```
# modo real, 24/7 (lo que corre el systemd service):
venv/bin/python3 orchestrator/scheduler.py --cycle-duration 2400 --max-concurrent 2

# prueba corta, una sola sweep:
venv/bin/python3 orchestrator/scheduler.py --cycle-duration 30 --max-concurrent 3 --sweeps 1

# como servicio real:
systemctl enable --now fracture-orchestrator
journalctl -u fracture-orchestrator -f
```

## Capacidad real / escala (2026-08-15)

Medido en vivo, no supuesto: con la config actual (`--max-concurrent 2`,
9 workers por target) y 18 targets reales en el registro, `mpstat -P ALL`
dio **0.00% idle promediado en los 18 cores durante la corrida real**
del daemon. Este VPS no tiene margen de CPU sin usar -- subir la
concurrencia no agrega throughput agregado nuevo, solo cambia CÓMO se
reparte el mismo total de cores entre profundidad (menos targets a la
vez, más workers c/u) y amplitud (más targets a la vez, menos workers
c/u).

**La cuenta real de cadencia** con la config actual: 18 targets × 40min
de ciclo / 2 concurrentes ≈ 6h por sweep completa ≈ ~4 sweeps/día ≈
~2.7h de fuzzing real acumulado por target por día. Razonable, no un
problema real que haya que resolver -- se documenta acá para que la
próxima persona que toque `--max-concurrent` lo cambie con el número
real en la mano, no a ojo. Si se quiere más amplitud (tocar los 18
targets más seguido) a costa de menos profundidad por ciclo,
`--max-concurrent 6` (3 workers c/u) es un cambio de un solo flag,
probado en vivo que funciona -- no se cambió el default de 2 porque no
hay evidencia real de que la cadencia actual esté causando un problema
concreto, solo el trade-off en sí.

**Sobre "fuzzing distribuido"**: no está construido, y no se fabricó
nada que aparente estarlo. Este VPS es la única máquina disponible --
distribuir de verdad necesita infraestructura adicional real (otro
VPS, burst a la nube) que es una decisión de costo/infra del usuario,
no algo para asumir o inventar en una sesión de código.

**Sobre "snapshot/persistent mode"**: la recomendación original (de la
ronda de "qué le falta a FRACTURE") asumía el mundo de AFL++ clásico,
donde fork-per-iteration es un costo real que ese modo elimina. No
aplica igual acá -- libFuzzer (Rust vía cargo-fuzz, C) YA corre
in-process/persistente por diseño (un solo proceso llama
`LLVMFuzzerTestOneInput` en loop, sin fork por iteración), y el
fuzzing nativo de Go (`go test -fuzz`) también. No hay una
optimización real de "modo persistente" pendiente para el stack que
este proyecto realmente usa -- corregido acá en vez de repetir la
recomendación genérica sin chequear si aplicaba de verdad.

## Lo que falta (honesto)

- ~~El total de ejecuciones para targets Go queda en 0~~ **cerrado
  (2026-08-15)**: `go test -fuzz` sí imprime un contador acumulado real
  (`fuzz: elapsed: 8s, execs: 121195 (16635/sec), new interesting:
  0...`) -- el último `execs:` de la corrida ya es el total (no
  incremental como `new interesting:`, no hace falta sumar). Probado
  en vivo contra `fabric_ca_decode_token`: `lifetime_runs` pasó de 0 a
  317,440 en una corrida de 10s.
- La detección de "estancado" es una heurística simple (cobertura
  plana N ciclos seguidos) — no sabe distinguir "este target ya no da
  más" de "esta seed particular tuvo mala suerte 3 veces seguidas".
  Suficiente para no gastar los mismos cores infinitamente en algo
  chato, no es ciencia exacta.
- ~~No hay engine para JVM (Jazzer)~~ **cerrado (2026-08-16)**:
  `run_jvm_fuzzer.py` (mismo patrón que `run_c_fuzzer.py`, Jazzer
  envuelve libFuzzer -- confirmado en vivo que imprime el mismo
  formato real de `cov:`/`Done N runs`). JDK 21 + Jazzer standalone
  0.30.0 instalados. Primer target real:
  `fabric_chaincode_java_parseattributes`
  (`ClientIdentity.parseAttributes`, fabric-chaincode-java -- mismo
  patrón real ya fuzzeado en Go/C++ por este proyecto: atributos de
  identidad codificados en JSON dentro de una extensión de certificado
  X.509). Encontró **3+ tipos distintos de excepciones reales sin
  capturar** en menos de 20s de fuzzing real -- ver
  `findings/2026-08-16_fabric-chaincode-java_parseattributes_uncaught_exceptions.md`.
  21er target del registro.

  Dos bugs propios encontrados construyendo esto: un flag con doble
  guion en vez de uno solo (`--artifact_prefix` vs `-artifact_prefix`)
  que hacía fallar la corrida real en silencio (quedó escondido porque
  ya había un crash viejo de la investigación manual en `artifact_dir`,
  documentado en el finding); y el log de Jazzer, mucho más verboso
  que ASAN/Rust (una línea por CADA clase instrumentada), enterraba el
  crash real fuera de la ventana de recorte de 3000 caracteres que
  alcanzaba para los demás engines -- subida a 50000 solo para JVM.

- **Sigue sin engine para fuzzing binario (QEMU mode de AFL++/Frida,
  para targets closed-source sin fuente)** -- toolchain aparte
  (requiere compilar AFL++ con soporte QEMU), más pesado que agregar
  un `elif` nuevo. No se hizo en esta ronda.
