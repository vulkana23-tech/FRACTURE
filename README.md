# FRACTURE

Granja de fuzzing continuo (24/7, sin supervisión) contra proyectos
open-source que están en scope de programas de bug bounty reales, con
agentes de IA manejando selección de objetivo, generación de harness,
y triage de crashes.

## Por qué existe esto (y por qué es distinto de SPECTRE)

SPECTRE (proyecto hermano, `/root/SPECTRE`) encuentra vulnerabilidades
*conocidas* (CVEs vía Trivy) y bugs de *lógica/configuración* (IDOR,
race conditions, CORS, JWT, cache poisoning, etc.) contra targets web
en producción. Es un cazador de bug bounty efectivo, pero no encuentra
**zero-days reales** — bugs de memoria/lógica que nadie descubrió
todavía. Eso sale casi siempre de fuzzing o revisión profunda de
código, un dominio técnico distinto (toolchains con sanitizers,
harnesses, corpus, triage de crashes).

FRACTURE es ese proyecto separado. Comparte el mismo VPS (18 cores,
94GB RAM, prácticamente idle — hay margen real para esto) pero es una
disciplina de trabajo distinta: no manda requests a un target en vivo,
compila y fuzzea código open-source localmente.

## Arquitectura (4 piezas)

```
targets/       -- que proyectos OSS fuzzear, y por que (scope de bounty,
                   cobertura de fuzzing existente, lenguaje memory-unsafe)
harness_gen/   -- generacion de harnesses de fuzzing asistida por IA
                   (lee la API/tests publicos del proyecto, redacta un
                   harness de libFuzzer/AFL++)
orchestrator/  -- corridas de fuzzing 24/7, gestion de corpus, paralelismo
                   entre los cores disponibles
triage/        -- dedup de crashes por stack hash, analisis de output de
                   sanitizers (ASAN/UBSAN/MSAN), clasificacion de severidad
                   real antes de mostrarle algo a un humano
```

### 1. `targets/` — selección de objetivo

Un agente elige proyectos C/C++/Rust que:
- Estén en scope de un programa de bug bounty real con payout
  confirmado (cruzar contra los programas que SPECTRE ya trackea via
  HackerOne/Bugcrowd es el punto de partida más barato — Hyperledger,
  que SPECTRE ya sigue, es un buen primer candidato: componentes en Go/C
  con historial real de CVEs de memoria).
- Tengan poca cobertura de fuzzing existente (chequear si ya están en
  OSS-Fuzz de Google primero — fuzzear algo que Google ya fuzzea 24/7
  hace años es esfuerzo desperdiciado).
- Sean de un lenguaje memory-unsafe (C/C++) o con superficie de unsafe
  real en Rust/Go (cgo, unsafe blocks) — el filtro más barato y de más
  señal antes de invertir tiempo de compute.

### 2. `harness_gen/` — generación de harness con IA

El cuello de botella clásico de fuzzing es escribir el harness (el
punto de entrada que alimenta bytes random a una función real del
proyecto). Un agente de IA (reusa Ollama, ya corriendo en este mismo
VPS para SPECTRE) lee la API pública/tests del proyecto y redacta un
primer borrador de harness — no reemplaza revisión humana antes de
correrlo, pero elimina la mayor parte del trabajo manual repetitivo.

### 3. `orchestrator/` — corridas 24/7

Gestiona instancias de libFuzzer/AFL++ corriendo en paralelo (18 cores
disponibles), persistencia de corpus entre reinicios, y rotación de
objetivos cuando uno deja de dar cobertura nueva.

### 4. `triage/` — clasificación de crashes

Un crash crudo no es un hallazgo. Este componente:
- Dedupea por stack hash (miles de crashes suelen ser 2-3 bugs
  distintos repetidos).
- Cruza contra la salida de ASAN/UBSAN/MSAN — use-after-free,
  heap-buffer-overflow, etc. son señal fuerte de severidad real vs. un
  simple "input mal formado, panic controlado".
- Recién ahí un humano revisa lo que sobrevivió el filtro.

## Estado actual

Recién arrancado (2026-08-09) — repo creado, arquitectura definida,
todavía sin implementar. Ver CHANGELOG.md a medida que avance.

## Infraestructura compartida con SPECTRE

- VPS: mismo host que SPECTRE/VettedSec/Vigia (18 cores, 94GB RAM).
- Ollama (LLM local, ya corriendo con `qwen3-coder:30b`/`llama3.1:8b`
  para SPECTRE) — reusar para harness_gen/triage en vez de levantar un
  modelo nuevo.
- Programas de bug bounty ya trackeados por SPECTRE (Postgres de
  SPECTRE, tabla `bugbounty_programs`) — punto de partida para
  `targets/`, evita reinventar el tracking de scope/payout desde cero.
