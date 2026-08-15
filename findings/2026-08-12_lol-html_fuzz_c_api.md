# lol-html — fuzz_c_api (C API real usada por workerd) — resultado limpio

**Programa:** Cloudflare (HackerOne `hackerone.com/cloudflare`, `automated_scanning: allowed` para `workerd`)
**Repo fuzzeado:** `cloudflare/lol-html` (Tier 1, Rust con parsing/FFI en la frontera C) -- la
librería real detrás de `HTMLRewriter` en `workerd/src/workerd/api/html-rewriter.c++`
(`#include <lol_html.h>`). No cubierto por OSS-Fuzz (confirmado: 404 en
`google/oss-fuzz` para `lol-html`/`lol_html`).

## Contexto: por qué este target y no workerd directo

`html-rewriter.c++` (1334 líneas) es mayormente bindings C++ sobre la
API C de `lol_html` con clases `jsg::Object` (arrastran V8 completo,
mismo obstáculo que `TextEncoder`/`TextDecoder` en el finding de
`encoding.c++`). La lógica de parseo/rewriting real de HTML vive en
`lol_html` mismo, no en el wrapper. En vez de fakear la capa V8 del
wrapper, se fuzzeó `lol_html` directo vía la MISMA API C
(`fuzz_c_api.rs` → `run_c_api_rewriter`) que `workerd` usa en
producción -- un bug de memoria acá es un bug real independientemente
de qué lado (Cloudflare mantiene ambos repos).

## Setup

`lol-html` ya trae su propia infraestructura de fuzzing
(`fuzz/fuzz_targets/fuzz_c_api.rs`, `fuzz_rewriter.rs`, diccionarios de
tags HTML, configs de AFL/Hongfuzz) -- no hizo falta escribir un harness
nuevo, solo `cargo +nightly fuzz build fuzz_c_api` (compiló limpio a la
primera) y correrlo. Instalado Rust (rustup, toolchain stable + nightly)
y `cargo-fuzz` en esta sesión (no estaban disponibles antes).

## Resultado

- Smoke test: 30s con diccionario de tags HTML, 1,196,247 ejecuciones,
  limpio.
- Campaña completa: `-fork=18`, 2400s (40 min), **812,554,327+
  ejecuciones reales**, `oom/timeout/crash: 0/0/0` estable en toda la
  corrida. Cobertura (`cov`/`ft`) estable en 1232/5530 bastante antes
  del final -- corpus saturado.
- Sin artefactos de crash generados.

## Conclusión honesta

Limpio, con alta confianza. No se reporta nada a Cloudflare. Nota para
la próxima sesión: se evaluó también `brave/brave-core`
(`components/speedreader/rust`, código propio de Brave para reader
mode) como candidato -- Rust real, no cubierto por OSS-Fuzz, harness ya
armado y compilado (`readability` crate, función `extractor::extract`)
-- pero se frenó antes de correr la campaña porque la policy de
`automated_scanning` de Brave en HackerOne dio `unclear` (no `allowed`
explícito), y se decidió no proceder para mantener el mismo criterio
fail-closed aplicado en el resto del proyecto. El harness queda armado
en `/root/.claude/jobs/b5bac52f/tmp/brave_check/` (ruta de scratch, no
persistente) si se quiere retomar despues de confirmar la policy por
otro canal.
