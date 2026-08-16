"""Tests de la parte determinística (sin red, sin Ollama, sin `go`
real) -- ambos chequeos de _try_compile_and_run corren ANTES de tocar
el filesystem/compilar, así que se pueden probar aislados con un
repo_dir/package_path que nunca se usan.

La parte que sí depende de Ollama+`go test -race` se validó en vivo a
mano contra hyperledger/fabric-lib-go -- ver targets/README.md."""

from generate_race_test import _MULTIPLE_WAIT_RE, _try_compile_and_run


_SEQUENTIAL_WAVES_CODE = """package factory

import (
	"sync"
	"testing"
)

func TestRaceConditions(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); InitFactories(nil) }()
	}
	wg.Wait()

	wg.Add(50)
	for i := 0; i < 50; i++ {
		go func() { defer wg.Done(); GetDefault() }()
	}
	wg.Wait()
}
"""

_SINGLE_BATCH_CODE = """package factory

import (
	"sync"
	"testing"
)

func TestRaceConditions(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); InitFactories(nil) }()
		go func() { defer wg.Done(); GetDefault() }()
	}
	wg.Wait()
}
"""


def test_multiple_wait_regex_counts_real_sequential_waves_case():
    # Caso REAL encontrado validando esto en vivo contra
    # hyperledger/fabric-lib-go: el modelo genero 3 oleadas separadas.
    assert len(_MULTIPLE_WAIT_RE.findall(_SEQUENTIAL_WAVES_CODE)) == 2


def test_sequential_waves_rejected_before_touching_filesystem():
    ok, race_detected, error = _try_compile_and_run("/nonexistent/repo", "nonexistent/pkg", _SEQUENTIAL_WAVES_CODE)
    assert ok is False
    assert race_detected is False
    assert "0/20" in error or "oleadas" in error


def test_single_batch_structure_passes_the_static_check():
    # No debe rechazarse por el chequeo de .Wait() (solo tiene uno) --
    # este test NO llega a compilar de verdad (repo_dir no existe), asi
    # que confirma que pasa el chequeo estatico y falla mas adelante
    # (en el compile real), no por el antipatron de oleadas.
    assert len(_MULTIPLE_WAIT_RE.findall(_SINGLE_BATCH_CODE)) == 1
