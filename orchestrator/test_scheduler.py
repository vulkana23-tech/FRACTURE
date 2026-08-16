"""Tests reales de la logica de scheduling (no corren fuzzing de verdad --
mockean _run_target_safely para inspeccionar que duracion/que targets
recibio, igual que test_generate_go_harness.py mockea solo la parte
que necesita red/tiempo real).

Cubre la decision real del 2026-08-16 (ver comentario en scheduler.py
arriba de _HIGH_PRIORITY_DURATION_MULTIPLIER/_LOW_PRIORITY_SKIP_MODULO):
targets con reachability ya probada corren con MAS tiempo por sweep
(priority=high), targets con bug confirmado pero sin reachability
conocida corren mucho menos seguido (priority=low), y un target sin
el campo "priority" en absoluto (la gran mayoria del registro real)
se comporta exactamente igual que antes de este cambio."""

import scheduler


def _target(id_, priority=None, plateau_streak=0):
    t = {"id": id_, "engine": "c", "state": {"plateau_streak": plateau_streak}}
    if priority is not None:
        t["priority"] = priority
    return t


def test_duration_for_high_priority_multiplies_base_duration():
    t = _target("fpc_parson_json_parse_string", priority="high")
    assert scheduler._duration_for(t, 100) == 100 * scheduler._HIGH_PRIORITY_DURATION_MULTIPLIER


def test_duration_for_low_priority_uses_base_duration_unchanged():
    t = _target("fabric_amcl_dilithium_verify2", priority="low")
    assert scheduler._duration_for(t, 100) == 100


def test_duration_for_no_priority_field_uses_base_duration_unchanged():
    # La gran mayoria de targets.json no tiene "priority" -- default
    # real es "normal" (sin multiplicar), no debe romperse.
    t = _target("fabric_ca_decode_token")
    assert scheduler._duration_for(t, 100) == 100


def test_run_sweep_skips_low_priority_target_on_non_eligible_sweep(monkeypatch):
    calls = []
    monkeypatch.setattr(scheduler, "_run_target_safely",
                         lambda t, d, w: calls.append((t["id"], d)))

    low = _target("rust_fil_proofs_fr32_write_unpadded", priority="low")
    normal = _target("fabric_ca_decode_token")
    # sweep_number=1 no es multiplo de _LOW_PRIORITY_SKIP_MODULO (6)
    scheduler.run_sweep([low, normal], sweep_number=1, duration_seconds=100,
                        max_concurrent=2, cores=2)

    called_ids = {c[0] for c in calls}
    assert "rust_fil_proofs_fr32_write_unpadded" not in called_ids
    assert "fabric_ca_decode_token" in called_ids


def test_run_sweep_runs_low_priority_target_on_eligible_sweep(monkeypatch):
    calls = []
    monkeypatch.setattr(scheduler, "_run_target_safely",
                         lambda t, d, w: calls.append((t["id"], d)))

    low = _target("rust_fil_proofs_fr32_write_unpadded", priority="low")
    # sweep_number=6 SI es multiplo de _LOW_PRIORITY_SKIP_MODULO
    scheduler.run_sweep([low], sweep_number=6, duration_seconds=100,
                        max_concurrent=1, cores=1)

    assert calls == [("rust_fil_proofs_fr32_write_unpadded", 100)]


def test_run_sweep_passes_multiplied_duration_to_high_priority_target(monkeypatch):
    calls = []
    monkeypatch.setattr(scheduler, "_run_target_safely",
                         lambda t, d, w: calls.append((t["id"], d)))

    high = _target("fpc_parson_json_parse_string", priority="high")
    scheduler.run_sweep([high], sweep_number=1, duration_seconds=100,
                        max_concurrent=1, cores=1)

    assert calls == [("fpc_parson_json_parse_string",
                       100 * scheduler._HIGH_PRIORITY_DURATION_MULTIPLIER)]


def test_run_sweep_low_priority_skip_takes_precedence_over_plateau_check(monkeypatch):
    # Un target low-priority Y estancado igual se saltea por la regla
    # de low-priority (no hace falta que las dos condiciones coincidan
    # para que se saltee -- cualquiera de las dos alcanza).
    calls = []
    monkeypatch.setattr(scheduler, "_run_target_safely",
                         lambda t, d, w: calls.append(t["id"]))

    low_and_plateaued = _target("fabric_amcl_dilithium_verify2", priority="low",
                                 plateau_streak=scheduler._PLATEAU_CYCLES)
    scheduler.run_sweep([low_and_plateaued], sweep_number=3, duration_seconds=100,
                        max_concurrent=1, cores=1)

    assert calls == []
