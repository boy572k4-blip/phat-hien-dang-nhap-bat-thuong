"""MR24 — bộ dữ liệu hiệu chỉnh có nhãn: tái lập theo seed, tách bộ hiệu chỉnh/đánh giá không giao nhau, nhãn đúng, IP thật
đã xác minh, và một biến thể chạy trọn qua pipeline thật. Cần GeoLite2 (backend/geoip/, không commit) — thiếu thì bỏ qua."""

import pytest

from app.detection.geoip import lookup_asn, lookup_ip
from ml.corpus.families import FAMILIES, SPLIT_SEEDS, VARIANTS_PER_FAMILY, build_variant, generate


@pytest.fixture(scope="module")
def pools():
    if lookup_ip("210.245.88.1") is None:
        pytest.skip("cần GeoLite2 (backend/geoip/) để dựng kho IP thật")
    from ml.corpus.ip_pools import build_pools

    return build_pools()


def test_every_family_is_reproducible_from_its_seed_and_varies_between_seeds(pools):
    for family in FAMILIES:
        assert build_variant(family, 3, pools) == build_variant(family, 3, pools)
        assert build_variant(family, 3, pools).steps != build_variant(family, 4, pools).steps, family


def test_calibration_and_evaluation_seeds_never_overlap_and_each_family_has_enough_variants(pools):
    assert not set(SPLIT_SEEDS["calibration"]) & set(SPLIT_SEEDS["evaluation"])
    assert VARIANTS_PER_FAMILY >= 30  # điều kiện "xong" của MR24
    calibration = generate("calibration", pools)
    evaluation = generate("evaluation", pools)
    assert len(calibration) == len(evaluation) == len(FAMILIES) * VARIANTS_PER_FAMILY
    assert not {v.id for v in calibration} & {v.id for v in evaluation}


def test_labels_attack_variants_have_attacker_steps_benign_variants_have_none(pools):
    kinds = {kind for kind, _ in FAMILIES.values()}
    assert kinds == {"attack", "benign"}
    for variant in generate("calibration", pools, per_family=5):
        malicious = [s for s in variant.steps if s.malicious]
        assert (len(malicious) > 0) == (variant.kind == "attack"), variant.id
        assert all(not h.malicious and h.success for h in variant.history)  # lịch sử = thói quen của chính chủ
        assert all(s.username in variant.accounts or s.username.startswith("ghost_") for s in variant.steps)
        assert [s.offset_s for s in variant.steps] == sorted(s.offset_s for s in variant.steps)


def test_pool_ips_are_real_and_geolocate_as_recorded(pools):
    from ml.corpus.ip_pools import ANONYMIZER_POOLS

    for name, ips in pools.items():
        assert len(ips) >= 5, name
        for info in ips[:5]:
            geo, asn = lookup_ip(info.ip), lookup_asn(info.ip)
            assert (geo.country if geo else None) == info.country and (asn.asn if asn else None) == info.asn
            if name not in ANONYMIZER_POOLS:
                assert info.latitude is not None and info.city is not None


def test_business_travel_never_moves_faster_than_a_plane(pools):
    """Ca hợp lệ "khó" phải thật sự hợp lệ: đi công tác không được rơi vào ngưỡng di chuyển bất khả thi (900 km/h)."""
    from app.utils.geo import haversine_distance

    for seed in range(30):
        steps = build_variant("business_travel", seed, pools).steps
        for a, b in zip(steps, steps[1:]):
            km = haversine_distance(a.ip.latitude, a.ip.longitude, b.ip.latitude, b.ip.longitude)
            assert km / max((b.offset_s - a.offset_s) / 3600, 1e-9) < 900


def test_one_variant_runs_through_the_real_pipeline_and_records_raw_evidence(pools, monkeypatch):
    import app.detection.pipeline as pipeline
    import app.detection.rate_counter as rate_counter
    from app.detection import hybrid_runtime
    from ml.corpus import run

    # _init_worker/_run_variant gán thẳng các biến module — đăng ký trước để monkeypatch trả lại sau test.
    monkeypatch.setattr(pipeline, "SessionLocal", pipeline.SessionLocal)
    monkeypatch.setattr(rate_counter, "redis_client", rate_counter.redis_client)
    monkeypatch.setattr(hybrid_runtime.HybridEngine, "evaluate", hybrid_runtime.HybridEngine.evaluate)
    monkeypatch.setattr(hybrid_runtime, "_engine", hybrid_runtime._engine)  # _init_worker dựng engine riêng
    try:
        run._init_worker()
    except RuntimeError as exc:
        pytest.skip(str(exc))

    record = run._run_variant(("success_after_failures", 0))

    variant = build_variant("success_after_failures", 0, pools)
    assert record["kind"] == "attack" and len(record["steps"]) == len(variant.steps) == record["events"]
    last = record["steps"][-1]
    assert last["malicious"] and last["success"] and last["action"] in ("alert", "step_up", "lock")
    assert any(rule == "success_after_failures" for rule, _shadow in last["hits"])
    assert {"ml", "ml_geo", "hits", "forced_by", "score"} <= set(last)
    assert record["alerts"] == 1  # một sự cố (MR23)
    summary = run.summarize([record])
    assert summary["success_after_failures"]["detected"] == 1.0
