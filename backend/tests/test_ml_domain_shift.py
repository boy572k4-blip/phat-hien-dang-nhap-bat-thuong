"""MR26 — độ lệch miền của `hybrid_cp2` (`ml/corpus/calibrate_ml.py`): Δ = phân vị lưu lượng hợp lệ của hệ thống − phân vị
hợp lệ của RBA, chỉ dùng lưu lượng HỢP LỆ, không âm, khoảng tin cậy theo biến thể; hồ sơ đang dùng mang Δ có nguồn."""

import numpy as np
import pytest

from app.detection.hybrid import ActionBands, HybridProfile, MonotonicCalibrator, MlDomainShift, RuleWeights
from ml.corpus import calibrate_ml as cm


def _variant(kind, steps, family="f"):
    return {"family": family, "kind": kind, "steps": steps}


def _step(raw, success=True, malicious=False, hits=(), ml_geo=None):
    return {"ml_raw": raw, "success": success, "malicious": malicious, "hits": [[h, False] for h in hits], "ml_geo": ml_geo}


def test_weighted_quantile_respects_weights():
    values, weights = np.array([1.0, 2.0, 3.0]), np.array([1.0, 1.0, 8.0])
    assert cm.weighted_quantile(values, weights, 0.5) == 3.0
    assert cm.weighted_quantile(values, np.ones(3), 0.5) == 2.0


def test_the_shift_uses_only_legit_traffic_and_is_never_negative():
    rng = np.random.default_rng(0)
    legit = [_variant("benign", [_step(float(x)) for x in rng.normal(3.0, 0.3, 5)] + [_step(0.2, success=False)]) for _ in range(60)]
    attacks = [_variant("attack", [_step(9.0, malicious=True)] * 5) for _ in range(60)]  # điểm tấn công không được kéo Δ
    shift = cm.estimate_shift(legit + attacks, {"success": 1.0, "failure": 2.0}, quantile=0.5, n_boot=50)
    assert shift.success == pytest.approx(2.0, abs=0.1) and shift.failure == 0.0  # lần thất bại hợp lệ thấp hơn RBA -> chặn 0
    assert shift.ci95_success[0] <= shift.success <= shift.ci95_success[1]
    assert shift.source == "corpus_mr24" and shift.n_reference == 300


def test_replay_uses_the_profile_shift_and_can_isolate_the_model():
    profile = HybridProfile(RuleWeights(), ActionBands(32, 58, 70), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)))
    record = [_variant("benign", [_step(2.0, hits=("tor_exit",)), _step(2.0, success=False)])]
    shifted = HybridProfile(profile.weights, profile.bands, profile.ml_calibration, MlDomainShift(success=2.0))
    assert cm.replay(record, profile, with_rules=False) == [["alert", "alert"]]  # 0,4 ≥ 0,32
    assert cm.replay(record, shifted, with_rules=False) == [["allow", "alert"]]  # chỉ lần thành công được trừ Δ


def test_the_geo_option_caps_the_geo_source_only_in_the_comparison():
    profile = HybridProfile(RuleWeights(), ActionBands(32, 58, 70), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)))
    record = [_variant("benign", [_step(0.0, ml_geo=0.382)])]
    assert cm.replay(record, profile) == [["alert"]]
    assert cm.replay(record, profile, geo_cap=0.31) == [["allow"]]


def test_the_shipped_profile_carries_a_measured_domain_shift():
    profile = HybridProfile.from_file(cm.PROFILE_PATH)
    shift = profile.ml_domain_shift
    assert shift is not None and shift.source == "corpus_mr24" and shift.quantile == cm.QUANTILE
    assert shift.success > 0 and shift.failure == 0.0 and shift.ci95_success[0] <= shift.success <= shift.ci95_success[1]
    assert shift.rba_median_success is not None


def test_rerunning_the_rba_calibration_keeps_the_domain_shift(tmp_path, monkeypatch):
    """`python -m ml.rba.hybrid_calibrate` (MR11) ghi lại hồ sơ — không được xoá độ lệch miền (MR26) và trọng số MR25."""
    import json

    from ml.rba import hybrid_calibrate

    current = tmp_path / "profile.json"
    current.write_text(json.dumps({"rule_weights": {"weights": {"tor_exit": {"weight": 0.57, "calibrated": True, "n": 1, "ci95": None, "source": "corpus_mr24_capped"}}},
                                   "bands": {"alert_at": 32, "step_up_at": 58, "lock_at": 70}, "ml_calibration": None,
                                   "ml_domain_shift": {"success": 1.5}}), encoding="utf-8")
    monkeypatch.setattr(hybrid_calibrate, "PROFILE_PATH", current)
    fresh = {"rule_weights": {"weights": {"tor_exit": {"weight": 0.05, "calibrated": False, "n": 0, "ci95": None}}},
             "bands": {"alert_at": 32, "step_up_at": 58, "lock_at": 70}, "ml_calibration": None}
    kept = hybrid_calibrate._keep_corpus_weights(fresh)
    assert kept["ml_domain_shift"] == {"success": 1.5} and kept["rule_weights"]["weights"]["tor_exit"]["weight"] == 0.57
