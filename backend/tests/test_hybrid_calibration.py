"""MR11 — kiểu dữ liệu của hồ sơ hybrid risk engine: hiệu chỉnh đơn điệu, trọng số luật, ngưỡng hành động, round-trip JSON."""

import json

import pytest

from app.detection.hybrid.calibration import (
    ActionBands,
    HybridConfigError,
    HybridProfile,
    MonotonicCalibrator,
    RuleWeightEntry,
    RuleWeights,
    geo_cap,
    geo_probability,
)
from app.detection.hybrid.combine import noisy_or


# ------------------------------------------------------------------------------------------------ MonotonicCalibrator


def test_interpolates_linearly_between_breakpoints_and_clamps_outside_the_range():
    cal = MonotonicCalibrator((0.0, 2.0, 4.0), (0.0, 0.5, 1.0))
    assert cal.probability(1.0) == pytest.approx(0.25) and cal.probability(3.0) == pytest.approx(0.75)
    assert cal.probability(-10.0) == 0.0 and cal.probability(100.0) == 1.0  # giữ nguyên giá trị biên, không ngoại suy


def test_probability_preserves_scalar_vs_array_input():
    cal = MonotonicCalibrator((0.0, 1.0), (0.0, 1.0))
    single = cal.probability(0.5)
    assert isinstance(single, float) and single == pytest.approx(0.5)
    batch = cal.probability([0.0, 0.5, 1.0])
    assert list(batch) == pytest.approx([0.0, 0.5, 1.0]) and batch.shape == (3,)


@pytest.mark.parametrize(
    "xs,ys,match",
    [
        ((0.0,), (0.0,), "ít nhất 2"),
        ((0.0, 1.0), (0.0, 1.0, 2.0), "cùng độ dài"),
        ((1.0, 1.0), (0.0, 1.0), "tăng NGẶT"),
        ((0.0, 1.0, 2.0), (0.5, 0.4, 0.6), "không giảm"),
        ((0.0, 1.0), (-0.1, 0.5), r"\[0, 1\]"),
        ((0.0, 1.0), (0.5, 1.5), r"\[0, 1\]"),
    ],
)
def test_rejects_malformed_breakpoints(xs, ys, match):
    with pytest.raises(HybridConfigError, match=match):
        MonotonicCalibrator(xs, ys)


def test_calibrator_round_trips_through_json():
    cal = MonotonicCalibrator((0.0, 1.5, 3.0), (0.1, 0.4, 0.9))
    restored = MonotonicCalibrator.from_dict(json.loads(json.dumps(cal.to_dict())))
    assert restored == cal
    with pytest.raises(HybridConfigError):
        MonotonicCalibrator.from_dict({"xs": [0.0, 1.0]})  # thiếu "ys"


# ------------------------------------------------------------------------------------------------ RuleWeightEntry / RuleWeights


@pytest.mark.parametrize("kwargs", [{"weight": 1.5}, {"weight": 0.2, "n": -1}, {"weight": 0.2, "ci95": (0.5, 0.1)}])
def test_rule_weight_entry_validates_its_fields(kwargs):
    RuleWeightEntry(0.2, True, 500, (0.1, 0.3))  # hợp lệ, không raise
    with pytest.raises(HybridConfigError):
        RuleWeightEntry(kwargs.get("weight", 0.2), True, kwargs.get("n", 0), kwargs.get("ci95"))


def test_rule_weight_entry_round_trips_including_a_missing_ci():
    entry = RuleWeightEntry(0.31, True, 812, (0.20, 0.45))
    assert RuleWeightEntry.from_dict(json.loads(json.dumps(entry.to_dict()))) == entry
    no_ci = RuleWeightEntry(0.05, False)
    assert RuleWeightEntry.from_dict(json.loads(json.dumps(no_ci.to_dict()))) == no_ci


def test_rule_weights_falls_back_to_the_default_for_unknown_rules():
    weights = RuleWeights({"brute_force": RuleWeightEntry(0.4, True, 10)}, default_weight=0.07)
    assert weights.weight_of("brute_force") == 0.4 and weights.weight_of("some_future_rule") == 0.07


def test_rule_weights_round_trips():
    weights = RuleWeights({"brute_force": RuleWeightEntry(0.4, True, 10, (0.2, 0.6)), "blocklist_hit": RuleWeightEntry(1.0, False)}, 0.05)
    restored = RuleWeights.from_dict(json.loads(json.dumps(weights.to_dict())))
    assert restored.entries == weights.entries and restored.default_weight == weights.default_weight
    assert RuleWeights.from_dict({}).weight_of("anything") == 0.05  # hồ sơ rỗng vẫn nạp được, dùng toàn mặc định


def test_a_profile_from_before_mr21_with_an_override_list_still_loads():
    """MR21 bỏ `override_rule_ids` (thay bằng `min_action` của luật) — hồ sơ cũ còn khoá đó vẫn phải nạp được, khoá bị bỏ qua."""
    legacy = {"weights": {"brute_force": {"weight": 0.1, "calibrated": True, "n": 5, "ci95": None}}, "override_rule_ids": ["blocklist_hit"], "default_weight": 0.05}
    weights = RuleWeights.from_dict(legacy)
    assert weights.weight_of("brute_force") == 0.1 and "override_rule_ids" not in weights.to_dict()


def test_action_floor_is_the_lowest_score_of_each_action():
    bands = ActionBands(30, 60, 90)
    assert [bands.floor(a) for a in ("allow", "alert", "step_up", "lock")] == [0, 30, 60, 90]
    assert all(bands.classify(bands.floor(a)) == a for a in ("allow", "alert", "step_up", "lock"))


def test_rule_weights_rejects_an_out_of_range_default():
    with pytest.raises(HybridConfigError):
        RuleWeights(default_weight=1.5)


# ------------------------------------------------------------------------------------------------ ActionBands


def test_classifies_scores_into_the_four_actions_with_closed_open_boundaries():
    bands = ActionBands(30, 60, 90)
    assert [bands.classify(s) for s in (0, 29, 30, 59, 60, 89, 90, 100)] == ["allow", "allow", "alert", "alert", "step_up", "step_up", "lock", "lock"]


@pytest.mark.parametrize("alert_at,step_up_at,lock_at", [(60, 30, 90), (30, 90, 60), (30, 30, 90), (-1, 30, 90), (30, 30, 30), (10, 20, 101)])
def test_rejects_bands_that_are_not_a_strictly_increasing_triple_within_0_100(alert_at, step_up_at, lock_at):
    with pytest.raises(HybridConfigError):
        ActionBands(alert_at, step_up_at, lock_at)


def test_bands_round_trip_through_json():
    bands = ActionBands(12, 45, 88)
    assert ActionBands.from_dict(json.loads(json.dumps(bands.to_dict()))) == bands


# ------------------------------------------------------------------------------------------------ MR22: nguồn ml_geo

RBA_BANDS = ActionBands(32, 58, 70)  # ngưỡng của hồ sơ rba_calibrated.json


def test_geo_probability_is_anchored_at_the_alert_threshold():
    """Biên độ 0 (đúng ngưỡng của mô hình) -> đúng alert_at/100: một mình tầng 3 cảnh báo đúng khi mô hình gắn cờ."""
    for bands in (RBA_BANDS, ActionBands(40, 65, 85)):
        assert geo_probability(0.0, 48.0, bands) == pytest.approx(bands.alert_at / 100)
        assert bands.classify(round(geo_probability(1e-4, 48.0, bands) * 100)) == "alert"
        assert bands.classify(round(geo_probability(-0.05, 48.0, bands) * 100)) == "allow"


def test_geo_probability_is_monotonic_and_bounded_by_the_cap():
    margins = [-1.0, -0.1, -0.02, 0.0, 0.002, 0.01, 0.1, 5.0]
    values = [geo_probability(m, 48.0, RBA_BANDS) for m in margins]
    assert values == sorted(values) and values[0] >= 0.0
    assert max(values) == pytest.approx(geo_cap(RBA_BANDS))


def test_geo_probability_survives_extreme_margins():
    assert geo_probability(-1e9, 48.0, RBA_BANDS) == 0.0  # không tràn số
    assert geo_probability(1e9, 48.0, RBA_BANDS) == pytest.approx(geo_cap(RBA_BANDS))


def test_the_geo_cap_means_the_geo_model_plus_one_more_alert_worthy_signal_reaches_step_up():
    """Định nghĩa của trần: noisy-OR(trần, alert_at) = step_up_at — một mình chỉ cảnh báo, thêm một tín hiệu độc lập đủ
    cảnh báo thì mới yêu cầu xác thực thêm."""
    cap = geo_cap(RBA_BANDS)
    assert cap == pytest.approx(1 - 0.42 / 0.68)  # 0,382 với ngưỡng 32/58
    assert RBA_BANDS.alert_at / 100 < cap < RBA_BANDS.step_up_at / 100
    assert noisy_or([cap, RBA_BANDS.alert_at / 100]) == pytest.approx(RBA_BANDS.step_up_at / 100)


def test_the_geo_cap_never_falls_below_the_alert_threshold():
    narrow = ActionBands(45, 50, 90)  # công thức cho 0,09 < 0,45: khi đó giữ ngưỡng alert để tầng 3 một mình vẫn cảnh báo được
    assert geo_cap(narrow) == pytest.approx(0.45)
    assert geo_probability(1.0, 48.0, narrow) == pytest.approx(0.45)


# ------------------------------------------------------------------------------------------------ HybridProfile


def _profile(with_ml=True):
    weights = RuleWeights({"brute_force": RuleWeightEntry(0.3, True, 50, (0.1, 0.5))})
    bands = ActionBands(20, 50, 85)
    calibration = MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)) if with_ml else None
    return HybridProfile(weights, bands, calibration)


def test_profile_round_trips_with_and_without_an_ml_calibration(tmp_path):
    for with_ml in (True, False):
        profile = _profile(with_ml)
        restored = HybridProfile.from_dict(json.loads(json.dumps(profile.to_dict())))
        assert restored == profile
        path = tmp_path / f"p_{with_ml}.json"
        profile.save(path)
        assert HybridProfile.from_file(path) == profile
        assert path.read_text(encoding="utf-8").endswith("\n")


def test_profile_rejects_unknown_top_level_keys_and_bad_json(tmp_path):
    with pytest.raises(HybridConfigError, match="rule_weights"):
        HybridProfile.from_dict({"bands": ActionBands(10, 20, 30).to_dict(), "extra": 1})
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(HybridConfigError):
        HybridProfile.from_file(bad)


def test_a_profile_without_bands_is_rejected():
    with pytest.raises(HybridConfigError):
        HybridProfile.from_dict({"rule_weights": {}})


# ------------------------------------------------------------------------------------------------ MR26: độ lệch miền


def test_domain_shift_round_trips_and_old_profiles_without_it_still_load():
    from app.detection.hybrid.calibration import MlDomainShift

    shift = MlDomainShift(1.78, 0.0, 0.99, "corpus_mr24", (1.61, 1.97), 1020, 0.59)
    profile = HybridProfile(RuleWeights(), ActionBands(32, 58, 70), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)), shift)
    assert HybridProfile.from_dict(json.loads(json.dumps(profile.to_dict()))) == profile
    old = {k: v for k, v in profile.to_dict().items() if k != "ml_domain_shift"}
    assert HybridProfile.from_dict(old).ml_domain_shift is None


def test_domain_shift_never_makes_the_model_more_sensitive_than_on_rba():
    from app.detection.hybrid.calibration import MlDomainShift

    with pytest.raises(HybridConfigError, match="≥ 0"):
        MlDomainShift(success=-0.5)
    with pytest.raises(HybridConfigError, match="≥ 0"):
        MlDomainShift(success=float("nan"))


def test_ml_probability_applies_the_shift_of_the_login_outcome():
    from app.detection.hybrid.calibration import MlDomainShift

    profile = HybridProfile(RuleWeights(), ActionBands(32, 58, 70), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)), MlDomainShift(success=2.0, failure=0.5))
    assert profile.ml_probability(3.0, success=True) == pytest.approx(0.2)
    assert profile.ml_probability(3.0, success=False) == pytest.approx(0.5)
    assert HybridProfile(RuleWeights(), ActionBands(32, 58, 70)).ml_probability(3.0, success=True) is None
