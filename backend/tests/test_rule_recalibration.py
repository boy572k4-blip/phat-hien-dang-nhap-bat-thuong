"""MR25 — trọng số luật đo lại trên bộ MR24: công thức tỉ số khả năng -> xác suất, hai trần theo ngưỡng hành động, phát lại
ngoại tuyến đúng bằng `combine_risk`, và chính sách của hồ sơ đang dùng (mọi trọng số có nguồn, không luật đo trên bộ tự
dựng nào một mình bắt xác thực thêm/khoá). Dữ liệu thật của MR24 (ml/artifacts/corpus, không commit) chỉ cần cho test cuối."""

import pytest

from app.detection.engine.registry import REGISTRY
from app.detection.engine.types import RuleHit
from app.detection.hybrid import ActionBands, HybridProfile, RuleWeightEntry, RuleWeights, combine_risk
from ml.corpus import calibrate_rules as cr

BANDS = ActionBands(32, 58, 70)


def _variant(kind, steps, family=None):
    return {"family": family or kind, "kind": kind, "steps": steps}


def _step(malicious, hits=(), ml=None, ml_geo=None, action="allow"):
    return {"malicious": malicious, "hits": [[rule, False] for rule in hits], "ml": ml, "ml_geo": ml_geo, "action": action}


def test_a_rule_that_fires_equally_on_both_sides_carries_exactly_the_rba_prior():
    assert cr.posterior_weight(10, 100, 10, 100) == pytest.approx(cr.RBA_ATTACK_PRIOR)
    assert cr.posterior_weight(50, 100, 1, 100) > cr.posterior_weight(50, 100, 10, 100) > cr.posterior_weight(50, 100, 50, 100)


def test_zero_legit_hits_give_a_finite_weight_below_one_thanks_to_smoothing():
    weight = cr.posterior_weight(400, 3000, 0, 1300)
    assert 0.9 < weight < 1.0  # chỉ bị chặn bởi cỡ mẫu — lý do của trần chung


def test_caps_follow_the_action_bands():
    general, context = cr.caps(BANDS)
    assert round(general * 100) < BANDS.step_up_at and round(context * 100) < BANDS.alert_at
    assert round(general * 100) + 1 == BANDS.step_up_at and round(context * 100) + 1 == BANDS.alert_at


def test_calibrate_caps_strong_rules_keeps_rba_rules_and_skips_rules_with_too_few_hits():
    attacks = [_variant("attack", [_step(True, ("tor_exit", "datacenter_ip", "brute_force", "bot_user_agent"))]) for _ in range(40)]
    benign = [_variant("benign", [_step(False, ("datacenter_ip",) if i < 4 else ())]) for i in range(40)]
    entries = cr.calibrate(attacks + benign, BANDS, n_boot=20)

    general, context = cr.caps(BANDS)
    assert entries["tor_exit"].weight == general and entries["tor_exit"].source == "corpus_mr24_capped"
    assert entries["tor_exit"].ci95[0] > general  # khoảng tin cậy là của SỐ ĐO, chưa chặn
    assert entries["datacenter_ip"].weight == context and entries["datacenter_ip"].source == "corpus_mr24_capped"
    assert "brute_force" not in entries  # đo hợp lệ trên RBA -> giữ trọng số RBA
    assert entries["bot_user_agent"].n == 40
    sparse = cr.calibrate(attacks[:5] + benign, BANDS, n_boot=5)
    assert "bot_user_agent" not in sparse  # 5 lần khớp < MIN_HITS


def test_a_measured_weight_under_the_cap_is_kept_as_measured():
    attacks = [_variant("attack", [_step(True, ("vpn_ip",) if i < 10 else ())]) for i in range(100)]
    benign = [_variant("benign", [_step(False, ("vpn_ip",) if i < 10 else ())]) for i in range(100)]
    entry = cr.calibrate(attacks + benign, BANDS, n_boot=20)["vpn_ip"]
    assert entry.source == "corpus_mr24" and entry.weight == pytest.approx(cr.RBA_ATTACK_PRIOR, abs=1e-4)


def test_replay_scores_every_attempt_with_the_real_combine_risk():
    weights = RuleWeights({"tor_exit": RuleWeightEntry(0.5, True, 1, None)})
    step = _step(True, ("tor_exit", "brute_force"), ml=0.2, ml_geo=0.3)
    (actions,) = cr.replay([_variant("attack", [step])], weights, BANDS)
    hits = [RuleHit("tor_exit", "medium", "", {}, "enforce", ()), RuleHit("brute_force", "medium", "", {}, "enforce", ())]
    assert actions == [combine_risk(ml_probability=0.2, ml_geo_probability=0.3, hits=hits, weights=weights, bands=BANDS).action]
    (rules_only,) = cr.replay([_variant("attack", [step])], weights, BANDS, with_models=False)
    assert rules_only == [combine_risk(ml_probability=None, hits=hits, weights=weights, bands=BANDS).action]


def test_replay_fidelity_only_tolerates_differences_on_attempts_with_two_reputation_hits():
    weights = RuleWeights({})
    agree = _step(False, ("tor_exit",), action=cr.replay([_variant("benign", [_step(False, ("tor_exit",))])], weights, BANDS)[0][0])
    two_reputation = _step(False, ("tor_exit", "vpn_ip"), action="lock")
    other = _step(False, ("brute_force",), action="lock")
    fidelity = cr.replay_fidelity([_variant("benign", [agree, two_reputation, other])], weights, BANDS, REGISTRY)
    assert fidelity == {"attempts": 3, "identical": 1, "differ_only_by_reputation_max": 1, "unexplained": 1}


def test_metrics_count_legit_attempts_per_family_and_attack_detection_per_variant():
    records = [
        _variant("attack", [_step(False), _step(True)], family="a"),
        _variant("benign", [_step(False), _step(False)], family="b"),
    ]
    m = cr.metrics(records, [["alert", "allow"], ["step_up", "allow"]])
    assert m["families"]["a"]["rate"] == 0.0  # chỉ lần thử độc hại của họ tấn công mới tính là "bắt được"
    assert m["legit_alert_rate"] == 0.5 and m["legit_step_up_or_lock_rate"] == 0.5
    assert m["legit_by_family"] == {"b": [1, 1, 2]}


def test_the_shipped_profile_names_a_source_for_every_weight_and_no_corpus_rule_alone_forces_friction():
    profile = HybridProfile.from_file(cr.PROFILE_PATH)
    general, context = cr.caps(profile.bands)
    for rule, entry in profile.weights.entries.items():
        assert entry.source in ("rba", "default", "corpus_mr24", "corpus_mr24_capped"), rule
        if entry.source.startswith("corpus"):
            assert entry.weight <= (context if rule in cr.CONTEXT_ONLY else general), rule
            alone = combine_risk(ml_probability=None, hits=[RuleHit(rule, "medium", "", {}, "shadow", ())], weights=profile.weights, bands=profile.bands)
            assert alone.action in (("allow",) if rule in cr.CONTEXT_ONLY else ("allow", "alert")), rule
    for rule in cr.RBA_VALID:
        assert profile.weights.entries[rule].source == "rba"


def test_on_the_real_mr24_corpus_replay_reproduces_the_pipeline_actions():
    """Phát lại với cấu hình lúc chạy MR24 phải ra đúng hành động pipeline thật đã ghi (trừ thay đổi gộp danh tiếng có chủ đích)."""
    if not (cr.CORPUS_DIR / "evaluation.jsonl").is_file() or not cr.REPORT_PATH.is_file():
        pytest.skip("cần ml/artifacts/corpus (python -m ml.corpus.run rồi python -m ml.corpus.calibrate_rules)")
    import json

    before = RuleWeights.from_dict(json.loads(cr.REPORT_PATH.read_text(encoding="utf-8"))["weights_before"])
    profile = HybridProfile.from_file(cr.PROFILE_PATH)
    fidelity = cr.replay_fidelity(cr.load("evaluation"), before, profile.bands, cr.registry_with(cr.MR21_MIN_ACTIONS))
    assert fidelity["unexplained"] == 0 and fidelity["identical"] > 0.99 * fidelity["attempts"]
