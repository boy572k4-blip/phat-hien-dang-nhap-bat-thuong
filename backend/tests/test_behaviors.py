"""MR27 — bộ đánh giá "hành vi vững" (`ml/corpus/behaviors.py`): chỉ tín hiệu riêng của hành vi được dùng để chấm lại, tôn trọng chế độ,
hành động tối thiểu và cờ `forces`; báo nhầm tính trên lần thử của họ hợp lệ."""

from app.detection.hybrid import ActionBands, HybridProfile, MonotonicCalibrator, RuleWeightEntry, RuleWeights
from ml.corpus import behaviors as B

PROFILE = HybridProfile(
    RuleWeights({"tor_exit": RuleWeightEntry(0.57, True, 1, None), "vpn_ip": RuleWeightEntry(0.3, True, 1, None)}),
    ActionBands(32, 58, 70), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)),
)


def _step(hits=(), malicious=False, ml_geo=None, ml_raw=None, success=True, pool="vn_fpt"):
    return {"hits": [list(h) for h in hits], "malicious": malicious, "ml_geo": ml_geo, "ml_raw": ml_raw, "success": success, "pool": pool}


def test_own_action_keeps_only_the_behavior_signals():
    step = _step(hits=[("tor_exit", False), ("brute_force", False)], ml_geo=0.382, ml_raw=3.0)
    assert B.own_action(step, ("tor_exit",), PROFILE) == "alert"
    assert B.own_action(step, ("vpn_ip",), PROFILE) == "allow"  # luật không khớp -> không bằng chứng
    assert B.own_action(step, ("brute_force",), PROFILE) == "alert"  # hành động tối thiểu của luật vẫn áp dụng
    assert B.own_action(_step(hits=[("brute_force", True)]), ("brute_force",), PROFILE) == "allow"  # shadow không ép
    assert B.own_action(_step(hits=[("credential_stuffing", False, False)]), ("credential_stuffing",), PROFILE) == "allow"  # phạm vi ASN không ép
    assert B.own_action(step, ("ml_geo",), PROFILE) == "alert" and B.own_action(step, ("ml",), PROFILE) == "step_up"


def test_behavior_table_counts_variants_for_detection_and_legit_attempts_for_false_alarms(monkeypatch):
    monkeypatch.setattr(B, "BEHAVIORS", {"Tor": (("anonymizer_login",), ("tor_exit",), ("tor",)), "VPN": (("anonymizer_login",), ("vpn_ip",), ("vpn",))})
    records = [
        {"id": "a1", "family": "anonymizer_login", "kind": "attack", "steps": [_step([("tor_exit", False)], malicious=True, pool="tor")]},
        {"id": "a2", "family": "anonymizer_login", "kind": "attack", "steps": [_step([("vpn_ip", False)], malicious=True, pool="vpn")]},
        {"id": "b1", "family": "vpn_user", "kind": "benign", "steps": [_step([("vpn_ip", False)]), _step()]},
        {"id": "b2", "family": "tor_fan", "kind": "benign", "steps": [_step([("tor_exit", False)]), _step(), _step(), _step()]},
    ]
    tor, vpn = B.behavior_table(records, PROFILE)
    assert tor["variants"] == 1 and tor["own_detection"] == 1.0 and tor["own_legit_alerts"] == 1
    assert tor["own_legit_alert_rate"] == round(1 / 6, 4) and tor["worst_legit_family"] == "tor_fan" and not tor["robust"]
    assert vpn["variants"] == 1 and vpn["own_detection"] == 0.0 and vpn["own_legit_alerts"] == 0 and not vpn["robust"]
