"""MR28 — phép đo chỉ tính lần thử ĐƯỢC CHẤM (bỏ bước gửi mã OTP và lần thử bị cửa `/login` từ chối), và tách riêng các biến thể mà hệ thống
đã khoá kẻ tấn công bằng tín hiệu khác trước khi tín hiệu riêng kịp chấm ("bị chặn sớm")."""

import json

from app.detection.hybrid import ActionBands, HybridProfile, MonotonicCalibrator, RuleWeightEntry, RuleWeights
from ml.corpus import behaviors as B
from ml.corpus.calibrate_rules import load_records

PROFILE = HybridProfile(RuleWeights({"tor_exit": RuleWeightEntry(0.57, True, 1, None)}), ActionBands(32, 58, 70), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)))


def _step(malicious=True, hits=(), kind="login", gated=False):
    step = {"kind": kind, "malicious": malicious, "hits": [list(h) for h in hits], "success": True, "ml_raw": None, "ml_geo": None, "action": "allow"}
    if gated:
        step.update(gated=True, action="lock")
    return step


def test_load_records_keeps_only_scored_attempts_and_counts_gated_malicious_ones(tmp_path):
    setup_gated = {**_step(gated=True), "gate": "setup"}  # khoá dựng sẵn của kịch bản: không phải "hệ thống chặn sớm"
    record = {"id": "v", "family": "f", "kind": "attack",
              "steps": [_step(), _step(kind="otp_fail"), {**_step(gated=True), "gate": "system"}, _step(gated=True, malicious=False), setup_gated]}
    path = tmp_path / "evaluation.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    (loaded,) = load_records(path)
    assert len(loaded["steps"]) == 1 and loaded["gated_malicious"] == 1


def test_a_variant_stopped_earlier_by_another_signal_is_counted_as_preempted_not_as_a_miss(monkeypatch):
    monkeypatch.setattr(B, "BEHAVIORS", {"Tor": (("anonymizer_login",), ("tor_exit",))})
    records = [
        {"id": "a1", "family": "anonymizer_login", "kind": "attack", "gated_malicious": 0, "steps": [_step(hits=[("tor_exit", False)])]},
        {"id": "a2", "family": "anonymizer_login", "kind": "attack", "gated_malicious": 3, "steps": [_step()]},
        {"id": "a3", "family": "anonymizer_login", "kind": "attack", "gated_malicious": 0, "steps": [_step()]},
        {"id": "b1", "family": "routine", "kind": "benign", "steps": [_step(malicious=False)]},
    ]
    (row,) = B.behavior_table(records, PROFILE)
    assert row["own_detection"] == round(1 / 3, 3) and row["preempted_by_other_signals"] == 1
