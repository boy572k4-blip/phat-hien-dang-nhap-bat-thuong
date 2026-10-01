"""MR21 — một bộ luật duy nhất: những gì tầng 1 (ba luật Redis riêng, Tuần 3) và bảng cộng điểm của tầng 2 (Tuần 4) từng
bắt, giờ phải được bắt qua luật v2 mang HÀNH ĐỘNG TỐI THIỂU — kiểm qua CHÍNH pipeline thật (`run_detection_pipeline`),
thay cho test_rules.py / test_scoring.py / test_rate_counter.py (đã xoá cùng mã tầng 1-2).

Mọi test ở đây chạy với hồ sơ dự phòng (trọng số mặc định 5%, KHÔNG có mô hình ML) và tầng 3 tắt: hành động chỉ có thể
đến từ luật — chứng minh đúng điều MR21 cần (luật xác định tự cảnh báo được dù trọng số thấp), không lẫn điểm mô hình."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.detection import hybrid_runtime
from app.detection.pipeline import run_detection_pipeline
from app.models import Alert, LoginEvent, RuleOverride, User
from ml.attack_scenarios import CHROME_UA, GOOGLE_US_IP, HANOI_FPT_IP

BASE = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
ATTACKER_IP = "198.51.100.7"  # dải TEST-NET-2 (RFC 5737): không có GeoIP/ASN — chỉ các luật đếm theo tài khoản/IP liên quan


@pytest.fixture(autouse=True)
def rules_only(monkeypatch):
    monkeypatch.setattr(hybrid_runtime, "_engine", hybrid_runtime.HybridEngine())  # hồ sơ dự phòng: trọng số 5%, không ML
    monkeypatch.setattr("app.detection.pipeline.ml_model.predict", lambda features: None)  # tầng 3 tắt


def _bands():
    return hybrid_runtime.get_engine().profile.bands


def _user(db, name="alice"):
    user = User(username=name, password_hash="x")
    db.add(user)
    db.commit()
    return user


def _login(username, user_id, *, success, minutes=0.0, ip=ATTACKER_IP):
    return asyncio.run(
        run_detection_pipeline(username=username, user_id=user_id, success=success, ip=ip, user_agent=CHROME_UA, timestamp=BASE + timedelta(minutes=minutes))
    )


def _hybrid_alerts(db):
    return db.query(Alert).filter(Alert.alert_type == "hybrid_risk").all()


# -------------------------------------------------------------------------- dò mật khẩu (tầng 1 brute_force + tầng 2 "+40")


def test_five_failures_in_five_minutes_alert_through_the_brute_force_min_action(db_session):
    user = _user(db_session)
    results = [_login("alice", user.id, success=False, minutes=i * 0.5) for i in range(5)]
    assert [r.hybrid_action for r in results] == ["allow"] * 4 + ["alert"]

    (alert,) = _hybrid_alerts(db_session)
    assert alert.rule_id == "brute_force" and alert.explanation["forced_by"] == "brute_force"
    assert alert.risk_score == _bands().alert_at  # bằng chứng 5% -> điểm hiển thị nâng lên đúng ngưỡng cảnh báo
    assert "hành động tối thiểu" in alert.message
    assert {a.alert_type for a in db_session.query(Alert).all()} == {"hybrid_risk"}  # không còn alert tầng 1/tầng 2 riêng


def test_the_same_failures_spread_over_half_an_hour_stay_below_the_five_minute_window(db_session):
    """Cửa sổ trượt theo THỜI ĐIỂM SỰ KIỆN, không theo thứ tự gọi — tương đương test MR18 của bộ đếm tầng 1 cũ (bug thật:
    kịch bản mô phỏng "chậm" từng bị bắt nhầm vì các lần gọi xảy ra trong vài giây thật)."""
    user = _user(db_session)
    results = [_login("alice", user.id, success=False, minutes=i * 6) for i in range(5)]
    assert all(r.hybrid_action == "allow" for r in results)
    assert _hybrid_alerts(db_session) == []


def test_switching_brute_force_to_shadow_keeps_it_as_evidence_but_stops_it_forcing_an_alert(db_session):
    """Định nghĩa mới của shadow (MR21): vẫn là bằng chứng có trọng số, KHÔNG tự ép hành động."""
    db_session.add(RuleOverride(rule_id="brute_force", mode="shadow", updated_by="test"))
    db_session.commit()
    user = _user(db_session)
    results = [_login("alice", user.id, success=False, minutes=i * 0.5) for i in range(5)]
    assert all(r.hybrid_action == "allow" for r in results)
    assert 0 < results[-1].hybrid_risk_score < _bands().alert_at  # vẫn góp phần trọng số của nó vào điểm


# -------------------------------------------------------------------------- nhồi thông tin (tầng 1 credential_stuffing)


def test_ten_failures_across_five_names_from_one_ip_alert_through_credential_stuffing(db_session):
    names = [f"ghost{i}" for i in range(5)]
    results = [_login(names[i % 5], None, success=False, minutes=i * 0.25) for i in range(10)]
    assert all(r.hybrid_action == "allow" for r in results[:9]) and results[-1].hybrid_action == "alert"
    (alert,) = _hybrid_alerts(db_session)
    assert alert.rule_id == "credential_stuffing"


# -------------------------------------------------------------------------- thành công sau chuỗi sai (tầng 2 "+50")


def test_a_success_right_after_five_failures_requires_step_up(db_session):
    user = _user(db_session)
    for i in range(5):
        _login("alice", user.id, success=False, minutes=i * 0.5)
    result = _login("alice", user.id, success=True, minutes=3)
    assert result.hybrid_action == "step_up" and result.hybrid_risk_score == _bands().step_up_at

    (alert,) = _hybrid_alerts(db_session)  # gộp với cảnh báo dò mật khẩu ngay trước đó (MR13), mức tăng lên step_up
    assert alert.rule_id == "success_after_failures" and alert.occurrence_count == 2 and alert.explanation["action"] == "step_up"


# -------------------------------------------------------------------------- di chuyển bất khả thi (tầng 1 impossible_travel)


def test_hanoi_then_the_us_five_minutes_later_alerts_and_carries_both_points_for_the_map(db_session):
    from app.detection.geoip import lookup_ip

    if lookup_ip(HANOI_FPT_IP) is None or lookup_ip(GOOGLE_US_IP) is None:
        pytest.skip("cần GeoIP (GeoLite2-City) để có toạ độ")
    user = _user(db_session)
    _login("alice", user.id, success=True, ip=HANOI_FPT_IP)
    result = _login("alice", user.id, success=True, minutes=5, ip=GOOGLE_US_IP)
    assert result.hybrid_action in ("alert", "step_up", "lock")

    alerts = _hybrid_alerts(db_session)
    assert [a.rule_id for a in alerts] == ["impossible_travel"]
    payload = next(p for p in result.alert_payloads if p["alert_type"] == "hybrid_risk")
    hanoi = lookup_ip(HANOI_FPT_IP)
    assert (payload["previous_latitude"], payload["previous_longitude"]) == (hanoi.latitude, hanoi.longitude)  # bản đồ vẽ được đường nối


# -------------------------------------------------------------------------- một điểm rủi ro, tầng 3


def test_every_login_carries_one_score_in_both_score_columns(db_session):
    user = _user(db_session)
    _login("alice", user.id, success=True)
    _login("ghost", None, success=False, minutes=1)
    events = db_session.query(LoginEvent).all()
    assert len(events) == 2 and all(e.risk_score is not None and e.risk_score == e.hybrid_risk_score for e in events)


def test_a_tier3_anomaly_alert_carries_the_score_of_the_same_login(db_session, monkeypatch):
    monkeypatch.setattr("app.detection.pipeline.ml_model.predict", lambda features: {"is_anomaly": True, "anomaly_score": 0.7})
    monkeypatch.setattr("app.detection.pipeline.ml_model.explain", lambda features: "giả lập")
    user = _user(db_session)
    _login("alice", user.id, success=False)
    (alert,) = db_session.query(Alert).filter(Alert.alert_type == "ml_anomaly").all()
    assert alert.risk_score == db_session.query(LoginEvent).one().hybrid_risk_score
