"""MR22 — mô hình địa lý-thời gian (tầng 3) là nguồn bằng chứng `ml_geo` của hybrid, có cổng cold-start — kiểm qua CHÍNH
pipeline thật (`run_detection_pipeline`).

Chạy với hồ sơ dự phòng (không có mô hình `hybrid_cp2`, ngưỡng 40/65/85) và một mô hình tầng 3 GIẢ luôn gắn cờ bất
thường: mọi cảnh báo ở đây chỉ có thể đến từ tầng 3, và không phụ thuộc artifacts đã train (bị .gitignore)."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.detection import hybrid_runtime
from app.detection.alert_intelligence import GEO_FAMILY
from app.detection.hybrid import GEO_LABEL, geo_probability
from app.detection.pipeline import run_detection_pipeline
from app.models import Alert, User
from ml.attack_scenarios import CHROME_UA, HANOI_FPT_IP

BASE = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
MARGIN = 0.05  # biên độ > 0: mô hình gắn cờ
SLOPE = 40.0


@pytest.fixture(autouse=True)
def flagging_geo_model(monkeypatch):
    monkeypatch.setattr(hybrid_runtime, "_engine", hybrid_runtime.HybridEngine())  # hồ sơ dự phòng: không ML, ngưỡng 40/65/85
    monkeypatch.setattr("app.detection.pipeline.ml_model.predict", lambda features: {"is_anomaly": True, "anomaly_score": 0.7, "margin": MARGIN})
    monkeypatch.setattr("app.detection.pipeline.ml_model.geo_slope", lambda: SLOPE)
    monkeypatch.setattr("app.detection.pipeline.ml_model.cold_start_min_successes", lambda: 5)
    monkeypatch.setattr("app.detection.pipeline.ml_model.explain", lambda features: "vị trí mới ↑")


def _user(db, name="newbie"):
    user = User(username=name, password_hash="x")
    db.add(user)
    db.commit()
    return user


def _daily_logins(user, days):
    """Mỗi ngày một lần đăng nhập thành công, cùng giờ, cùng mạng, cùng trình duyệt — tài khoản mới dùng bình thường."""
    return [
        asyncio.run(run_detection_pipeline(username=user.username, user_id=user.id, success=True, ip=HANOI_FPT_IP, user_agent=CHROME_UA, timestamp=BASE + timedelta(days=d)))
        for d in range(days)
    ]


def test_the_first_logins_of_a_new_account_are_not_scored_even_when_the_model_flags_them(db_session, monkeypatch):
    """Lỗi MR18 đã sửa: trước MR22 lần đăng nhập ĐẦU TIÊN của mọi tài khoản đều thành alert `ml_anomaly`. Từ MR23 mô hình
    còn không được gọi dưới cổng (MR22 vẫn chấm để ghi `ml_anomaly_score` — cột đó đã xoá)."""
    calls = []
    monkeypatch.setattr("app.detection.pipeline.ml_model.predict", lambda features: calls.append(features) or {"is_anomaly": True, "anomaly_score": 0.7, "margin": MARGIN})
    user = _user(db_session)
    results = _daily_logins(user, 5)  # 0..4 lần thành công trước đó: dưới cổng

    assert [r.hybrid_action for r in results] == ["allow"] * 5
    assert db_session.query(Alert).count() == 0
    assert calls == []
    assert len(_daily_logins(_user(db_session, "veteran"), 6)) == 6 and len(calls) == 1  # qua cổng ở lần thứ 6: được chấm


def test_past_the_gate_a_flagged_login_becomes_one_hybrid_alert_with_the_ml_geo_source(db_session):
    user = _user(db_session)
    results = _daily_logins(user, 6)  # lần thứ 6: đúng 5 lần thành công trước đó

    bands = hybrid_runtime.get_engine().profile.bands
    expected = geo_probability(MARGIN, SLOPE, bands)
    assert results[-1].hybrid_action == "alert" and results[-1].hybrid_risk_score == round(expected * 100)

    (alert,) = db_session.query(Alert).all()  # một cảnh báo duy nhất — không còn alert tầng 3 riêng
    assert alert.attack_family == GEO_FAMILY
    assert alert.rule_id is None  # mô hình không phải luật — `rule_id` chỉ lấy từ bằng chứng luật/danh tiếng
    (geo,) = [c for c in alert.explanation["contributions"] if c["source"] == "ml_geo"]
    assert geo["group"] == "ml" and geo["label"] == f"{GEO_LABEL}: vị trí mới ↑"  # giữ phần diễn giải của alert tầng 3 cũ
    assert "vị trí mới ↑" in alert.message


def test_alone_the_geo_model_can_only_alert_never_step_up_or_lock(db_session, monkeypatch):
    monkeypatch.setattr("app.detection.pipeline.ml_model.predict", lambda features: {"is_anomaly": True, "anomaly_score": 0.99, "margin": 10.0})
    user = _user(db_session)
    results = _daily_logins(user, 6)
    assert results[-1].hybrid_action == "alert"


def test_a_model_trained_before_mr22_is_not_used_as_evidence(db_session, monkeypatch):
    """meta.json cũ không có độ dốc hiệu chỉnh -> không đoán bừa một độ dốc, bỏ qua tầng 3 (và không còn alert riêng)."""
    monkeypatch.setattr("app.detection.pipeline.ml_model.geo_slope", lambda: None)
    user = _user(db_session)
    results = _daily_logins(user, 6)
    assert [r.hybrid_action for r in results] == ["allow"] * 6
    assert db_session.query(Alert).count() == 0


def test_an_unflagged_login_past_the_gate_adds_only_weak_evidence(db_session, monkeypatch):
    monkeypatch.setattr("app.detection.pipeline.ml_model.predict", lambda features: {"is_anomaly": False, "anomaly_score": 0.4, "margin": -0.1})
    user = _user(db_session)
    results = _daily_logins(user, 6)
    assert results[-1].hybrid_action == "allow"
    assert results[-1].hybrid_risk_score < hybrid_runtime.get_engine().profile.bands.alert_at
    assert db_session.query(Alert).count() == 0
