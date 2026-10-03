"""MR23 — một sự cố = một cảnh báo, một điểm rủi ro; pipeline 5 bước, mỗi khối một SAVEPOINT. Kiểm qua CHÍNH pipeline thật
(`run_detection_pipeline`) với hồ sơ dự phòng (trọng số 5%, không mô hình ML) và tầng 3 tắt: mọi hành động đến từ luật
xác định, không lẫn điểm mô hình — cùng hạ tầng với test_pipeline_mr21.py."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.detection import hybrid_runtime
from app.detection.engine.registry import REGISTRY
from app.detection.pipeline import run_detection_pipeline
from app.models import Alert, BlocklistEntry, Campaign, LoginEvent, ResponseAction, User
from app.schemas import AlertOut
from ml.attack_scenarios import CHROME_UA

BASE = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
HOME_IP = "198.51.100.7"  # TEST-NET-2: không có GeoIP/ASN
BLOCKED_IP = "198.51.100.66"


@pytest.fixture(autouse=True)
def rules_only(monkeypatch):
    monkeypatch.setattr(hybrid_runtime, "_engine", hybrid_runtime.HybridEngine())  # hồ sơ dự phòng: trọng số 5%, không ML
    monkeypatch.setattr("app.detection.pipeline.ml_model.predict", lambda features: None)  # tầng 3 tắt


def _user(db, name="alice"):
    user = User(username=name, password_hash="x")
    db.add(user)
    db.commit()
    return user


def _login(username, user_id, *, success, minutes=0.0, ip=HOME_IP):
    return asyncio.run(
        run_detection_pipeline(username=username, user_id=user_id, success=success, ip=ip, user_agent=CHROME_UA, timestamp=BASE + timedelta(minutes=minutes))
    )


def _block(db, ip=BLOCKED_IP):
    db.add(BlocklistEntry(kind="ip", value=ip, reason="test MR23", added_by="test"))
    db.commit()


def test_the_e2e_tc1_attack_is_exactly_one_alert_listing_all_its_evidence(db_session):
    """Điều kiện "xong" của MR23 (E2E TC1: 5 lần sai rồi 1 lần đúng vào một tài khoản)."""
    user = _user(db_session)
    for i in range(5):
        _login("alice", user.id, success=False, minutes=i * 0.5)
    result = _login("alice", user.id, success=True, minutes=3)
    assert result.hybrid_action == "step_up"

    (alert,) = db_session.query(Alert).all()
    assert alert.occurrence_count == 2 and alert.explanation["action"] == "step_up" and alert.severity == "high"
    sources = {c["source"] for c in alert.explanation["contributions"]}
    assert {"brute_force", "success_after_failures"} <= sources
    assert {"brute_force", "success_after_failures"} <= set(alert.explanation["evidence"])
    assert alert.explanation["evidence"]["success_after_failures"]["fails_before"] == 5
    assert alert.rule_id == "success_after_failures"  # luật đã ép hành động nặng nhất
    assert "Sự cố gồm 2 lần thử" in alert.message
    assert db_session.query(ResponseAction).filter(ResponseAction.action == "step_up").count() == 1
    AlertOut.model_validate(alert)  # API trả được nguyên cảnh báo (không còn `alert_type`)


def test_an_attack_that_changes_technique_midway_stays_one_incident(db_session):
    """Trước MR23 khoá gộp gồm cả họ tấn công: dò mật khẩu rồi đăng nhập từ IP trong blocklist ra HAI cảnh báo."""
    user = _user(db_session)
    _block(db_session)
    for i in range(5):
        _login("alice", user.id, success=False, minutes=i * 0.5)
    _login("alice", user.id, success=True, minutes=4, ip=BLOCKED_IP)

    (alert,) = db_session.query(Alert).all()
    assert REGISTRY["brute_force"].category != REGISTRY["blocklist_hit"].category  # đúng là hai họ tấn công khác nhau
    assert alert.explanation["action"] == "lock" and alert.rule_id == "blocklist_hit"
    assert alert.attack_family == REGISTRY["blocklist_hit"].category  # họ của lần thử điểm cao nhất
    assert {"brute_force", "blocklist_hit"} <= set(alert.explanation["evidence"])


def test_the_incident_window_slides_with_the_latest_attempt(db_session):
    """Tấn công chậm (mỗi 10 phút một lần, kéo dài 1 giờ) vẫn là MỘT sự cố — trước MR23 cửa sổ tính từ lần ĐẦU TIÊN nên
    cứ quá 15 phút lại mở cảnh báo mới. Nghỉ quá 15 phút thì là sự cố mới."""
    user = _user(db_session)
    _block(db_session)
    for i in range(7):
        _login("alice", user.id, success=False, minutes=i * 10, ip=BLOCKED_IP)
    (alert,) = db_session.query(Alert).all()
    assert alert.occurrence_count == 7
    assert alert.last_seen_at.replace(tzinfo=timezone.utc) == BASE + timedelta(minutes=60)

    _login("alice", user.id, success=False, minutes=60 + 16, ip=BLOCKED_IP)
    assert [a.occurrence_count for a in db_session.query(Alert).order_by(Alert.id)] == [7, 1]


def test_a_resolved_incident_is_not_reopened_by_a_new_attempt(db_session):
    user = _user(db_session)
    _block(db_session)
    _login("alice", user.id, success=False, ip=BLOCKED_IP)
    alert = db_session.query(Alert).one()
    alert.status = "false_positive"
    db_session.commit()

    _login("alice", user.id, success=False, minutes=1, ip=BLOCKED_IP)
    assert db_session.query(Alert).count() == 2


def test_a_failure_after_the_alert_is_written_leaves_no_half_written_incident(db_session, monkeypatch):
    """SAVEPOINT của khối chấm điểm: lỗi ở bước phản ứng (sau khi cảnh báo đã được ghi) huỷ cả cảnh báo lẫn điểm của lần
    thử, lần thử vẫn được ghi. Trước MR23 khối chỉ có try/except: SQLite giữ lại cảnh báo nửa vời, còn Postgres huỷ CẢ giao
    dịch ở lần commit cuối — mất luôn lần thử."""

    import app.detection.pipeline as pipeline_module

    # ⚠️ KHÔNG dùng monkeypatch.undo() để "bỏ lỗi" giữa test: nó gỡ luôn các patch của fixture db_session/fake_redis
    # (SessionLocal của pipeline, client Redis) và lần thử sau sẽ ghi vào Postgres/Redis DEV thật — đã xảy ra khi viết test này.
    broken = {"on": True}
    real_respond = pipeline_module._respond

    def flaky_respond(db, **kwargs):
        if broken["on"]:
            db.execute(text("SELECT * FROM bang_khong_ton_tai"))  # lỗi SQL thật
        return real_respond(db, **kwargs)

    monkeypatch.setattr("app.detection.pipeline._respond", flaky_respond)
    user = _user(db_session)
    _block(db_session)
    result = _login("alice", user.id, success=False, ip=BLOCKED_IP)

    assert db_session.query(Alert).count() == 0 and db_session.query(ResponseAction).count() == 0
    (event,) = db_session.query(LoginEvent).all()
    assert event.hybrid_action is None and event.hybrid_risk_score is None  # không nửa vời: có điểm mà không có cảnh báo
    assert result.alert_payloads == [] and result.hybrid_action is None

    broken["on"] = False
    assert _login("alice", user.id, success=False, minutes=1, ip=BLOCKED_IP).hybrid_action == "lock"  # lần sau chạy bình thường
    assert db_session.query(Alert).count() == 1


def test_a_broken_campaign_block_does_not_lose_the_alert(db_session, monkeypatch):
    def broken_correlation(db, *, event, alert):
        db.add(Campaign(label="nửa vời", first_seen_at=BASE, last_seen_at=BASE))
        db.flush()
        raise RuntimeError("lỗi giả lập trong khối chiến dịch")

    monkeypatch.setattr("app.detection.pipeline._correlate_campaign", broken_correlation)
    user = _user(db_session)
    _block(db_session)
    result = _login("alice", user.id, success=False, ip=BLOCKED_IP)

    assert db_session.query(Alert).count() == 1 and db_session.query(Campaign).count() == 0  # chiến dịch nửa vời bị huỷ
    assert result.hybrid_action == "lock" and len(result.alert_payloads) == 1


def test_the_websocket_payload_has_the_same_fields_as_the_alerts_api(db_session):
    """Frontend chèn payload thẳng vào danh sách cảnh báo (thay hàng cùng `id` khi sự cố được cập nhật)."""
    user = _user(db_session)
    _block(db_session)
    first = _login("alice", user.id, success=False, ip=BLOCKED_IP).alert_payloads[0]
    second = _login("alice", user.id, success=False, minutes=1, ip=BLOCKED_IP).alert_payloads[0]

    assert set(AlertOut.model_fields) - {"created_at", "last_seen_at"} <= set(first)
    assert second["id"] == first["id"] and second["occurrence_count"] == 2
    assert "alert_type" not in first


def test_a_late_or_back_dated_attempt_never_joins_an_incident_from_its_future(db_session):
    """Cửa sổ chặn cả hai phía. Thiếu chặn trên, một lần thử ghi lùi ngày (nạp lại, đồng thời) đã gộp vào cảnh báo xảy ra
    sau nó nhiều tháng — tìm ra khi viết chính file test này."""
    user = _user(db_session)
    _block(db_session)
    _login("alice", user.id, success=False, minutes=60 * 24 * 30, ip=BLOCKED_IP)  # sự cố một tháng sau
    _login("alice", user.id, success=False, minutes=0, ip=BLOCKED_IP)  # lần thử ghi lùi
    assert [a.occurrence_count for a in db_session.query(Alert).order_by(Alert.id)] == [1, 1]

    _login("alice", user.id, success=False, minutes=60 * 24 * 30 - 5, ip=BLOCKED_IP)  # đến trễ 5 phút: cùng sự cố, không kéo lùi mốc
    later = db_session.query(Alert).order_by(Alert.id).first()
    assert later.occurrence_count == 2
    assert later.last_seen_at.replace(tzinfo=timezone.utc) == BASE + timedelta(minutes=60 * 24 * 30)
