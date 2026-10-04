"""MR28 — cửa của `POST /login` và `POST /login/verify-otp` ghi tín hiệu cho rule engine (`app/detection/gate.py`), và luật đọc chúng ở lần
đăng nhập kế tiếp qua CHÍNH pipeline thật: đoán mã OTP -> khoá; cứ thử khi đang bị khoá -> xác thực thêm khi khoá hết hạn."""

from datetime import datetime, timedelta, timezone

from app.detection import gate, hybrid_runtime, rate_counter
from app.detection.engine import RedisStore
from app.detection.engine import indexes as K
from app.detection.hybrid import Contribution, RiskResult
from app.detection.response_execution import OTP_MAX_ATTEMPTS
from app.detection.rule_engine_runtime import invalidate_blocklist_cache
from app.models import Alert, AuditLog, BlocklistEntry, User
from app.security import hash_password

PASSWORD = "CorrectHorse123"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def _create_user(db_session, username="alice"):
    user = User(username=username, password_hash=hash_password(PASSWORD))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _count(key: str) -> int:
    return RedisStore(rate_counter.redis_client).log_count(key, 0.0)


def _login(client, username="alice"):
    return client.post("/login", json={"username": username, "password": PASSWORD}, headers={"user-agent": CHROME_UA})


def _step_up_once(monkeypatch):
    """Ép hành động step_up cho MỘT lần chấm (để có mã OTP), rồi trả engine về như cũ."""
    engine = hybrid_runtime.get_engine()
    original = engine.evaluate
    forced = RiskResult(score=60, action="step_up", probability=0.6, ml_probability=None, rule_probability=0.6, reputation_probability=0.0,
                        overridden_by=None, contributions=(Contribution("test", "ép step_up", 0.6, "rule"),))

    def once(*args, **kwargs):
        monkeypatch.setattr(engine, "evaluate", original)
        return forced

    monkeypatch.setattr(engine, "evaluate", once)


def test_every_failed_otp_submission_is_audited_and_counted_for_the_account(client, db_session, monkeypatch):
    user = _create_user(db_session)
    _step_up_once(monkeypatch)
    login = _login(client).json()
    wrong = "000000" if login["demo_otp_code"] != "000000" else "111111"

    for _ in range(OTP_MAX_ATTEMPTS + 2):  # 5 lần sai mã + 2 lần gửi tiếp vào mã đã hết lượt
        assert client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": wrong}).json()["success"] is False

    logs = db_session.query(AuditLog).filter(AuditLog.action == "verify_otp_failed").order_by(AuditLog.id).all()
    assert [log.detail["reason"] for log in logs] == ["wrong_code"] * OTP_MAX_ATTEMPTS + ["exhausted"] * 2
    assert _count(K.otp_fail_user(str(user.id))) == OTP_MAX_ATTEMPTS + 2
    client.post("/login/verify-otp", json={"challenge_id": 999999, "code": wrong})  # mã không tồn tại: không có tài khoản để ghi
    assert _count(K.otp_fail_user(str(user.id))) == OTP_MAX_ATTEMPTS + 2


def test_after_two_codes_worth_of_wrong_otps_the_next_correct_password_login_is_locked(client, db_session):
    user = _create_user(db_session)
    now = datetime.now(timezone.utc)
    for _ in range(10):
        gate.record_otp_failure(user.id, now)

    response = _login(client)

    assert response.status_code == 423 and response.json()["locked"] is True
    alert = db_session.query(Alert).one()
    assert alert.explanation["forced_by"] == "otp_guessing" and alert.explanation["evidence"]["otp_guessing"]["otp_failures"] == 10
    assert db_session.query(BlocklistEntry).filter(BlocklistEntry.kind == "username", BlocklistEntry.value == "alice").one().added_by == "system"


def test_attempts_rejected_while_locked_are_counted_and_force_a_step_up_once_the_lock_expires(client, db_session):
    _create_user(db_session)
    lock = BlocklistEntry(kind="username", value="alice", reason="test MR28", added_by="system", expires_at=datetime.now(timezone.utc) + timedelta(minutes=30))
    db_session.add(lock)
    db_session.commit()
    invalidate_blocklist_cache()

    for _ in range(10):
        assert _login(client, "Alice").status_code == 423  # tên gõ khác hoa/thường vẫn là một tài khoản
    assert _count(K.blocked_user("alice")) == 10
    assert db_session.query(AuditLog).filter(AuditLog.action == "reject_blocked_login").count() == 10

    lock.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)  # khoá hết hạn
    db_session.commit()
    invalidate_blocklist_cache()
    body = _login(client).json()

    assert body["step_up_required"] is True  # chủ tài khoản qua được bằng OTP; kẻ chỉ có mật khẩu thì không
    assert db_session.query(Alert).one().explanation["forced_by"] == "blocked_retry"


def test_a_counter_outage_never_blocks_the_login_door(client, db_session, monkeypatch):
    _create_user(db_session)

    class Broken:
        def __getattr__(self, name):
            raise ConnectionError("redis down")

    monkeypatch.setattr(rate_counter, "redis_client", Broken())
    gate.record_otp_failure(1, datetime.now(timezone.utc))  # không raise
