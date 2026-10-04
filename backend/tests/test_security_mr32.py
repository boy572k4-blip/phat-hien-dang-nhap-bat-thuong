"""MR32 — hệ thống tự bảo vệ: giới hạn/khoá/ghi vết đăng nhập quản trị (`app/admin_guard.py`), JWT, CORS, OTP demo, độ dài mật khẩu.

IP nguồn trong test lấy từ header `x-test-ip` (TestClient luôn kết nối từ "testclient")."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest

from app import admin_guard
from app.config import Settings
from app.models import Admin, AuditLog
from app.security import hash_password
from tests.test_auth_mr16 import PASSWORD as USER_PASSWORD
from tests.test_auth_mr16 import _create_user, _force_action

ADMIN_PASSWORD = "MatKhauQuanTri123!"
HOME, ATTACKER, OTHER = "198.51.100.10", "203.0.113.66", "203.0.113.77"


@pytest.fixture(autouse=True)
def client_ip_from_header(monkeypatch):
    monkeypatch.setattr("app.routers.admin.resolve_client_ip", lambda request: request.headers.get("x-test-ip", "testclient"))


@pytest.fixture
def admin(db_session):
    row = Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD))
    db_session.add(row)
    db_session.commit()
    return row


def _login(client, password, ip, username="admin"):
    return client.post("/admin/login", json={"username": username, "password": password}, headers={"x-test-ip": ip, "user-agent": "pytest-ua"})


def _age_rows(db_session, minutes, actions=(admin_guard.FAILURE,)):
    """Đẩy các dòng audit về quá khứ — mô phỏng thời gian trôi mà không phải chờ."""
    old = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    db_session.query(AuditLog).filter(AuditLog.action.in_(actions)).update({AuditLog.created_at: old}, synchronize_session=False)
    db_session.commit()


def _outcomes(db_session):
    db_session.expire_all()
    return [row.action for row in db_session.query(AuditLog).filter(AuditLog.action.in_(admin_guard.ACTIONS)).order_by(AuditLog.id)]


# ------------------------------------------------------------------------------------------ khoá theo tài khoản


def test_five_wrong_passwords_lock_the_account_even_for_the_right_password(client, db_session, admin):
    for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT):
        assert _login(client, "sai", ATTACKER).status_code == 401

    locked = _login(client, ADMIN_PASSWORD, OTHER)  # IP khác nhưng cũng lạ: cùng cửa "IP lạ" của tài khoản

    assert locked.status_code == 429
    assert 0 < int(locked.headers["Retry-After"]) <= 15 * 60
    assert "tạm khoá" in locked.json()["detail"]
    assert _outcomes(db_session)[-1] == admin_guard.REJECTED


def test_a_locked_attempt_does_not_run_bcrypt(client, db_session, admin, monkeypatch):
    for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT):
        _login(client, "sai", ATTACKER)
    calls = []
    monkeypatch.setattr("app.routers.admin.check_password", lambda *args: calls.append(args) or True)

    assert _login(client, ADMIN_PASSWORD, ATTACKER).status_code == 429
    assert calls == []


def test_smart_lockout_attacker_from_a_new_ip_cannot_lock_out_the_admin_at_a_familiar_ip(client, db_session, admin):
    assert _login(client, ADMIN_PASSWORD, HOME).status_code == 200  # HOME thành IP quen
    for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT):
        _login(client, "sai", ATTACKER)

    assert _login(client, ADMIN_PASSWORD, ATTACKER).status_code == 429  # cửa IP lạ đã khoá
    assert _login(client, ADMIN_PASSWORD, HOME).status_code == 200      # cửa IP quen vẫn mở


def test_failures_from_the_familiar_ip_are_counted_on_their_own(client, db_session, admin):
    assert _login(client, ADMIN_PASSWORD, HOME).status_code == 200
    for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT):
        _login(client, "sai", HOME)

    assert _login(client, ADMIN_PASSWORD, HOME).status_code == 429


def test_a_successful_login_resets_the_counter_of_its_door(client, db_session, admin):
    for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT - 1):
        _login(client, "sai", HOME)
    assert _login(client, ADMIN_PASSWORD, HOME).status_code == 200
    for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT - 1):
        assert _login(client, "sai", HOME).status_code == 401

    assert _login(client, ADMIN_PASSWORD, HOME).status_code == 200


def test_the_lock_expires_after_the_window_and_rejected_attempts_do_not_extend_it(client, db_session, admin):
    for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT):
        _login(client, "sai", ATTACKER)
    for _ in range(3):
        assert _login(client, "sai", ATTACKER).status_code == 429  # cứ thử tiếp trong lúc khoá

    _age_rows(db_session, minutes=16)  # chỉ các lần SAI già đi; các lần bị từ chối vẫn là "vừa xong"

    assert _login(client, ADMIN_PASSWORD, ATTACKER).status_code == 200


def test_attempts_still_in_flight_count_before_the_password_check(db_session):
    """Chống vượt giới hạn bằng request song song: lần thử được ghi (tạm là sai) TRƯỚC khi đếm và trước bcrypt — 6 lần `begin` chưa
    lần nào kiểm xong mật khẩu thì lần thứ 6 đã bị từ chối."""
    now = datetime.now(timezone.utc)
    attempts = [admin_guard.begin(db_session, username="admin", ip=ATTACKER, user_agent=None, now=now) for _ in range(admin_guard.MAX_FAILURES_PER_ACCOUNT + 1)]

    assert [a.refusal is None for a in attempts] == [True] * admin_guard.MAX_FAILURES_PER_ACCOUNT + [False]
    assert attempts[-1].refusal.scope == "account"


# ----------------------------------------------------------------------------------------------- giới hạn theo IP


def test_one_ip_spraying_many_usernames_is_throttled(client, db_session, admin):
    for i in range(admin_guard.MAX_FAILURES_PER_IP):
        assert _login(client, "sai", ATTACKER, username=f"khong-ton-tai-{i}").status_code == 401

    response = _login(client, ADMIN_PASSWORD, ATTACKER)  # tên khác, chưa sai lần nào — nhưng IP đã hết lượt

    assert response.status_code == 429
    db_session.expire_all()
    last = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    assert last.action == admin_guard.REJECTED and last.detail["scope"] == "ip"
    assert _login(client, ADMIN_PASSWORD, HOME).status_code == 200  # IP khác không bị ảnh hưởng


def test_unknown_admin_username_costs_a_bcrypt_check_too(client, db_session, admin, monkeypatch):
    import app.security as security

    calls = []
    real_checkpw = security.bcrypt.checkpw
    monkeypatch.setattr(security.bcrypt, "checkpw", lambda password, hashed: calls.append(hashed) or real_checkpw(password, hashed))

    assert _login(client, "sai", HOME, username="root").status_code == 401
    assert _login(client, "sai", HOME).status_code == 401
    assert len(calls) == 2


# ------------------------------------------------------------------------------------------------------ ghi vết


def test_every_attempt_is_audited_and_visible_to_admins(client, db_session, admin):
    _login(client, ADMIN_PASSWORD, HOME)
    _login(client, "sai", ATTACKER, username="root")
    token = _login(client, ADMIN_PASSWORD, HOME).json()["access_token"]

    assert client.get("/admin/login-attempts").status_code == 401
    rows = client.get("/admin/login-attempts", headers={"Authorization": f"Bearer {token}"}).json()

    assert [r["outcome"] for r in rows] == ["success", "failed", "success"]  # mới nhất trước
    assert rows[1] == {**rows[1], "username": "root", "ip": ATTACKER, "familiar_ip": False, "user_agent": "pytest-ua", "refused_scope": None}
    assert rows[0]["familiar_ip"] is True and rows[2]["familiar_ip"] is False
    success = db_session.query(AuditLog).filter(AuditLog.action == admin_guard.SUCCESS).first()
    assert success.actor == "admin" and success.target_id == admin.id
    assert "password" not in str(success.detail).lower()


# --------------------------------------------------------------------------------------------------------- JWT


def _settings(**overrides):
    return Settings(_env_file=None, **overrides)


def test_a_public_placeholder_jwt_secret_is_replaced_outside_production():
    for placeholder in ("change-me-to-a-random-secret", "doi-chuoi-nay-thanh-random-secret-that-dai", "ngan"):
        settings = _settings(app_env="development", jwt_secret_key=placeholder)
        assert settings.jwt_secret_key != placeholder and len(settings.jwt_secret_key) >= 32


def test_a_public_placeholder_jwt_secret_refuses_to_start_in_production():
    with pytest.raises(ValueError):
        _settings(app_env="production", jwt_secret_key="doi-chuoi-nay-thanh-random-secret-that-dai")
    assert _settings(app_env="production", jwt_secret_key="x" * 48).jwt_secret_key == "x" * 48


def test_tokens_without_expiry_are_rejected(client, db_session):
    from app.config import get_settings

    settings = get_settings()
    no_exp = jwt.encode({"sub": "1", "role": "admin", "iat": datetime.now(timezone.utc)}, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

    assert client.get("/login-events", headers={"Authorization": f"Bearer {no_exp}"}).status_code == 401


# ---------------------------------------------------------------------------------------- CORS, OTP, độ dài mật khẩu


def test_cors_allows_only_the_frontend_origin_without_credentials(client):
    from app.config import get_settings

    allowed = client.options("/alerts", headers={"Origin": get_settings().frontend_origin, "Access-Control-Request-Method": "GET"})
    foreign = client.options("/alerts", headers={"Origin": "https://ke-tan-cong.example", "Access-Control-Request-Method": "GET"})

    assert allowed.headers.get("access-control-allow-origin") == get_settings().frontend_origin
    assert "access-control-allow-credentials" not in allowed.headers
    assert "access-control-allow-origin" not in foreign.headers


def test_demo_otp_code_is_never_returned_in_production(client, db_session, monkeypatch):
    _create_user(db_session, "alice")
    _force_action(monkeypatch, "step_up")
    monkeypatch.setattr("app.routers.auth.get_settings", lambda: SimpleNamespace(is_production=True))

    body = client.post("/login", json={"username": "alice", "password": USER_PASSWORD}).json()

    assert body["step_up_required"] is True and body["challenge_id"] is not None
    assert body["demo_otp_code"] is None


def test_oversized_passwords_are_rejected_before_hashing(client, db_session):
    assert client.post("/login", json={"username": "alice", "password": "a" * 129}).status_code == 422
    assert client.post("/admin/login", json={"username": "admin", "password": "a" * 129}).status_code == 422
