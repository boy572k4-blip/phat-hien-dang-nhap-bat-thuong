"""Kiểm tra nhiệm vụ 2.1 — 3 test case yêu cầu trong checklist:
đăng nhập đúng, đăng nhập sai, tài khoản không tồn tại.
"""

from app.models import LoginEvent, User
from app.security import hash_password

PASSWORD = "CorrectHorse123"


def _create_user(db_session, username="alice", password=PASSWORD):
    user = User(username=username, password_hash=hash_password(password))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_login_success_returns_200_and_logs_event(client, db_session):
    _create_user(db_session, "alice")

    response = client.post("/login", json={"username": "alice", "password": PASSWORD})

    assert response.status_code == 200
    # MR16: LoginResponse có thêm field step_up_required/challenge_id/demo_otp_code/locked — mặc định "không có gì
    # đặc biệt xảy ra" cho một lần đăng nhập bình thường (không bị khoá, không cần xác thực thêm).
    assert response.json() == {
        "success": True, "message": "Login successful",
        "step_up_required": False, "challenge_id": None, "demo_otp_code": None, "locked": False,
    }

    events = db_session.query(LoginEvent).all()
    assert len(events) == 1
    assert events[0].success is True
    assert events[0].attempted_username == "alice"
    assert events[0].user_id is not None


def test_login_wrong_password_returns_401_and_logs_failure(client, db_session):
    _create_user(db_session, "bob")

    response = client.post("/login", json={"username": "bob", "password": "SaiMatKhau"})

    assert response.status_code == 401
    assert response.json()["success"] is False
    # Mật khẩu gửi lên không được xuất hiện lại trong response.
    assert "SaiMatKhau" not in response.text

    event = db_session.query(LoginEvent).one()
    assert event.success is False
    assert event.user_id is not None  # bob tồn tại, chỉ sai mật khẩu


def test_login_nonexistent_account_returns_401_and_logs_null_user(client, db_session):
    response = client.post("/login", json={"username": "ghost", "password": "whatever"})

    assert response.status_code == 401
    assert response.json()["success"] is False

    event = db_session.query(LoginEvent).one()
    assert event.success is False
    assert event.user_id is None
    assert event.attempted_username == "ghost"


def test_password_check_runs_off_the_event_loop(client, db_session, monkeypatch):
    """MR20: bcrypt (~230 ms CPU) không được chạy trên vòng lặp sự kiện của hàm `async` /login — nếu chạy ở đó, mọi request
    đăng nhập đồng thời phải xếp hàng chờ nhau. Trong luồng của threadpool không có vòng lặp nào đang chạy."""
    import asyncio

    from app.security import check_password

    seen = []

    def spy(password, password_hash):
        try:
            asyncio.get_running_loop()
            seen.append("event-loop")
        except RuntimeError:
            seen.append("threadpool")
        return check_password(password, password_hash)

    monkeypatch.setattr("app.routers.auth.check_password", spy)
    _create_user(db_session, "dave")
    assert client.post("/login", json={"username": "dave", "password": PASSWORD}).status_code == 200
    assert client.post("/login", json={"username": "dave", "password": "SaiRoi"}).status_code == 401
    assert client.post("/login", json={"username": "khong-ton-tai", "password": "SaiRoi"}).status_code == 401
    assert seen == ["threadpool", "threadpool", "threadpool"]


def test_unknown_username_costs_the_same_bcrypt_check_as_a_real_one(client, db_session, monkeypatch):
    """MR32: trước đây tên không tồn tại trả lời ngay (không bcrypt) — thời gian phản hồi lộ tài khoản nào có thật."""
    import app.security as security

    calls = []
    real_checkpw = security.bcrypt.checkpw
    monkeypatch.setattr(security.bcrypt, "checkpw", lambda password, hashed: calls.append(hashed) or real_checkpw(password, hashed))
    _create_user(db_session, "erin")

    client.post("/login", json={"username": "erin", "password": "SaiRoi"})
    client.post("/login", json={"username": "khong-ton-tai", "password": "SaiRoi"})

    assert len(calls) == 2
    assert calls[0].startswith(b"$2b$12$") and calls[1].startswith(b"$2b$12$")  # cùng độ khó


def test_login_error_message_identical_for_wrong_password_and_unknown_user(client, db_session):
    """Không lộ thông tin tài khoản có tồn tại hay không (docs/api-contract.md mục 3)."""
    _create_user(db_session, "carol")

    wrong_password = client.post("/login", json={"username": "carol", "password": "SaiRoi"})
    unknown_user = client.post("/login", json={"username": "khong-ton-tai", "password": "SaiRoi"})

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["message"] == unknown_user.json()["message"]
