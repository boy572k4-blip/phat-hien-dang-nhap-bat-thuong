"""Kiểm tra bộ lọc GET /login-events (nâng cấp sau Tuần 7; MR23: lọc theo hành động của hybrid risk engine thay cho mức
low/medium/high theo ngưỡng cứng 40/70, và trả kèm ngưỡng hành động đang dùng)."""

from datetime import datetime, timezone

from app.models import Admin, LoginEvent, User
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"


def _admin_headers(client, db_session):
    admin = Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD))
    db_session.add(admin)
    db_session.commit()
    token = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _seed_events(db_session):
    user = User(username="alice", password_hash=hash_password("x"))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    now = datetime.now(timezone.utc)
    events = [
        LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1", hybrid_risk_score=10, hybrid_action="allow", is_synthetic=False, created_at=now),
        LoginEvent(user_id=user.id, attempted_username="alice", success=False, ip_address="1.1.1.1", hybrid_risk_score=50, hybrid_action="alert", is_synthetic=False, created_at=now),
        LoginEvent(user_id=None, attempted_username="bob", success=False, ip_address="2.2.2.2", hybrid_risk_score=80, hybrid_action="lock", is_synthetic=False, created_at=now),
        LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1", hybrid_risk_score=None, hybrid_action=None, is_synthetic=True, created_at=now),
    ]
    db_session.add_all(events)
    db_session.commit()


def test_filter_by_username(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    response = client.get("/login-events", params={"username": "ali"}, headers=headers)
    body = response.json()
    assert body["total"] == 3
    assert all(item["attempted_username"] == "alice" for item in body["items"])


def test_filter_by_success(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    response = client.get("/login-events", params={"success": False}, headers=headers)
    body = response.json()
    assert body["total"] == 2
    assert all(item["success"] is False for item in body["items"])


def test_filter_by_the_action_the_engine_decided(client, db_session):
    """Lọc theo hành động ĐÃ LƯU, không theo điểm: hành động đã gồm ngưỡng riêng của tài khoản (MR15) và hành động tối
    thiểu của luật (MR21) — điểm 50 ở đây là `alert` dù 50 không vượt ngưỡng step_up của hồ sơ nào."""
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    totals = {action: client.get("/login-events", params={"action": action}, headers=headers).json()["total"] for action in ("allow", "alert", "step_up", "lock")}

    assert totals == {"allow": 1, "alert": 1, "step_up": 0, "lock": 1}
    assert client.get("/login-events", params={"action": "high"}, headers=headers).status_code == 422


def test_the_response_carries_the_action_bands_in_use_and_one_score_per_attempt(client, db_session):
    from app.detection import hybrid_runtime

    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    body = client.get("/login-events", headers=headers).json()

    bands = hybrid_runtime.get_engine().profile.bands
    assert body["action_bands"] == {"alert_at": bands.alert_at, "step_up_at": bands.step_up_at, "lock_at": bands.lock_at}
    assert all("risk_score" not in item and "ml_anomaly_score" not in item for item in body["items"])  # MR23: một điểm
    assert sorted(item["hybrid_risk_score"] for item in body["items"] if item["hybrid_risk_score"] is not None) == [10, 50, 80]


def test_filter_by_is_synthetic(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    real_only = client.get("/login-events", params={"is_synthetic": False}, headers=headers).json()
    synthetic_only = client.get("/login-events", params={"is_synthetic": True}, headers=headers).json()

    assert real_only["total"] == 3
    assert synthetic_only["total"] == 1


def test_combined_filters(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    response = client.get(
        "/login-events",
        params={"username": "alice", "success": True, "is_synthetic": False},
        headers=headers,
    )
    body = response.json()
    assert body["total"] == 1
