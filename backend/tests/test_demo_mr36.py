"""MR36 — dữ liệu demo: luôn trỏ vào DB riêng `lad_demo` (không bao giờ DB dev), dữ liệu sinh ra giống nhau mỗi lần và mốc thời gian tính
theo lúc chạy (không có lần đăng nhập nào ở tương lai)."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models import Admin, LoginEvent, User, UserBaseline
from app.utils.time import ensure_utc
from scripts import demo


def test_demo_env_points_to_the_demo_database_and_redis(monkeypatch):
    monkeypatch.setattr(demo, "_dotenv", lambda: {"DATABASE_URL": "postgresql+psycopg2://u:p@localhost:5432/lad_db", "REDIS_URL": "redis://localhost:6379/0"})
    env = demo.demo_env()
    assert env["DATABASE_URL"] == "postgresql+psycopg2://u:p@127.0.0.1:5432/lad_demo"
    assert env["REDIS_URL"] == "redis://127.0.0.1:6379/3"
    assert env["TRUST_FORWARDED_FOR"] == "true"


def test_recreating_any_database_other_than_a_demo_one_is_refused():
    with pytest.raises(SystemExit):
        demo._recreate_database("postgresql+psycopg2://u:p@127.0.0.1:5432/lad_db")


def _seeded(db_session):
    demo._seed(db_session)
    events = db_session.query(LoginEvent).order_by(LoginEvent.id).all()
    return events, [(e.attempted_username, e.country, e.ip_address) for e in events]


def test_seed_is_repeatable_relative_to_now_and_builds_baselines(db_session):
    events, first = _seeded(db_session)
    now = datetime.now(timezone.utc)

    assert db_session.query(User).count() == demo.DEMO_USERS
    assert db_session.query(Admin).filter(Admin.username == demo.DEMO_ADMIN[0]).count() == 1
    assert db_session.query(UserBaseline).count() == demo.DEMO_USERS
    times = [ensure_utc(e.created_at) for e in events]
    assert max(times) <= now - timedelta(hours=11)                       # không có lần đăng nhập ở tương lai
    assert min(times) >= now - timedelta(days=demo.HISTORY_DAYS + 2)
    assert all(e.is_synthetic and e.success for e in events)

    db_session.query(UserBaseline).delete()
    db_session.query(LoginEvent).delete()
    db_session.query(User).delete()
    db_session.query(Admin).delete()
    db_session.commit()
    _, second = _seeded(db_session)
    assert second == first                                                # seed cố định: cùng tài khoản, nơi ở, IP mỗi lần reset
