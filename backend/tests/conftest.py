"""Fixture dùng chung: DB SQLite in-memory + Redis giả lập (fakeredis)
riêng cho mỗi test, tách biệt hoàn toàn khỏi Postgres/Redis dev — test
không cần Docker đang chạy.
"""

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


class _DevRedisForbidden:
    """Thay cho client Redis dev thật trong suốt phiên test — mọi lời gọi đều lỗi rõ ràng."""

    def __getattr__(self, name):
        raise RuntimeError("Test đang gọi Redis dev THẬT (app.detection.rate_counter.redis_client) — phải dùng fixture fake_redis")


@pytest.fixture(autouse=True, scope="session")
def never_touch_dev_services():
    """Lưới an toàn (MR23): fixture `db_session`/`fake_redis` chuyển pipeline sang SQLite/fakeredis bằng monkeypatch THEO
    TỪNG TEST — một test gọi `monkeypatch.undo()` giữa chừng (hoặc quên dùng fixture) sẽ âm thầm rơi về Postgres/Redis DEV
    THẬT. Đã xảy ra khi viết test MR23: một lần đăng nhập giả ghi vào DB dev và sửa một cảnh báo có sẵn (đã khôi phục từ
    bản sao lưu). Từ đây: engine Postgres thật từ chối mọi kết nối, client Redis thật bị thay bằng đối tượng báo lỗi —
    rơi về dịch vụ thật thì test FAIL ngay thay vì ghi dữ liệu."""
    from sqlalchemy import event

    import app.detection.rate_counter as rate_counter
    from app.database import engine as dev_engine

    def refuse_connection(*args, **kwargs):
        raise RuntimeError("Test đang kết nối Postgres dev THẬT (app.database.engine) — phải dùng SQLite của fixture db_session")

    event.listen(dev_engine, "do_connect", refuse_connection)
    real_redis = rate_counter.redis_client
    rate_counter.redis_client = _DevRedisForbidden()
    yield
    rate_counter.redis_client = real_redis
    event.remove(dev_engine, "do_connect", refuse_connection)


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Thay redis_client thật bằng fakeredis cho MỌI test — brute force,
    credential stuffing đều dùng chung module app.detection.rate_counter.
    """
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("app.detection.rate_counter.redis_client", client)
    yield client
    client.flushall()


@pytest.fixture()
def db_session(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # app/detection/pipeline.py (background task của POST /login, nhiệm vụ
    # 5.2) mở SESSION RIÊNG qua app.database.SessionLocal — KHÔNG đi qua
    # Depends(get_db) nên override ở dưới không đụng tới nó. Không patch
    # chỗ này thì test sẽ âm thầm ghi vào Postgres dev thật (hoặc lỗi nếu
    # Postgres không chạy) thay vì SQLite in-memory của test.
    monkeypatch.setattr("app.detection.pipeline.SessionLocal", TestingSessionLocal)
    # app/main.py (MR12): sự kiện "startup" (đăng ký model_registry, nạp hybrid risk engine) cũng mở SESSION RIÊNG
    # qua app.database.SessionLocal, chạy khi TestClient(app) vào `with` — cùng lý do phải patch như trên.
    monkeypatch.setattr("app.main.SessionLocal", TestingSessionLocal)
    # app/detection/rule_engine_runtime.py cache blocklist (MR12) VÀ rule config (MR17) DB TTL 15s ở BIẾN MODULE
    # (persist giữa các test trong cùng tiến trình pytest) — xoá cả hai cache mỗi test để không đọc nhầm dữ liệu đã
    # cache từ DB (SQLite in-memory) của một test KHÁC chạy trước đó chưa quá 15 giây.
    from app.detection.login_context import invalidate_global_counts
    from app.detection.rule_engine_runtime import invalidate_blocklist_cache, invalidate_rule_config_cache
    from app.routers.model_health import invalidate_drift_cache

    invalidate_blocklist_cache()
    invalidate_rule_config_cache()
    # app/detection/login_context.py (MR20): bộ đếm toàn cục dùng chung cũng là biến module, TTL theo THỜI GIAN SỰ KIỆN —
    # các test dùng cùng mốc giả (2026-01-01...) nên bản đếm của test trước rất dễ "còn hạn" với DB của test sau.
    invalidate_global_counts()
    # app/routers/model_health.py (MR17): cache drift TTL 600s — RẤT dễ rò rỉ giữa các test nếu không xoá (dài hơn
    # nhiều so với thời gian chạy cả bộ test), không đụng _reference_frame_cache (file train RBA không đổi).
    invalidate_drift_cache()

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
