"""Kiểm tra nhiệm vụ 1.3 — backend chạy được và báo đúng trạng thái kết nối DB.

MR23: dùng DB SQLite của fixture `client`/`db_session` (vá `app.main.SessionLocal`). Trước đây test này dựng TestClient
riêng ở cấp module và gọi THẲNG Postgres dev — cần Docker đang chạy, trái với cam kết của conftest; lưới an toàn MR23
(`never_touch_dev_services`) chặn mọi kết nối tới Postgres dev nên lộ ra."""


def test_health_returns_200_and_connected(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "connected"}


def test_health_reports_an_unreachable_database_instead_of_failing(client, monkeypatch):
    def unreachable():
        raise OSError("không kết nối được DB")

    monkeypatch.setattr("app.main.SessionLocal", unreachable)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "unavailable"}
