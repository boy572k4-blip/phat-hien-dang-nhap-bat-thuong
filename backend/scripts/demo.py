"""MR36 — dữ liệu và kiểm tra cho buổi demo (chạy qua `demo/start.ps1`, `demo/reset.ps1`; hướng dẫn: docs/demo-guide.md).

Demo chạy trên DB RIÊNG `lad_demo` + Redis db 3 — không bao giờ đụng DB dev `lad_db` (lệnh `reset` tự kiểm tra tên DB, từ chối mọi tên
không kết thúc bằng `_demo`).

    cd backend
    venv\\Scripts\\python.exe -m scripts.demo reset     # xoá và dựng lại lad_demo + xoá Redis db 3 (~1 phút)
    venv\\Scripts\\python.exe -m scripts.demo check     # kiểm tra trước khi demo, in cách sửa cho từng mục lỗi
    venv\\Scripts\\python.exe -m scripts.demo ensure    # dựng lad_demo nếu chưa có (start.ps1 gọi)
    venv\\Scripts\\python.exe -m scripts.demo env       # in biến môi trường demo (start.ps1 dùng)

Dữ liệu sau `reset` luôn giống nhau (seed cố định) và mốc thời gian tính theo LÚC CHẠY: 25 tài khoản `user001`-`user025` (mật khẩu
`Demo@12345`), mỗi tài khoản 60 ngày lịch sử đăng nhập kết thúc hôm qua — ngày bảo vệ chạy reset thì hệ thống thấy y như lúc thử (lịch sử
sinh một lần rồi để đó sẽ "già" dần: quá 90 ngày thì mọi lần đăng nhập demo đều khớp luật tài khoản ngủ đông). Tài khoản quản trị
`admin_demo` / `Admin@Demo2026`. Không có cảnh báo, khoá, chiến dịch, phản hồi hay ghi đè luật nào.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
DEMO_DB = "lad_demo"
DEMO_REDIS_DB = 3
DEMO_SEED = 2026
DEMO_USERS = 25
DEMO_PASSWORD = "Demo@12345"
DEMO_ADMIN = ("admin_demo", "Admin@Demo2026")
HISTORY_DAYS = 60
PORTS = {"backend": 8000, "frontend": 5173}


def _dotenv() -> dict[str, str]:
    path = ROOT / ".env"
    if not path.is_file():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def demo_env() -> dict[str, str]:
    """Biến môi trường cho backend demo: DB/Redis demo, tin X-Forwarded-For (script tấn công giả lập IP), khoá JWT ổn định."""
    env = _dotenv()
    base_db = env.get("DATABASE_URL", "postgresql+psycopg2://lad_user:lad_password@localhost:5432/lad_db")
    db_url = re.sub(r"/[^/?]+(\?.*)?$", f"/{DEMO_DB}", base_db).replace("@localhost:", "@127.0.0.1:")
    redis_url = re.sub(r"/\d+$", "", env.get("REDIS_URL", "redis://localhost:6379/0")).replace("localhost", "127.0.0.1") + f"/{DEMO_REDIS_DB}"
    out = {"DATABASE_URL": db_url, "REDIS_URL": redis_url, "TRUST_FORWARDED_FOR": "true"}
    secret_file = ROOT / "demo" / ".jwt_secret"  # khoá riêng của máy demo, không vào git — đăng nhập quản trị không mất khi khởi động lại
    if secret_file.is_file():
        out["JWT_SECRET_KEY"] = secret_file.read_text(encoding="utf-8").strip()
    return out


def _apply_demo_env() -> None:
    """Gọi TRƯỚC khi import `app.*`: mọi engine/kết nối tạo ra sau đó đều trỏ vào DB/Redis demo."""
    os.environ.update(demo_env())
    if not os.environ["DATABASE_URL"].rstrip("/").endswith("_demo"):
        sys.exit(f"Từ chối: DB đích không phải DB demo ({os.environ['DATABASE_URL']})")


# --------------------------------------------------------------------------------------------------------------------- reset


def _recreate_database(db_url: str) -> None:
    import psycopg2

    match = re.match(r"postgresql(?:\+psycopg2)?://([^:]+):([^@]+)@([^:/]+):(\d+)/(\w+)$", db_url)
    if not match or not match.group(5).endswith("_demo"):
        sys.exit(f"Từ chối: không nhận ra DB demo trong {db_url}")
    user, password, host, port, name = match.groups()
    conn = psycopg2.connect(dbname="postgres", user=user, password=password, host=host, port=port)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        cur.execute(f'CREATE DATABASE "{name}"')
    conn.close()


def _seed(db) -> tuple[int, int]:
    from app.detection.baseline import update_baseline_after_successful_login
    from app.models import Admin, User
    from app.security import hash_password
    from scripts.generate_labeled_anomalies import ANOMALIES_PER_USER_RANGE, NORMAL_LOGINS_PER_USER_RANGE, make_anomalous_events, make_normal_events, make_user_profile

    random.seed(DEMO_SEED)
    password_hash = hash_password(DEMO_PASSWORD)
    latest = datetime.now(timezone.utc) - timedelta(hours=12)
    n_events = 0
    for i in range(1, DEMO_USERS + 1):
        profile = make_user_profile(i)
        user = User(username=profile["username"], password_hash=password_hash, created_at=latest - timedelta(days=HISTORY_DAYS + 1))
        db.add(user)
        db.flush()
        events = make_normal_events(user, profile, random.randint(*NORMAL_LOGINS_PER_USER_RANGE))
        events += [event for event, _ in make_anomalous_events(user, profile, random.randint(*ANOMALIES_PER_USER_RANGE))]
        for event in events:
            # Bộ sinh gốc đặt giờ trong ngày SAU khi lùi ngày nên có thể rơi vào tương lai — lùi về trước "hôm qua".
            while event.created_at > latest:
                event.created_at -= timedelta(days=1)
        events.sort(key=lambda e: e.created_at)
        db.add_all(events)
        db.flush()
        for event in events:
            update_baseline_after_successful_login(db, user, event)
        n_events += len(events)
    db.add(Admin(username=DEMO_ADMIN[0], password_hash=hash_password(DEMO_ADMIN[1])))
    db.commit()
    return DEMO_USERS, n_events


def reset() -> None:
    _apply_demo_env()
    print(f"Dựng lại DB demo {DEMO_DB} (DB dev không bị đụng tới)...", flush=True)
    _recreate_database(os.environ["DATABASE_URL"])
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, check=True, env=os.environ.copy(),
                   stdout=subprocess.DEVNULL)

    import redis

    redis.Redis.from_url(os.environ["REDIS_URL"]).flushdb()

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(os.environ["DATABASE_URL"])
    db = sessionmaker(bind=engine, autoflush=False)()
    try:
        users, events = _seed(db)
    finally:
        db.close()
        engine.dispose()
    print(f"Xong: {users} tài khoản (mật khẩu {DEMO_PASSWORD}), {events} lần đăng nhập lịch sử, quản trị {DEMO_ADMIN[0]} / {DEMO_ADMIN[1]}; "
          f"Redis db {DEMO_REDIS_DB} đã xoá.", flush=True)


# --------------------------------------------------------------------------------------------------------------------- check


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def check(expect_running: bool = False) -> bool:
    """In ✓/✗ cho từng điều kiện của buổi demo kèm cách sửa; trả True nếu không có mục ✗."""
    _apply_demo_env()
    results: list[tuple[bool, str, str]] = []

    def item(ok: bool, label: str, fix: str = "") -> None:
        results.append((ok, label, fix))

    from sqlalchemy import create_engine, text

    try:
        engine = create_engine(os.environ["DATABASE_URL"])
        with engine.connect() as conn:
            users = conn.execute(text("SELECT count(*) FROM users WHERE username LIKE 'user0%'")).scalar()
            admins = conn.execute(text("SELECT count(*) FROM admins WHERE username = :u"), {"u": DEMO_ADMIN[0]}).scalar()
            alerts = conn.execute(text("SELECT count(*) FROM alerts")).scalar()
            latest = conn.execute(text("SELECT max(created_at) FROM login_events WHERE is_synthetic")).scalar()
        engine.dispose()
        item(users == DEMO_USERS and admins == 1, f"DB {DEMO_DB}: {users} tài khoản demo, tài khoản quản trị {DEMO_ADMIN[0]}", "chạy demo/reset.ps1")
        item(alerts == 0 or expect_running, f"DB {DEMO_DB}: {alerts} cảnh báo (sạch = 0)", "chạy demo/reset.ps1 để demo từ đầu")
        if latest is not None:
            age = (datetime.now(timezone.utc) - latest).days
            item(age <= 30, f"lịch sử đăng nhập kết thúc {age} ngày trước", "chạy demo/reset.ps1 (lịch sử cũ làm mọi lần đăng nhập demo bị coi là ngủ đông)")
    except Exception as exc:  # noqa: BLE001 — công cụ kiểm tra: báo lỗi, không sập
        item(False, f"kết nối DB {DEMO_DB}: {type(exc).__name__}", "bật Docker (docker compose up -d) rồi chạy demo/reset.ps1")

    try:
        import redis

        redis.Redis.from_url(os.environ["REDIS_URL"], socket_timeout=3).ping()
        item(True, f"Redis db {DEMO_REDIS_DB}")
    except Exception as exc:  # noqa: BLE001
        item(False, f"Redis: {type(exc).__name__}", "bật Docker (docker compose up -d)")

    artifacts = BACKEND / "ml" / "artifacts"
    for rel, what in (("rba/hybrid_cp2.joblib", "mô hình hybrid_cp2"), ("isolation_forest.joblib", "mô hình địa lý–thời gian"),
                      ("scaler.joblib", "bộ chuẩn hoá của mô hình địa lý"), ("meta.json", "hiệu chỉnh mô hình địa lý")):
        item((artifacts / rel).is_file(), f"{what} ({rel})", "thiếu tệp mô hình — chép thư mục backend/ml/artifacts từ máy đã huấn luyện")
    for name in ("GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"):
        item((BACKEND / "geoip" / name).is_file(), f"GeoIP {name}", "xem docs/geoip-setup.md")
    threat = BACKEND / "threat_intel"
    item(threat.is_dir() and any(threat.iterdir()), "danh sách Tor/VPN/datacenter (threat_intel/)", "venv\\Scripts\\python.exe -m scripts.update_threat_feeds")

    try:
        # Nạp mô hình y như backend lúc khởi động — mã đặc trưng đổi mà mô hình cũ thì backend âm thầm tắt ML (chỉ ghi log).
        from sqlalchemy.orm import sessionmaker

        from app.detection import hybrid_runtime, model_registry

        engine = create_engine(os.environ["DATABASE_URL"])
        db = sessionmaker(bind=engine)()
        try:
            model_registry.ensure_registered(db)
            ml_on = hybrid_runtime.load_at_startup(db).ml_available
        finally:
            db.close()
            engine.dispose()
        item(ml_on, "mô hình hybrid_cp2 nạp được (không rơi về chế độ chỉ luật)", "xem log: thiếu tệp hoặc chữ ký đặc trưng không khớp — cần huấn luyện lại")
    except Exception as exc:  # noqa: BLE001
        item(False, f"nạp mô hình hybrid_cp2: {type(exc).__name__}", "xem thông báo lỗi phía trên")

    jwt_ok = bool(os.environ.get("JWT_SECRET_KEY"))
    item(jwt_ok, "khoá JWT riêng của máy demo (demo/.jwt_secret)", "demo/start.ps1 tự tạo ở lần chạy đầu")

    for name, port in PORTS.items():
        free = _port_free(port)
        item(free != expect_running, f"cổng {port} ({name}) {'đang chạy' if not free else 'trống'}",
             "đóng chương trình đang dùng cổng (một backend/frontend khác?) hoặc chạy demo/stop.ps1" if expect_running is False else "chạy demo/start.ps1")

    for ok, label, fix in results:
        print(f"  {'✓' if ok else '✗'} {label}" + ("" if ok else f"  →  {fix}"))
    bad = sum(not ok for ok, _, _ in results)
    print(f"{'Sẵn sàng demo.' if bad == 0 else f'{bad} mục cần xử lý.'}", flush=True)
    return bad == 0


def ensure() -> None:
    """Dựng DB demo nếu chưa có hoặc thiếu tài khoản demo; có rồi thì giữ nguyên (muốn làm sạch: `reset`)."""
    _apply_demo_env()
    from sqlalchemy import create_engine, text

    engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with engine.connect() as conn:
            ready = conn.execute(text("SELECT count(*) FROM users WHERE username LIKE 'user0%'")).scalar() == DEMO_USERS
    except Exception:  # noqa: BLE001 — DB chưa tồn tại / chưa có bảng
        ready = False
    finally:
        engine.dispose()
    if ready:
        print(f"DB demo {DEMO_DB} đã có — giữ nguyên (làm sạch: demo/reset.ps1).", flush=True)
    else:
        reset()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("reset", "ensure", "check", "env"))
    parser.add_argument("--running", action="store_true", help="check: backend/frontend đang chạy (cổng phải bận, cho phép có cảnh báo)")
    args = parser.parse_args()
    if args.command == "reset":
        reset()
    elif args.command == "ensure":
        ensure()
    elif args.command == "check":
        sys.exit(0 if check(expect_running=args.running) else 1)
    else:
        for key, value in demo_env().items():
            print(f"{key}={value}")


if __name__ == "__main__":
    main()
