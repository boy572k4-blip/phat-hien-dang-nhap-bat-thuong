"""Hash mật khẩu (bcrypt) + JWT cho admin/WebSocket (nhiệm vụ 5.1).

Mật khẩu: không bao giờ lưu/so sánh plain text.

MR32: `check_password` chạy bcrypt cả khi tài khoản KHÔNG tồn tại (so với một hash giả cùng độ khó) — trước đó `/login` và
`/admin/login` trả lời trong vài ms cho tên không tồn tại và ~230 ms cho tên có thật, nên thời gian phản hồi để lộ tài khoản nào
có thật dù thông báo lỗi giống hệt nhau. JWT bắt buộc có `exp`/`iat`/`sub`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import get_settings

# bcrypt của một chuỗi ngẫu nhiên đã bỏ đi (không ai biết mật khẩu), cùng độ khó 12 với `bcrypt.gensalt()` mặc định.
_DUMMY_PASSWORD_HASH = b"$2b$12$N7owFpQ4KuzexMdqeW9.H.f4636MPSE8mJFxADutJWKPITzvWKC9u"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def check_password(password: str, password_hash: str | None) -> bool:
    """Như `verify_password`, nhưng `password_hash=None` (tài khoản không tồn tại) vẫn tốn đúng một lần bcrypt rồi trả False."""
    if password_hash is None:
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_PASSWORD_HASH)
        return False
    return verify_password(password, password_hash)


def create_admin_access_token(admin_id: int, username: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(admin_id),
        "username": username,
        "role": "admin",
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_admin_access_token(token: str) -> dict | None:
    """Trả payload nếu token hợp lệ (chữ ký đúng + chưa hết hạn + role=admin),
    None nếu bất kỳ điều kiện nào sai — KHÔNG raise, để gọi được cả từ
    middleware HTTP lẫn WebSocket handshake mà không phải try/except lặp lại.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm], options={"require": ["exp", "iat", "sub"]})
    except jwt.PyJWTError:
        return None

    if payload.get("role") != "admin":
        return None
    return payload
