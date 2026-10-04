"""MR28 — tín hiệu từ "cửa" của `POST /login` và `POST /login/verify-otp` cho rule engine v2.

Hai loại lần thử KHÔNG đi qua pipeline phát hiện nên trước MR28 không luật nào thấy:
  - lần thử bị từ chối NGAY vì tài khoản/IP đang bị khoá (MR16: trả 423 trước cả bước kiểm tra mật khẩu, chỉ ghi audit);
  - lần nhập SAI mã OTP (MR16: chỉ tăng bộ đếm của từng mã).
Ở đây chúng được ghi vào CHÍNH bộ đếm cửa sổ thời gian mà luật đọc (`app/detection/engine/indexes.py`), kèm audit — luật `blocked_retry` và
`otp_guessing` chấm ở lần đăng nhập kế tiếp đi qua pipeline. Bộ chạy bộ dữ liệu có nhãn (`ml/corpus/run.py`) gọi đúng các hàm này để tái hiện
cửa của `/login`, nên số đo không phải một bản sao logic.

Không bao giờ chặn luồng đăng nhập: lỗi ghi bộ đếm (Redis) chỉ ghi log — tín hiệu bị lỡ, không phải từ chối người dùng.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.detection import rate_counter
from app.detection.engine import RedisStore
from app.detection.engine import indexes as K
from app.detection.engine.intel import BlockEntry
from app.detection.engine.types import LoginAttempt
from app.detection.rule_engine_runtime import refresh_blocklist
from app.models import AuditLog

logger = logging.getLogger("gate")


def blocking_entry(db: Session, *, username: str, ip: str, at: datetime) -> BlockEntry | None:
    """Mục khoá còn hiệu lực ở thời điểm `at` chặn lần thử này (theo IP, dải, tên đăng nhập — không tra ASN ở cửa vì cần GeoIP; khối theo ASN
    vẫn bị bắt trong pipeline qua luật `blocklist_hit`)."""
    return refresh_blocklist(db).match(LoginAttempt(ts=at.timestamp(), username=username, success=False, ip=ip))


def _record(action, what: str) -> None:
    try:
        action(RedisStore(rate_counter.redis_client))
    except Exception:  # noqa: BLE001 — xem docstring module
        logger.exception("không ghi được bộ đếm %s — luật tương ứng sẽ thiếu lần thử này", what)


def reject_blocked(db: Session, *, username: str, ip: str, entry: BlockEntry, at: datetime) -> None:
    """Ghi một lần thử bị từ chối vì đang bị khoá: audit (như MR16) + bộ đếm `blk:u`/`blk:ip` cho luật `blocked_retry`."""
    db.add(AuditLog(
        actor="system", action="reject_blocked_login", target_type="blocklist", target_id=None,
        detail={"username": username, "ip": ip, "blocklist_kind": entry.kind, "blocklist_value": entry.value},
    ))
    db.commit()
    _record(lambda store: K.record_blocked(store, username, ip, at.timestamp()), "blk")


def record_otp_failure(user_id: int, at: datetime) -> None:
    """Một lần nhập sai mã OTP của tài khoản `user_id` — bộ đếm `otpf:u` cho luật `otp_guessing`."""
    _record(lambda store: K.record_otp_failure(store, str(user_id), at.timestamp()), "otpf")


def otp_failed(db: Session, *, challenge_id: int, user_id: int, attempts: int, reason: str, at: datetime) -> None:
    """Lần gửi mã OTP thất bại ở `POST /login/verify-otp`: audit (để quản trị viên thấy ai đang đoán mã) + bộ đếm."""
    db.add(AuditLog(
        actor="system", action="verify_otp_failed", target_type="otp_challenge", target_id=challenge_id,
        detail={"user_id": user_id, "attempts": attempts, "reason": reason},
    ))
    db.commit()
    record_otp_failure(user_id, at)
