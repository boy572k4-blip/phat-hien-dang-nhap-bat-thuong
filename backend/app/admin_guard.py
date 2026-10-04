"""MR32 — bảo vệ chính cửa đăng nhập quản trị `POST /admin/login` (trước MR32: thử không giới hạn, không ghi vết).

Mọi lần thử được ghi vào `audit_log` (nguồn sự thật duy nhất, quản trị viên xem ở dashboard qua `GET /admin/login-attempts` — không
cần bảng mới hay Redis), và hai giới hạn đọc lại từ chính các dòng đó:
  1. Theo IP: >= 10 lần sai trong 15 phút từ một IP (với mọi tên) -> IP đó bị từ chối (429) cho tới khi lần sai cũ ra khỏi cửa sổ.
  2. Theo tài khoản, kiểu "khoá thông minh": >= 5 lần sai trong 15 phút vào một tên -> tên đó bị từ chối, nhưng đếm RIÊNG hai cửa:
     IP QUEN (đã đăng nhập quản trị thành công bằng tên này trong 90 ngày) và IP LẠ. Kẻ tấn công từ IP lạ chỉ khoá được cửa IP lạ —
     quản trị viên ở máy quen vẫn vào được, cơ chế khoá không thành công cụ để chặn quản trị viên. Đăng nhập đúng xoá bộ đếm của cửa đó.

Chống vượt giới hạn bằng request song song: dòng của lần thử được GHI TRƯỚC (tạm coi là sai) rồi mới đếm, và bcrypt chạy sau — trong
N request đồng thời, request có dòng thứ (giới hạn + 1) chắc chắn đếm thấy đủ và bị từ chối. Lần bị từ chối không chạy bcrypt (không
tốn CPU băm) và không tính là lần sai (không kéo dài khoá mãi).

Không dùng danh sách khoá (`blocklist`) của phần phát hiện ở đây: script tấn công demo chạy cùng máy với quản trị viên (127.0.0.1),
khoá tự động theo IP sẽ khoá luôn người cần vào để mở khoá.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models import Admin, AuditLog
from app.utils.time import ensure_utc

WINDOW = timedelta(minutes=15)
MAX_FAILURES_PER_IP = 10
MAX_FAILURES_PER_ACCOUNT = 5
FAMILIAR_LOOKBACK = timedelta(days=90)
USER_AGENT_MAX = 256

SUCCESS, FAILURE, REJECTED = "admin_login_success", "admin_login_failed", "admin_login_rejected"
ACTIONS = (SUCCESS, FAILURE, REJECTED)


@dataclass(frozen=True)
class Refusal:
    scope: str  # "ip" | "account"
    retry_after_s: int


@dataclass(frozen=True)
class Attempt:
    row_id: int
    familiar: bool
    refusal: Refusal | None


@dataclass(frozen=True)
class _Row:
    id: int
    at: datetime
    action: str
    username: str
    ip: str
    familiar: bool


def _rows(db: Session, since: datetime, actions: tuple[str, ...]) -> list[_Row]:
    rows = db.query(AuditLog.id, AuditLog.created_at, AuditLog.action, AuditLog.detail).filter(AuditLog.action.in_(actions), AuditLog.created_at >= since)
    out = []
    for row_id, created_at, action, detail in rows:
        detail = detail or {}
        out.append(_Row(row_id, ensure_utc(created_at), action, str(detail.get("username", "")), str(detail.get("ip", "")), bool(detail.get("familiar"))))
    return out


def is_familiar(db: Session, *, username: str, ip: str, now: datetime) -> bool:
    """IP này đã từng đăng nhập quản trị thành công bằng tên này trong `FAMILIAR_LOOKBACK`."""
    return any(r.username == username and r.ip == ip for r in _rows(db, now - FAMILIAR_LOOKBACK, (SUCCESS,)))


def _failures_since_last_success(rows: list[_Row]) -> list[_Row]:
    last = max((r.at for r in rows if r.action == SUCCESS), default=None)
    return [r for r in rows if r.action == FAILURE and (last is None or r.at > last)]


def _refusal(rows: list[_Row], own_id: int, limit: int, scope: str, now: datetime) -> Refusal | None:
    """`rows` gồm cả dòng của chính lần thử này (tạm coi là sai): vượt giới hạn khi số lần sai TRƯỚC nó đã đủ `limit`."""
    earlier = sorted(r.at for r in _failures_since_last_success(rows) if r.id != own_id)
    if len(earlier) < limit:
        return None
    unlock_at = earlier[len(earlier) - limit] + WINDOW  # lúc lần sai cũ nhất trong `limit` lần gần nhất ra khỏi cửa sổ
    return Refusal(scope, max(1, math.ceil((unlock_at - now).total_seconds())))


def begin(db: Session, *, username: str, ip: str, user_agent: str | None, now: datetime) -> Attempt:
    """Ghi lần thử (tạm là sai) rồi kiểm tra giới hạn; bị từ chối thì dòng đó đổi thành `admin_login_rejected`."""
    familiar = is_familiar(db, username=username, ip=ip, now=now)
    detail = {"username": username, "ip": ip, "user_agent": (user_agent or "")[:USER_AGENT_MAX], "familiar": familiar}
    row = AuditLog(actor="system", action=FAILURE, target_type="admin", target_id=None, detail=detail, created_at=now)
    db.add(row)
    db.commit()

    recent = _rows(db, now - WINDOW, (SUCCESS, FAILURE))
    refusal = _refusal([r for r in recent if r.ip == ip], row.id, MAX_FAILURES_PER_IP, "ip", now) or _refusal(
        [r for r in recent if r.username == username and r.familiar == familiar], row.id, MAX_FAILURES_PER_ACCOUNT, "account", now
    )
    if refusal is not None:
        row.action, row.detail = REJECTED, {**detail, "scope": refusal.scope}
        db.commit()
    return Attempt(row_id=row.id, familiar=familiar, refusal=refusal)


def succeed(db: Session, attempt: Attempt, admin: Admin) -> None:
    row = db.get(AuditLog, attempt.row_id)
    row.action, row.actor, row.target_id = SUCCESS, admin.username, admin.id
    db.commit()


def recent_attempts(db: Session, limit: int) -> list[AuditLog]:
    return db.query(AuditLog).filter(AuditLog.action.in_(ACTIONS)).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit).all()
