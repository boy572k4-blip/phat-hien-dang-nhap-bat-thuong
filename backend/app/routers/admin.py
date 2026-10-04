"""POST /admin/login — đăng nhập quản trị viên (nhiệm vụ 5.1).

Hoàn toàn tách biệt khỏi POST /login (web app mẫu): bảng `admins` riêng,
không có logic detection/log login_events cho luồng này (đây là backend
office, không phải mục tiêu giám sát).

MR32: cửa này tự bảo vệ — giới hạn số lần sai theo IP và theo tài khoản (khoá thông minh tách IP quen/IP lạ), khoá tạm 15 phút, ghi
vết mọi lần thử, bcrypt chạy cả khi tên không tồn tại (`app/admin_guard.py`). `GET /admin/login-attempts` cho quản trị viên xem lại.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import admin_guard
from app.database import get_db
from app.dependencies import require_admin
from app.models import Admin
from app.schemas import AdminLoginAttemptOut, AdminLoginRequest, AdminLoginResponse
from app.security import check_password, create_admin_access_token
from app.utils.network import resolve_client_ip
from app.utils.time import ensure_utc

router = APIRouter()

_OUTCOMES = {admin_guard.SUCCESS: "success", admin_guard.FAILURE: "failed", admin_guard.REJECTED: "rejected"}


@router.post("/admin/login", response_model=AdminLoginResponse)
def admin_login(payload: AdminLoginRequest, request: Request, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    attempt = admin_guard.begin(db, username=payload.username, ip=resolve_client_ip(request), user_agent=request.headers.get("user-agent"), now=now)
    if attempt.refusal is not None:
        minutes = -(-attempt.refusal.retry_after_s // 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, headers={"Retry-After": str(attempt.refusal.retry_after_s)},
            detail=f"Đăng nhập quản trị sai quá nhiều lần — tạm khoá, thử lại sau khoảng {minutes} phút.",
        )

    admin = db.query(Admin).filter(Admin.username == payload.username).first()
    if not check_password(payload.password, admin.password_hash if admin else None):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sai tài khoản hoặc mật khẩu quản trị")

    admin_guard.succeed(db, attempt, admin)
    token = create_admin_access_token(admin.id, admin.username)
    return AdminLoginResponse(access_token=token, token_type="bearer")


@router.get("/admin/login-attempts", response_model=list[AdminLoginAttemptOut])
def list_admin_login_attempts(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), _admin: dict = Depends(require_admin)):
    out = []
    for row in admin_guard.recent_attempts(db, limit):
        detail = row.detail or {}
        out.append(AdminLoginAttemptOut(
            id=row.id, created_at=ensure_utc(row.created_at), outcome=_OUTCOMES[row.action], username=str(detail.get("username", "")),
            ip=str(detail.get("ip", "")), user_agent=detail.get("user_agent") or None, familiar_ip=bool(detail.get("familiar")),
            refused_scope=detail.get("scope"),
        ))
    return out
