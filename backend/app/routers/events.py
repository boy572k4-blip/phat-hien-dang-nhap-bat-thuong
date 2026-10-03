"""GET /login-events — bảng log phân trang cho dashboard (nhiệm vụ 4.3),
có bộ lọc (nâng cấp thêm sau Tuần 7 — dashboard thật cần lọc được khi log
đã lên tới hàng nghìn bản ghi).

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1) — xem app/dependencies.py.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.detection import hybrid_runtime
from app.models import LoginEvent
from app.schemas import ActionBandsOut, PaginatedLoginEvents

router = APIRouter()


@router.get("/login-events", response_model=PaginatedLoginEvents)
def list_login_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    username: str | None = Query(None, description="Lọc gần đúng theo username (không phân biệt hoa/thường)"),
    success: bool | None = Query(None, description="Lọc theo kết quả đăng nhập"),
    action: str | None = Query(
        None, pattern="^(allow|alert|step_up|lock)$",
        description="Lọc theo hành động mà hybrid risk engine đã quyết định cho lần thử (MR23 — thay mức low/medium/high theo ngưỡng cứng 40/70 của Tuần 4)",
    ),
    is_synthetic: bool | None = Query(None, description="True = chỉ dữ liệu giả lập, False = chỉ dữ liệu thật"),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    query = db.query(LoginEvent)

    if username:
        query = query.filter(LoginEvent.attempted_username.ilike(f"%{username}%"))
    if success is not None:
        query = query.filter(LoginEvent.success.is_(success))
    if is_synthetic is not None:
        query = query.filter(LoginEvent.is_synthetic.is_(is_synthetic))
    if action is not None:
        # Lọc theo hành động ĐÃ LƯU của từng lần thử, không tính lại từ điểm: hành động đã phản ánh ngưỡng riêng của tài
        # khoản (MR15) và hành động tối thiểu của luật (MR21) — hai thứ một ngưỡng điểm cố định không thấy được.
        query = query.filter(LoginEvent.hybrid_action == action)

    query = query.order_by(LoginEvent.created_at.desc())
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    bands = hybrid_runtime.get_engine().profile.bands
    return PaginatedLoginEvents(
        items=items, total=total, page=page, page_size=page_size,
        action_bands=ActionBandsOut(alert_at=bands.alert_at, step_up_at=bands.step_up_at, lock_at=bands.lock_at),
    )
