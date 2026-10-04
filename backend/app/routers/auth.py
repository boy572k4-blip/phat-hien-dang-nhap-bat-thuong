"""POST /login — đăng nhập web app mẫu (nhiệm vụ 2.1). Không log payload ở đâu (không print/logging.debug request) để
mật khẩu không bao giờ lộ ra dạng plain text trong log hệ thống.

Đường nhanh (mặc định, không đổi từ MR12): CHỈ xác thực mật khẩu rồi trả response ngay, detection engine chạy NỀN
(`app/detection/pipeline.py`, nhiệm vụ 5.2) — không chặn thời gian phản hồi.

MR16 "Phản ứng tự động (mô phỏng)" đổi đường đi cho HAI trường hợp, THỰC THI THẬT các đề xuất mà trước đó chỉ ghi nhận
(`ResponseAction.status` luôn `"recommended"` từ MR12):
  1. Tài khoản hoặc IP đang bị KHOÁ (`Blocklist`, `app/detection/engine/intel.py` — đã hỗ trợ `kind="username"` + hạn
     dùng từ MR9): từ chối NGAY LẬP TỨC, KHÔNG xác thực mật khẩu (không lộ tài khoản có tồn tại/mật khẩu đúng hay không
     cho một request chắc chắn bị từ chối).
  2. Mật khẩu ĐÚNG nhưng hybrid risk engine đề xuất `step_up`/`lock` CHO CHÍNH lần thử này: phải CHỜ kết quả chấm điểm
     (`await run_detection_pipeline` trực tiếp, KHÔNG qua `BackgroundTasks`) trước khi trả response — đây là cách DUY
     NHẤT biết được có cần OTP/khoá ngay hay không, đổi lại độ trễ CAO HƠN đường nhanh cho ĐÚNG những lần thử này (đo
     được, xem `docs/automated-response.md`). Lần thử SAI mật khẩu vẫn đi đường nhanh như cũ (không có gì để "chờ"
     thêm khi đã từ chối rồi — OTP chỉ có ý nghĩa SAU KHI mật khẩu đã đúng).

`POST /login/verify-otp` hoàn tất bước xác thực thêm ở (2).

MR28: hai loại lần thử không qua pipeline — bị từ chối vì đang khoá ở (1), và nhập sai mã OTP — được ghi vào bộ đếm của rule engine qua
`app/detection/gate.py` (luật `blocked_retry`, `otp_guessing` chấm ở lần đăng nhập kế tiếp).

MR32: tên đăng nhập không tồn tại vẫn tốn một lần bcrypt (`check_password`) — trước đó thời gian phản hồi (~vài ms so với ~230 ms) để
lộ tài khoản nào có thật. Mã OTP demo chỉ trả trong response khi KHÔNG chạy production (`APP_ENV=production`: mã chỉ ghi ra log máy chủ
như một kênh gửi mô phỏng — người cầm mật khẩu không tự nhận được mã).
"""

from datetime import datetime, timezone

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.detection import gate
from app.detection.pipeline import run_detection_pipeline
from app.detection.response_execution import OTP_MAX_ATTEMPTS, OTP_TTL, generate_otp_code, hash_otp_code, otp_code_matches
from app.models import AuditLog, OtpChallenge, ResponseAction, User
from app.schemas import LoginRequest, LoginResponse, OtpVerifyRequest
from app.security import check_password
from app.utils.network import resolve_client_ip
from app.utils.time import ensure_utc

router = APIRouter()
logger = logging.getLogger("auth")

_LOCKED_MESSAGE = "Tài khoản hoặc nguồn đăng nhập đang tạm khoá do hoạt động bất thường. Thử lại sau."
_OTP_INVALID_MESSAGE = "Mã xác thực không đúng hoặc đã hết hạn."


def _locked_response() -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_423_LOCKED, content={"success": False, "message": _LOCKED_MESSAGE, "locked": True})


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    ip = resolve_client_ip(request)
    user_agent = request.headers.get("user-agent")
    now = datetime.now(timezone.utc)

    # --- MR16 (1): chặn NGAY nếu tài khoản hoặc IP đang bị khoá — TRƯỚC CẢ khi xác thực mật khẩu (không tốn bcrypt
    # cho một request chắc chắn bị từ chối, không lộ mật khẩu đúng/sai qua thời gian phản hồi khi đã bị khoá). Không
    # tra ASN ở đây (đắt — cần GeoIP) nên khối chặn theo ASN không bị bắt ở bước này; vẫn được bắt sau khi mật khẩu
    # đúng, ở nhánh `result.hybrid_action == "lock"` bên dưới (pipeline CÓ tra ASN) — precheck chỉ là đường tắt cho các
    # loại rẻ để kiểm (ip/cidr/username), không phải ranh giới an toàn duy nhất.
    block_entry = gate.blocking_entry(db, username=payload.username, ip=ip, at=now)
    if block_entry is not None:
        # Không chạy lại toàn bộ pipeline chấm điểm cho một kết quả đã CHẮC CHẮN là "lock" — nhưng vẫn ghi vết (audit) để
        # quản trị viên thấy, và (MR28) ghi vào bộ đếm để luật `blocked_retry` thấy người cứ thử tiếp khi khoá hết hạn.
        gate.reject_blocked(db, username=payload.username, ip=ip, entry=block_entry, at=now)
        return _locked_response()

    user = db.query(User).filter(User.username == payload.username).first()
    # So khớp hash chứ không so plain text. MR20: bcrypt (~230 ms CPU, cố ý chậm) chạy ở threadpool — gọi thẳng trong hàm
    # `async` này sẽ CHẶN vòng lặp sự kiện dùng chung, mọi request đăng nhập đồng thời phải xếp hàng chờ nhau (đo: 10
    # request đồng thời mất ~3 giây). Thư viện bcrypt nhả GIL khi băm nên các lần kiểm tra chạy song song được trên nhiều lõi.
    success = await run_in_threadpool(check_password, payload.password, user.password_hash if user else None)

    if not success:
        background_tasks.add_task(
            run_detection_pipeline, username=payload.username, user_id=user.id if user else None, success=False, ip=ip, user_agent=user_agent, timestamp=now,
        )
        # Thông báo giống hệt nhau cho "sai mật khẩu" và "tài khoản không tồn tại" để không lộ thông tin tài khoản có
        # tồn tại hay không (docs/api-contract.md mục 3).
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"success": False, "message": "Invalid username or password"})

    # --- MR16 (2): mật khẩu ĐÚNG — CHỜ kết quả chấm điểm (không background) để biết CHÍNH lần thử này có cần OTP/khoá.
    result = await run_detection_pipeline(username=payload.username, user_id=user.id, success=True, ip=ip, user_agent=user_agent, timestamp=now)

    if result.hybrid_action == "lock":
        return _locked_response()

    if result.hybrid_action == "step_up":
        code = generate_otp_code()
        challenge = OtpChallenge(login_event_id=result.login_event_id, user_id=user.id, code_hash=hash_otp_code(code), expires_at=now + OTP_TTL)
        db.add(challenge)
        db.flush()

        pending = (
            db.query(ResponseAction)
            .filter(ResponseAction.login_event_id == result.login_event_id, ResponseAction.action == "step_up")
            .order_by(ResponseAction.id.desc())
            .first()
        )
        if pending is not None:
            pending.status, pending.executed_at = "executed", now
        db.add(AuditLog(actor="system", action="execute_step_up", target_type="login_event", target_id=result.login_event_id, detail={"otp_challenge_id": challenge.id}))
        db.commit()

        if get_settings().is_production:
            logger.info("OTP cho user_id=%s (challenge %s) đã gửi qua kênh mô phỏng: %s", user.id, challenge.id, code)
            return LoginResponse(success=False, message="Cần xác thực thêm — mã đã gửi tới kênh đã đăng ký.", step_up_required=True, challenge_id=challenge.id)
        return LoginResponse(
            success=False,
            message=f"Cần xác thực thêm — mã demo: {code} (hệ thống thật sẽ gửi qua SMS/email, KHÔNG BAO GIỜ hiện trực tiếp như thế này).",
            step_up_required=True, challenge_id=challenge.id, demo_otp_code=code,
        )

    return LoginResponse(success=True, message="Login successful")


@router.post("/login/verify-otp", response_model=LoginResponse)
def verify_otp(payload: OtpVerifyRequest, db: Session = Depends(get_db)):
    challenge = db.get(OtpChallenge, payload.challenge_id)
    now = datetime.now(timezone.utc)
    invalid = LoginResponse(success=False, message=_OTP_INVALID_MESSAGE)

    # Thông báo GIỐNG NHAU cho mọi lý do thất bại (không tồn tại/đã dùng/hết hạn/quá số lần/sai mã) — không lộ chi tiết.
    if challenge is None or challenge.verified_at is not None:
        return invalid

    # MR28: mọi lần gửi thất bại vào một mã CHƯA dùng đều được ghi (audit + bộ đếm của luật `otp_guessing`) — kể cả gửi tiếp vào mã đã hết
    # lượt/hết hạn (không tốn bcrypt cho các lần đó, như trước).
    if challenge.attempts >= OTP_MAX_ATTEMPTS or ensure_utc(challenge.expires_at) < now:
        reason = "exhausted" if challenge.attempts >= OTP_MAX_ATTEMPTS else "expired"
        gate.otp_failed(db, challenge_id=challenge.id, user_id=challenge.user_id, attempts=challenge.attempts, reason=reason, at=now)
        return invalid

    if not otp_code_matches(payload.code, challenge.code_hash):
        challenge.attempts += 1
        gate.otp_failed(db, challenge_id=challenge.id, user_id=challenge.user_id, attempts=challenge.attempts, reason="wrong_code", at=now)
        return invalid

    challenge.verified_at = now
    db.commit()
    return LoginResponse(success=True, message="Login successful")
