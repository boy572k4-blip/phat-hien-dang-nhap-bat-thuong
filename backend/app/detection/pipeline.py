"""Detection engine chạy BẤT ĐỒNG BỘ sau khi API /login đã trả response
(nhiệm vụ 5.2) — GeoIP, luật, ML, baseline, known device/location đều chuyển
vào đây (trước ở routers/auth.py, chặn response).
Alert mới được broadcast qua WebSocket ngay sau khi commit (nhiệm vụ 5.3).
MR16: không còn ĐÚNG TUYỆT ĐỐI cho lần thử MẬT KHẨU ĐÚNG — xem đoạn MR16 bên dưới.

Mở SESSION DB RIÊNG (không dùng session được inject qua Depends(get_db) của
request — session đó đã đóng khi response được trả về, dùng lại sẽ lỗi).

Message của Alert đều được DIỄN GIẢI CỤ THỂ (không chỉ nói "bất thường" hay
1 con số điểm) — nâng cấp sau Tuần 7: admin đọc alert phải hiểu ngay tình
huống là gì mà không cần vào tra log riêng.

MR21 — MỘT bộ luật duy nhất: tầng 1 (ba luật đếm Redis riêng của Tuần 3, mỗi lần khớp một alert riêng) và tầng 2 (bảng
cộng điểm tay +20/+30/+40/+50 của Tuần 4, alert `high_risk_score`) đã bị XOÁ — cùng các dấu hiệu đó giờ là luật của rule
engine v2 (MR9), luật xác định mang "hành động tối thiểu" (`RuleSpec.min_action`) nên vẫn tự cảnh báo được dù trọng số
hiệu chỉnh trên RBA thấp. Điểm rủi ro DUY NHẤT của một lần đăng nhập là điểm hybrid (ghi cả vào `risk_score`). Ánh xạ
từng thành phần cũ: docs/rule-unification.md. Đánh đổi: trước đây khối MR12 hỏng thì alert tầng 1 vẫn còn làm dự phòng;
giờ chỉ còn một đường — các thành phần của nó (ngữ cảnh, rule engine, mô hình) đều không raise với lỗi thường gặp, khối vẫn
được bọc `try/except` riêng để lỗi không làm mất `event` đã ghi hay làm sập luồng đăng nhập.

MR22 — tầng 3 (ML địa lý-thời gian, Tuần 7) không còn tạo alert `ml_anomaly` riêng: biên độ của nó được đổi sang xác suất
(`hybrid.calibration.geo_probability`) thành nguồn bằng chứng `ml_geo`, gộp với `hybrid_cp2` bằng max (hai mô hình dùng
chung tín hiệu thiết bị/vị trí mới) rồi noisy-OR với luật và danh tiếng (`hybrid/combine.py`). Chỉ chấm
tài khoản đã có ít nhất `ml_model.cold_start_min_successes()` lần đăng nhập thành công trước đó (cổng cold-start) — trước
MR22 gần như mọi tài khoản mới đều bị gắn `ml_anomaly` ngay lần đầu. `LoginEvent.ml_anomaly_score` vẫn được ghi cho mọi
lần thử vào tài khoản có thật (kể cả khi bị cổng chặn) để tra cứu.

MR13 (`app/detection/alert_intelligence.py`, THUẦN không đụng DB) làm giàu alert `hybrid_risk` NGAY TRONG khối MR12 ở
trên: novelty so với lịch sử tài khoản, họ tấn công GỢI Ý, ưu tiên hiển thị, và chống trùng lặp — cùng (tài khoản hoặc
IP) + họ tấn công trong 15 phút GỘP vào một hàng `Alert` thay vì tạo hàng mới.

MR14 (mục "MR14" ở cuối hàm, `app/detection/campaign_correlation.py`) gán `Alert.campaign_id` khi NHIỀU TÀI KHOẢN
khác nhau bị nhắm từ CÙNG hạ tầng (IP/ASN) trong 24h.

MR15 (`app/detection/adaptive_threshold.py`) đọc `UserRiskProfile` (nếu tài khoản đã đủ phản hồi "báo nhầm" ròng, cập
nhật ĐỊNH KỲ bởi `backend/scripts/retrain_from_feedback.py`, KHÔNG PHẢI ngay lúc chấm) và NỚI LỎNG riêng `ActionBands`
cho tài khoản đó trước khi gọi `hybrid_runtime`.

MR16 "Phản ứng tự động (mô phỏng)" THỰC THI THẬT đề xuất `step_up`/`lock` (trước đó `ResponseAction.status` luôn
`"recommended"`, không làm gì cả) — mục "MR16" ngay dưới khối tạo `response_action`: `lock` tạo/gia hạn một
`BlocklistEntry` có hạn (TÁI DÙNG `Blocklist`/`blocklist_hit` đã có từ MR9, xem `app/detection/response_execution.py`)
rồi gọi `invalidate_blocklist_cache()` để lần đăng nhập KẾ TIẾP thấy ngay, không đợi hết cache TTL 15s;
`step_up` (tạo `OtpChallenge`) nằm ở `app/routers/auth.py` (cần trả OTP thẳng trong response HTTP, không phải nền).
Hệ quả: `run_detection_pipeline()` giờ TRẢ VỀ một `PipelineResult` (trước đây `None`) để `auth.py` biết hành động vừa
quyết định là gì — và với MỘT lần thử ĐÚNG mật khẩu, `auth.py` phải `await` hàm này TRỰC TIẾP thay vì qua
`BackgroundTasks` như trước (nhiệm vụ 5.2 nguyên bản), đổi lấy độ trễ cao hơn CHO ĐÚNG những lần thử đó (đo được, xem
docs/automated-response.md) — lần thử SAI mật khẩu không đổi, vẫn chạy nền như cũ (không có gì để "chờ" thêm).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal
from app.detection import alert_intelligence, hybrid_runtime, ml_model, perf
from app.detection.adaptive_threshold import apply_delta
from app.detection.baseline import record_known_device_if_new, record_known_location_if_new, update_baseline_after_successful_login
from app.detection.campaign_correlation import LIVE_CAMPAIGN_WINDOW
from app.detection.geoip import lookup_asn, lookup_ip
from app.detection.hybrid import GEO_LABEL
from app.detection.login_context import build_login_context
from app.detection.response_execution import LOCK_TTL, lock_kind_and_value
from app.detection.rule_engine_runtime import build_rule_engine, invalidate_blocklist_cache
from app.models import Alert, AuditLog, BlocklistEntry, Campaign, LoginEvent, ResponseAction, User, UserBaseline, UserRiskProfile
from app.utils.device import compute_device_fingerprint, parse_user_agent
from app.utils.time import ensure_utc
from app.ws_manager import ws_manager
from ml.features import compute_realtime_features

logger = logging.getLogger("pipeline")

# MR12: điểm 0-100 của hybrid risk engine (MR11) -> severity của Alert khi hành động đề xuất không phải "allow".
_HYBRID_SEVERITY = {"alert": "medium", "step_up": "high", "lock": "high"}


@dataclass
class PipelineResult:
    """MR16: NGOÀI `alert_payloads` (đã có từ trước, để broadcast WebSocket), trả thêm hành động hybrid CỦA CHÍNH lần
    thử này — để `app/routers/auth.py` biết có cần chặn/OTP ngay trong response hay không (chỉ khi ĐANG CHỜ kết quả,
    tức gọi đồng bộ — xem docstring `run_detection_pipeline`). Đều là GIÁ TRỊ THUẦN (không phải object ORM còn gắn với
    session) vì được đọc TRƯỚC khi đóng session, giống `alert_payloads`."""

    alert_payloads: list[dict]
    login_event_id: int | None
    hybrid_action: str | None
    hybrid_risk_score: int | None


def _run_detection_pipeline_sync(
    *,
    username: str,
    user_id: int | None,
    success: bool,
    ip: str,
    user_agent: str | None,
    timestamp: datetime,
) -> PipelineResult:
    """Toàn bộ việc (GeoIP, DB, Redis, rule engine, ML) — MỌI THAO TÁC ĐỀU ĐỒNG BỘ (SQLAlchemy dùng driver psycopg2
    đồng bộ, redis-py đồng bộ, LightGBM/scikit-learn CPU-bound), không có `await` nào bên trong. Vì vậy hàm này CỐ Ý
    KHÔNG phải `async def`: `run_detection_pipeline` bên dưới chạy nó trong `asyncio.to_thread` — nếu để `async def` và
    gọi trực tiếp trên vòng lặp sự kiện (như trước MR12), toàn bộ thời gian chạy (đo được p50 ~vài chục ms, p95 có lúc
    tới hàng trăm ms — xem docs/realtime-integration.md) sẽ CHẶN vòng lặp sự kiện DÙNG CHUNG cho mọi kết nối khác; đo tải
    (nhiều request /login đồng thời) trước khi sửa cho thấy timeout thật sự, không phải giả thuyết suông."""
    db = SessionLocal()
    alert_payloads: list[dict] = []
    pipeline_started = time.perf_counter()

    try:
        user = db.get(User, user_id) if user_id else None
        geo = lookup_ip(ip)
        device_fingerprint = compute_device_fingerprint(user_agent)
        # MR12: parse UA + tra ASN — không chặn /login (toàn hàm này đã chạy nền), lỗi/thiếu dữ liệu trả None chứ không raise.
        parsed_ua = parse_user_agent(user_agent)
        asn_result = lookup_asn(ip)

        event = LoginEvent(
            user_id=user_id,
            attempted_username=username,
            success=success,
            ip_address=ip,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            country=geo.country if geo else None,
            city=geo.city if geo else None,
            latitude=geo.latitude if geo else None,
            longitude=geo.longitude if geo else None,
            asn=asn_result.asn if asn_result else None,
            os_name=parsed_ua.os,
            browser_name=parsed_ua.browser,
            device_type=parsed_ua.device_type,
            is_synthetic=False,
            created_at=timestamp,
        )
        db.add(event)
        db.flush()

        # (Alert, extra field cho payload WebSocket)
        alert_records: list[tuple[Alert, dict]] = []

        # --- Tầng 3: ML địa lý-thời gian (Tuần 7). Tính đặc trưng TRƯỚC khi record_known_*_if_new() bên dưới cập nhật
        # thiết bị/vị trí quen, cho đúng ý nghĩa "chưa từng thấy" (giống lúc train offline). Từ MR22 kết quả chỉ là một
        # nguồn bằng chứng (`ml_geo`) của khối hybrid bên dưới, không tạo alert riêng.
        ml_features = ml_result = None
        if user is not None:
            baseline = db.query(UserBaseline).filter(UserBaseline.user_id == user.id).first()
            ml_features = compute_realtime_features(
                db,
                user_id=user.id,
                baseline=baseline,
                country=event.country,
                city=event.city,
                latitude=event.latitude,
                longitude=event.longitude,
                device_fingerprint=device_fingerprint,
                created_at=event.created_at,
            )
            ml_result = ml_model.predict(ml_features)
            if ml_result is not None:
                event.ml_anomaly_score = ml_result["anomaly_score"]

            if success:
                update_baseline_after_successful_login(db, user, event)
                record_known_device_if_new(db, user, device_fingerprint, user_agent)
                record_known_location_if_new(db, user, event.country, event.city)

        # --- Bộ luật duy nhất (rule engine v2, MR9-10 + hành động tối thiểu MR21) + hybrid risk engine (MR11). Cô lập
        # trong try/except RIÊNG: lỗi ở đây không được làm hỏng `event` đã ghi hay làm sập luồng đăng nhập.
        try:
            with perf.timer("hybrid"):
                # MR20: lịch sử tài khoản (dạng tổng hợp), IP/ASN 24h và đếm toàn cục dựng MỘT lần ở đây, dùng chung cho
                # rule engine, đặc trưng RBA và novelty bên dưới (app/detection/login_context.py).
                with perf.timer("login_context"):
                    context = build_login_context(db, event, username=username)
                with perf.timer("rule_engine"):
                    evaluation = build_rule_engine(db, before=event.created_at, context=context).evaluate(context.attempt)
                with perf.timer("rba_features"):
                    features = context.rba_features()
                # MR15: ngưỡng THÍCH NGHI riêng cho tài khoản này nếu đã đủ phản hồi (adaptive_threshold.apply_delta),
                # NHÓM (mặc định) nếu chưa có hàng UserRiskProfile hay user_id là None (tên đăng nhập không tồn tại).
                user_bands = None
                if user_id is not None:
                    risk_profile = db.get(UserRiskProfile, user_id)
                    if risk_profile is not None and risk_profile.threshold_delta > 0:
                        user_bands = apply_delta(hybrid_runtime.get_engine().profile.bands, risk_profile.threshold_delta)
                hybrid_engine = hybrid_runtime.get_engine()
                with perf.timer("ml_inference"):
                    ml_assessment = hybrid_engine.ml_assessment(features)  # MỘT lần chạy mô hình cho cả điểm lẫn thành phần dẫn đầu (MR20)
                # MR22: mô hình địa lý-thời gian (tầng 3) là nguồn bằng chứng thứ hai `ml_geo` — CHỈ chấm tài khoản đã có đủ
                # lần đăng nhập thành công trước đó (cổng cold-start: lần đầu của MỌI tài khoản đều "vị trí mới + thiết bị
                # mới" theo định nghĩa, mô hình gắn cờ 100% — đo ở ml/train.py). Số lần đếm từ chính lịch sử của ngữ cảnh.
                prior_successes = context.account.n_success if context.account is not None else 0
                ml_geo = ml_geo_label = None
                if ml_result is not None and prior_successes >= ml_model.cold_start_min_successes():
                    ml_geo = hybrid_engine.ml_geo_probability(ml_result.get("margin"), ml_model.geo_slope())
                    if ml_geo is not None:  # giữ phần diễn giải mà alert `ml_anomaly` cũ từng có: đặc trưng nào lệch nhiều nhất
                        detail = ml_model.explain(ml_features)
                        ml_geo_label = f"{GEO_LABEL}: {detail}" if detail else None
                risk_result = hybrid_engine.evaluate(
                    features, evaluation.hits, bands=user_bands, ml=ml_assessment, ml_geo=ml_geo, ml_geo_label=ml_geo_label
                )
                event.hybrid_risk_score = risk_result.score
                event.hybrid_action = risk_result.action
                # MR21: điểm rủi ro DUY NHẤT của lần đăng nhập — cột `risk_score` (trước là điểm cộng tay của tầng 2, đã
                # xoá) giữ cho bảng log/biểu đồ hiện có tiếp tục hiển thị; MR23 gộp hẳn hai cột.
                event.risk_score = risk_result.score
                # Bằng chứng toạ độ của luật di chuyển bất khả thi -> payload WebSocket để bản đồ vẽ đường nối hai điểm
                # (trước MR21 do alert `impossible_travel` riêng của tầng 1 mang).
                travel = next((h for h in evaluation.hits if h.rule_id == "impossible_travel"), None)
                travel_extra = (
                    {"previous_latitude": travel.evidence.get("previous_latitude"), "previous_longitude": travel.evidence.get("previous_longitude")}
                    if travel is not None else {}
                )

                if risk_result.action != "allow":
                    # --- MR13: gán họ tấn công gợi ý, novelty, ưu tiên (app/detection/alert_intelligence.py — thuần, không đụng DB) ---
                    family, confidence = alert_intelligence.suggest_attack_family(risk_result, ml_component=ml_assessment.component)
                    novelty_facts = alert_intelligence.compute_novelty(context.record, context.summary)
                    importance = user.importance if user is not None else 1.0
                    priority = alert_intelligence.priority_score(novelty_facts, confidence, importance)
                    top_rule = next((c.source for c in risk_result.contributions if c.group != "ml"), None)  # bỏ qua cả hai mô hình (ml, ml_geo)

                    # --- MR13: chống trùng lặp — cùng (tài khoản, hoặc IP nếu tài khoản không tồn tại) + họ tấn công,
                    # trong DEDUP_WINDOW gần nhất và còn "open" thì GỘP vào alert đó thay vì tạo hàng mới.
                    # ⚠️ Lọc theo THỜI ĐIỂM ĐĂNG NHẬP (LoginEvent.created_at, JOIN), KHÔNG PHẢI lúc hàng Alert được ghi
                    # (Alert.created_at, server_default=func.now()) — bug thật cùng lớp đã sửa ở MR14 (app/detection/
                    # campaign_correlation.py): hai mốc trùng nhau khi chấm gần thời gian thực, nhưng lệch hẳn khi nạp
                    # lại/mô phỏng nhiều "ngày" trong thời gian chạy thật ngắn (lộ ra qua MR15's feedback_loop_sim.py,
                    # vốn cố tình cách các vòng 1 NGÀY GIẢ trong khi cả script chạy thật chỉ mất vài giây — dedup theo
                    # Alert.created_at sẽ coi MỌI vòng trước đó là "trong cửa sổ 15 phút" vì đều được GHI gần như cùng
                    # một thời điểm THẬT, dù các vòng cách nhau cả ngày về mặt "thời điểm đăng nhập"). ---
                    existing_alert = None
                    if family is not None:
                        dedup_query = (
                            db.query(Alert)
                            .join(LoginEvent, Alert.login_event_id == LoginEvent.id)
                            .filter(Alert.attack_family == family, Alert.status == "open", LoginEvent.created_at >= event.created_at - alert_intelligence.DEDUP_WINDOW)
                        )
                        if user_id is not None:
                            dedup_query = dedup_query.filter(Alert.user_id == user_id)
                        else:
                            dedup_query = dedup_query.filter(Alert.user_id.is_(None), LoginEvent.ip_address == ip)
                        existing_alert = dedup_query.order_by(Alert.created_at.desc()).first()

                    # "action" đã lưu ở lần trước là mức TỆ NHẤT của cả đợt tính đến lúc đó (xem combined_action bên dưới) — không phải riêng lần đó.
                    previous_action = (existing_alert.explanation or {}).get("action", "alert") if existing_alert is not None else "allow"
                    escalated = existing_alert is not None and alert_intelligence.action_escalated(previous_action, risk_result.action)
                    combined_action = risk_result.action if existing_alert is None or escalated else previous_action
                    occurrence_count = (existing_alert.occurrence_count + 1) if existing_alert is not None else 1
                    message = alert_intelligence.build_alert_message(
                        risk_result, novelty_facts=novelty_facts, family=family, confidence=confidence, occurrence_count=occurrence_count
                    )
                    explanation = {
                        "contributions": [{"source": c.source, "label": c.label, "weight": round(c.weight, 4), "group": c.group} for c in risk_result.contributions],
                        "action": combined_action,  # mức TỆ NHẤT tính đến lần này (không phải riêng risk_result.action) — dùng lại ở lần dedup SAU
                        "forced_by": risk_result.overridden_by,  # MR21: luật đã ép hành động tối thiểu (None nếu hành động đến từ điểm)
                    }

                    if existing_alert is not None:
                        hybrid_alert = existing_alert
                        hybrid_alert.risk_score = max(hybrid_alert.risk_score, risk_result.score)
                        hybrid_alert.severity = _HYBRID_SEVERITY[combined_action]
                        hybrid_alert.message = message
                        hybrid_alert.explanation = explanation
                        hybrid_alert.rule_id = risk_result.overridden_by or top_rule or hybrid_alert.rule_id
                        hybrid_alert.attack_family_confidence = confidence
                        hybrid_alert.occurrence_count = occurrence_count
                        hybrid_alert.last_seen_at = event.created_at
                        hybrid_alert.priority_score = max(hybrid_alert.priority_score or 0.0, priority)
                    else:
                        hybrid_alert = Alert(
                            login_event_id=event.id, user_id=user_id, alert_type="hybrid_risk",
                            severity=_HYBRID_SEVERITY[risk_result.action], risk_score=risk_result.score, message=message,
                            rule_id=risk_result.overridden_by or top_rule, explanation=explanation, attack_family=family,
                            attack_family_confidence=confidence, occurrence_count=1, last_seen_at=event.created_at, priority_score=priority,
                        )
                        db.add(hybrid_alert)
                    db.flush()
                    alert_records.append((hybrid_alert, travel_extra))

                    # Không lặp lại ĐÚNG đề xuất cũ mỗi lần trùng — chỉ ghi thêm khi MỚI hoặc mức đề xuất đã TĂNG (vd alert -> lock).
                    if risk_result.action in ("step_up", "lock") and (existing_alert is None or escalated):
                        reasons = "; ".join(f"{c.label} ({c.weight:.0%})" for c in risk_result.contributions[:3])
                        if risk_result.overridden_by is not None:  # MR21: nói rõ hành động đến từ luật xác định, không phải từ điểm
                            reasons = f"luật {risk_result.overridden_by} ép mức tối thiểu '{risk_result.action}'; {reasons}"
                        response_action = ResponseAction(
                            login_event_id=event.id, alert_id=hybrid_alert.id, user_id=user_id, action=risk_result.action,
                            reason=f"Hybrid risk engine đề xuất (điểm {risk_result.score}/100): {reasons}.",
                        )
                        db.add(response_action)
                        db.flush()
                        audit_action = f"recommend_{risk_result.action}"
                        audit_detail = {"response_action_id": response_action.id, "alert_id": hybrid_alert.id, "score": risk_result.score}

                        # --- MR16: THỰC THI THẬT hành động "lock" ngay tại đây (đủ ngữ cảnh, không cần chờ HTTP — khác
                        # "step_up" cần trả OTP thẳng trong response nên được app/routers/auth.py tự thực thi). Khoá áp
                        # dụng cho MỌI lần thử tiếp theo dẫn đến "lock" — kể cả lần thử THẤT BẠI (chạy nền, không HTTP
                        # nào đang chờ) — không chỉ lần thành công đã qua auth.py.
                        if risk_result.action == "lock":
                            kind, value = lock_kind_and_value(user_id=user_id, username=username, ip=ip)
                            new_expiry = event.created_at + LOCK_TTL
                            # "lock" có thể đến từ blocklist_hit (mục NÀY đã có sẵn trong bảng — chính là lý do khớp
                            # luật) — UniqueConstraint(kind, value) sẽ raise nếu cứ thêm mục mới trùng; tái dùng mục cũ,
                            # chỉ GIA HẠN nếu lock hiện tại đi xa hơn (không bao giờ RÚT NGẮN một mục đang dài hơn/vĩnh viễn).
                            block_entry = db.query(BlocklistEntry).filter(BlocklistEntry.kind == kind, BlocklistEntry.value == value).first()
                            if block_entry is None:
                                # MR20: một lần thử ĐỒNG THỜI khác cũng có thể vừa quyết định khoá đúng mục này và chèn
                                # trước — chèn trong SAVEPOINT, trùng thì dùng mục của lần thử kia (cùng lớp lỗi đã gặp thật
                                # ở baseline tầng 2, xem update_baseline_after_successful_login).
                                try:
                                    with db.begin_nested():
                                        block_entry = BlocklistEntry(kind=kind, value=value, reason=f"Tự động khoá (MR16) — {reasons}.", added_by="system", expires_at=new_expiry)
                                        db.add(block_entry)
                                except IntegrityError:
                                    block_entry = db.query(BlocklistEntry).filter(BlocklistEntry.kind == kind, BlocklistEntry.value == value).one()
                                invalidate_blocklist_cache()  # để lần thử NGAY SAU (có thể trong vài mili-giây) đã thấy mục khoá mới, không đợi hết TTL cache 15s
                            # ensure_utc: SQLite (test/mô phỏng) đọc lại `expires_at` không kèm múi giờ — so với mốc có múi giờ
                            # thì TypeError và cả khối hybrid bị bỏ (lộ ra ở MR22 khi kịch bản mô phỏng lần đầu đi tới đây).
                            elif block_entry.expires_at is not None and ensure_utc(block_entry.expires_at) < ensure_utc(new_expiry):
                                block_entry.expires_at = new_expiry
                                invalidate_blocklist_cache()
                            response_action.status = "executed"
                            response_action.executed_at = event.created_at
                            audit_action = "execute_lock"
                            audit_detail["blocklist_entry_id"] = block_entry.id
                            audit_detail["blocklist_kind"] = kind
                            audit_detail["blocklist_value"] = value

                        db.add(AuditLog(actor="system", action=audit_action, target_type="login_event", target_id=event.id, detail=audit_detail))
        except Exception:  # noqa: BLE001 — không bao giờ được làm hỏng `event` đã ghi hay làm sập luồng đăng nhập
            logger.exception("lỗi ở khối luật/hybrid cho user_id=%s ip=%s — bỏ qua, lần đăng nhập vẫn được ghi", user_id, ip)

        # --- MR14: tương quan chiến dịch — gom alert `hybrid_risk` (nguồn cảnh báo duy nhất từ MR22) CÙNG hạ tầng (IP hoặc
        # ASN) NHẮM VÀO NHIỀU TÀI KHOẢN KHÁC NHAU trong LIVE_CAMPAIGN_WINDOW thành một Campaign. Khác chống trùng lặp
        # của MR13 (chỉ gộp CÙNG một tài khoản/IP lặp lại) — ở đây là NHIỀU tài khoản chia sẻ hạ tầng. Cô lập riêng:
        # lỗi ở đây không được làm mất các alert đã tạo/commit ở trên (app/detection/campaign_correlation.py).
        try:
            if alert_records and (event.ip_address is not None or event.asn is not None):
                # ⚠️ Lọc theo THỜI ĐIỂM ĐĂNG NHẬP (LoginEvent.created_at), KHÔNG PHẢI lúc hàng Alert được ghi
                # (Alert.created_at, server_default=func.now()) — hai mốc này trùng nhau trong vận hành bình thường
                # (chấm gần như ngay khi xảy ra) nhưng KHÔNG PHẢI luôn vậy (nạp lại/backfill); test MR14 tự tạo timestamp
                # giả cũng lộ ra sai khác này ngay. So sánh chuẩn hoá múi giờ bằng ensure_utc() (đọc lại từ SQLite mất
                # tzinfo — cùng lớp lỗi đã sửa ở MR9/MR12/MR13).
                now = ensure_utc(event.created_at)
                window_start = now - LIVE_CAMPAIGN_WINDOW
                # MR20: lọc hạ tầng + cửa sổ thời gian NGAY TRONG SQL (dùng chỉ mục ip_address/asn của login_events).
                # Trước đó nạp TOÀN BỘ bảng alerts vào Python rồi mới lọc — đo trên Postgres dev (3.500 alert): ~140 ms
                # mỗi lần đăng nhập có cảnh báo, và tăng tuyến tính theo số alert tích luỹ. Bộ lọc Python bên dưới giữ
                # NGUYÊN điều kiện cũ trên tập kết quả nhỏ, nên ngữ nghĩa không đổi.
                same_infra = []
                if event.ip_address is not None:
                    same_infra.append(LoginEvent.ip_address == event.ip_address)
                if event.asn is not None:
                    same_infra.append(LoginEvent.asn == event.asn)
                candidates = (
                    db.query(Alert, LoginEvent)
                    .join(LoginEvent, Alert.login_event_id == LoginEvent.id)
                    .filter(Alert.login_event_id != event.id, or_(*same_infra), LoginEvent.created_at >= window_start, LoginEvent.created_at <= now)
                )
                if user_id is not None:
                    candidates = candidates.filter(or_(LoginEvent.user_id.is_(None), LoginEvent.user_id != user_id))
                matches = [
                    (a, ensure_utc(le.created_at))
                    for a, le in candidates
                    if window_start <= ensure_utc(le.created_at) <= now
                    and ((event.ip_address is not None and le.ip_address == event.ip_address) or (event.asn is not None and le.asn == event.asn))
                    and not (le.user_id is not None and le.user_id == user_id)  # loại chính tài khoản này lặp lại — đó là việc của MR13, không phải "nhiều tài khoản"
                ]
                existing_campaign_id = next((a.campaign_id for a, _ in matches if a.campaign_id is not None), None)
                campaign = db.get(Campaign, existing_campaign_id) if existing_campaign_id is not None else None
                if campaign is None and matches:
                    shared = f"ASN {event.asn}" if event.asn is not None else f"IP {event.ip_address}"
                    earliest = min((ts for _, ts in matches), default=now)
                    campaign = Campaign(label=f"Chiến dịch qua {shared}", first_seen_at=earliest, last_seen_at=now)
                    db.add(campaign)
                    db.flush()

                if campaign is not None:
                    for alert_obj in (*(a for a, _ in matches), *(a for a, _ in alert_records)):
                        if alert_obj.campaign_id is None:
                            alert_obj.campaign_id = campaign.id
                            campaign.alert_count += 1
                        if campaign.attack_family is None and alert_obj.attack_family is not None:
                            campaign.attack_family = alert_obj.attack_family
                    if now > ensure_utc(campaign.last_seen_at):
                        campaign.last_seen_at = now
                    if now < ensure_utc(campaign.first_seen_at):
                        campaign.first_seen_at = now
                    db.flush()
        except Exception:  # noqa: BLE001 — MR14 không bao giờ được làm mất alert đã tạo ở tầng 1-3/MR12-13
            logger.exception("lỗi ở khối MR14 (tương quan chiến dịch) cho user_id=%s ip=%s — bỏ qua, các alert khác không bị ảnh hưởng", user_id, ip)

        db.commit()
        perf.record("pipeline", (time.perf_counter() - pipeline_started) * 1000)

        # Đọc dữ liệu để broadcast TRƯỚC khi đóng session (object hết hạn sau khi đóng).
        for alert_obj, extra in alert_records:
            alert_payloads.append(
                {
                    "id": alert_obj.id,
                    "login_event_id": alert_obj.login_event_id,
                    "user_id": alert_obj.user_id,
                    "username": username,
                    "alert_type": alert_obj.alert_type,
                    "severity": alert_obj.severity,
                    "risk_score": alert_obj.risk_score,
                    "message": alert_obj.message,
                    "latitude": event.latitude,
                    "longitude": event.longitude,
                    "rule_id": alert_obj.rule_id,
                    "attack_family": alert_obj.attack_family,  # MR13 — gợi ý, xem alert_obj.attack_family_confidence
                    "priority_score": alert_obj.priority_score,
                    "occurrence_count": alert_obj.occurrence_count,
                    "campaign_id": alert_obj.campaign_id,  # MR14 — None nếu chưa thuộc chiến dịch nào
                    "created_at": alert_obj.created_at.isoformat() if alert_obj.created_at else timestamp.isoformat(),
                    **extra,
                }
            )

        # MR16: đọc TRƯỚC khi đóng session, giống alert_payloads ở trên — event.hybrid_risk_score/hybrid_action chỉ có
        # giá trị nếu khối MR12-15 chạy trót lọt (None nếu lỗi/bị bỏ qua, app/routers/auth.py tự xử lý None an toàn).
        login_event_id = event.id
        hybrid_action = event.hybrid_action
        hybrid_risk_score = event.hybrid_risk_score
    finally:
        db.close()

    return PipelineResult(alert_payloads=alert_payloads, login_event_id=login_event_id, hybrid_action=hybrid_action, hybrid_risk_score=hybrid_risk_score)


async def run_detection_pipeline(
    *,
    username: str,
    user_id: int | None,
    success: bool,
    ip: str,
    user_agent: str | None,
    timestamp: datetime,
) -> PipelineResult:
    """Wrapper mỏng: chạy toàn bộ việc ĐỒNG BỘ ở trên trong một thread riêng (`asyncio.to_thread`) rồi mới broadcast
    WebSocket (thao tác `await` DUY NHẤT thật sự cần vòng lặp sự kiện — xem `WebSocketManager.broadcast_json`). Nhiều
    lần đăng nhập đến CÙNG LÚC giờ chạy `_run_detection_pipeline_sync` song song ở các thread khác nhau thay vì nối đuôi
    nhau trên một vòng lặp sự kiện duy nhất.

    MR16: trả về `PipelineResult` (trước đây `None`) để `app/routers/auth.py` BIẾT được `hybrid_action` khi GỌI ĐỒNG BỘ
    (chờ `await` xong rồi mới trả response — chỉ cho lần thử ĐÚNG mật khẩu, xem docstring router); khi gọi qua
    `BackgroundTasks` (lần thử SAI mật khẩu, không đổi từ trước giờ) giá trị trả về đơn giản bị bỏ qua, không ảnh hưởng gì."""
    result = await asyncio.to_thread(
        _run_detection_pipeline_sync, username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=timestamp,
    )
    for payload in result.alert_payloads:
        await ws_manager.broadcast_json({"type": "alert", "data": payload})
    return result
