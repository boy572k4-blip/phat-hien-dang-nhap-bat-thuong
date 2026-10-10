"""Detection pipeline — chấm MỘT lần thử đăng nhập sau khi `/login` đã kiểm mật khẩu (nhiệm vụ 5.2). Mở SESSION DB
RIÊNG (session của request đã đóng khi response được trả về, dùng lại sẽ lỗi); cảnh báo mới được broadcast qua WebSocket
ngay sau khi commit (nhiệm vụ 5.3).

MR23 — năm bước, mỗi bước một hàm:
  1. Ghi lần thử và dựng ngữ cảnh (`_record_attempt`, `build_login_context` — lịch sử tài khoản/IP/ASN dùng chung, MR20).
  2. Luật (rule engine v2, MR9; luật xác định mang hành động tối thiểu, MR21).
  3. Mô hình (`_score_models`): `hybrid_cp2` (MR12) và mô hình địa lý-thời gian — nguồn `ml_geo`, chỉ chấm tài khoản đã
     qua cổng cold-start (MR22).
  4. Gộp điểm (`_combine`): MỘT điểm 0-100 và MỘT hành động cho lần thử (app/detection/hybrid), theo ngưỡng riêng của
     tài khoản nếu có (MR15); ghi vào `login_events.hybrid_risk_score/hybrid_action` — cột điểm DUY NHẤT từ MR23.
  5. Hành động: MỘT sự cố = MỘT cảnh báo (`_raise_incident`, `alert_intelligence.Incident`), phản ứng tự động step_up/lock
     (`_respond`, MR16), gom chiến dịch nhiều tài khoản cùng hạ tầng (`_correlate_campaign`, MR14).
Sau cùng, lần đăng nhập THÀNH CÔNG cập nhật hồ sơ tài khoản (baseline giờ, thiết bị/vị trí quen) — SAU khi chấm, vì đặc
trưng của mô hình địa lý-thời gian phải thấy hồ sơ TRƯỚC lần này (ml/features.py); không bộ phận nào khác đọc các bảng đó.

Cô lập lỗi bằng SAVEPOINT (MR23, nợ từ MR20): trên Postgres một lệnh SQL lỗi làm hỏng CẢ giao dịch — try/except quanh
từng khối không đủ, lần commit cuối vẫn lỗi và mất luôn lần thử đã ghi. Mỗi khối giờ chạy trong `db.begin_nested()`
(`_isolated`): lỗi chỉ huỷ phần việc của khối đó, phần còn lại vẫn được ghi. Chỉ còn MỘT đường chấm điểm (MR21): khối chấm
hỏng thì lần thử vẫn được ghi nhưng không có điểm/cảnh báo.

MR16: với lần thử ĐÚNG mật khẩu, `app/routers/auth.py` CHỜ hàm này (không qua `BackgroundTasks`) để biết có cần OTP/khoá
ngay trong response — `run_detection_pipeline` trả `PipelineResult`. Lần thử SAI vẫn chạy nền như cũ. Đo độ trễ:
docs/automated-response.md, docs/performance.md.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.detection import alert_intelligence, hybrid_runtime, ml_model, perf
from app.detection.adaptive_threshold import apply_delta
from app.detection.alert_intelligence import DEDUP_WINDOW, Incident
from app.detection.baseline import record_known_device_if_new, record_known_location_if_new, update_baseline_after_successful_login
from app.detection.campaign_correlation import LIVE_CAMPAIGN_WINDOW
from app.detection.engine.types import Evaluation
from app.detection.geoip import lookup_asn, lookup_ip
from app.detection.hybrid import GEO_LABEL, RiskResult
from app.detection.hybrid_runtime import MlAssessment
from app.detection.login_context import LoginContext, build_login_context
from app.detection.response_execution import LOCK_TTL, lock_kind_and_value
from app.detection.rule_engine_runtime import build_rule_engine, invalidate_blocklist_cache
from app.models import Alert, AuditLog, BlocklistEntry, Campaign, LoginEvent, ResponseAction, User, UserBaseline, UserRiskProfile
from app.utils.device import compute_device_fingerprint, parse_user_agent
from app.utils.time import ensure_utc
from app.ws_manager import ws_manager
from ml.features import compute_realtime_features

logger = logging.getLogger("pipeline")

# Hành động nặng nhất của sự cố -> severity của cảnh báo.
_SEVERITY = {"alert": "medium", "step_up": "high", "lock": "high"}
# MR27: lần thử trong vòng chừng này sau một lần THÀNH CÔNG cùng IP + cùng thiết bị là cùng một phiên làm việc — mô hình địa lý-thời gian
# không chấm lại (đặt trước khi đo; xem `_continues_last_session`).
GEO_SAME_SESSION = timedelta(minutes=30)


@dataclass
class PipelineResult:
    """MR16: ngoài `alert_payloads` (để broadcast WebSocket), trả hành động của CHÍNH lần thử này — để `auth.py` biết có
    cần chặn/OTP ngay trong response. Đều là GIÁ TRỊ THUẦN, đọc TRƯỚC khi đóng session."""

    alert_payloads: list[dict]
    login_event_id: int | None
    hybrid_action: str | None
    hybrid_risk_score: int | None


@dataclass(frozen=True)
class _Models:
    """Bước 3 — bằng chứng của hai mô hình cho một lần thử."""

    assessment: MlAssessment  # hybrid_cp2: xác suất + thành phần dẫn đầu (MR13 dùng gợi ý họ tấn công)
    geo: float | None  # ml_geo; None khi không chấm (tên đăng nhập không tồn tại, dưới cổng cold-start, chưa có mô hình)
    geo_label: str | None  # nhãn kèm các đặc trưng lệch nhiều nhất (`ml_model.explain`)


@dataclass
class _Block:
    committed: bool = False  # True khi SAVEPOINT của khối đã được giữ lại (không lỗi, kể cả lúc ghi xuống DB)


@contextmanager
def _isolated(db: Session, block: str, **where) -> Iterator[_Block]:
    """Một SAVEPOINT cho một khối: lỗi bên trong chỉ huỷ phần việc của khối, được ghi log, rồi pipeline đi tiếp. Nơi gọi
    đọc `committed` trước khi dùng object tạo trong khối — khối lỗi thì các object đó đã bị huỷ cùng SAVEPOINT."""
    outcome = _Block()
    try:
        with db.begin_nested():
            yield outcome
        outcome.committed = True
    except Exception:  # noqa: BLE001 — không khối nào được làm mất lần thử đã ghi hay làm sập luồng đăng nhập
        logger.exception("lỗi ở khối %s %s — bỏ qua khối này, lần thử vẫn được ghi", block, where)


# ------------------------------------------------------------------------------------------ bước 1: ghi lần thử


def _record_attempt(db: Session, *, username: str, user_id: int | None, success: bool, ip: str, user_agent: str | None, timestamp: datetime) -> LoginEvent:
    """Ghi lần thử kèm GeoIP, ASN, User-Agent đã phân tích (MR12) — thiếu dữ liệu thì để None, không raise."""
    geo = lookup_ip(ip)
    asn = lookup_asn(ip)
    parsed_ua = parse_user_agent(user_agent)
    event = LoginEvent(
        user_id=user_id, attempted_username=username, success=success, ip_address=ip, user_agent=user_agent,
        device_fingerprint=compute_device_fingerprint(user_agent),
        country=geo.country if geo else None, city=geo.city if geo else None,
        latitude=geo.latitude if geo else None, longitude=geo.longitude if geo else None,
        asn=asn.asn if asn else None, os_name=parsed_ua.os, browser_name=parsed_ua.browser, device_type=parsed_ua.device_type,
        is_synthetic=False, created_at=timestamp,
    )
    db.add(event)
    db.flush()
    return event


# ------------------------------------------------------------------------------------------ bước 3: mô hình


def _continues_last_session(db: Session, event: LoginEvent) -> bool:
    """MR27 — lần thử này có nối tiếp lần THÀNH CÔNG gần nhất của tài khoản (trong `GEO_SAME_SESSION`, CÙNG IP và CÙNG thiết bị) không.
    Nếu có, nó không mang thông tin vị trí/thiết bị/giờ nào mới — ngữ cảnh đó vừa được chấm ở lần trước. Lý do cần: sau khi MR23 sửa lệch
    đặc trưng `minutes_since_last_login`, mô hình (học trên dữ liệu chỉ có khoảng cách ngắn ở nhãn bất thường `rapid_fire`) báo động
    53% lần chính chủ đăng nhập lại vài lần liền (họ `relogin` của bộ MR24, đo ở MR27). Đăng nhập dồn dập thật do luật `success_burst` lo."""
    if event.user_id is None:
        return False
    at = event.created_at
    last = (
        db.query(LoginEvent.ip_address, LoginEvent.device_fingerprint)
        .filter(LoginEvent.user_id == event.user_id, LoginEvent.success.is_(True), LoginEvent.id != event.id,
                LoginEvent.created_at <= at, LoginEvent.created_at >= at - GEO_SAME_SESSION)
        .order_by(LoginEvent.created_at.desc(), LoginEvent.id.desc())
        .first()
    )
    return last is not None and last.ip_address == event.ip_address and last.device_fingerprint == event.device_fingerprint


def _score_models(db: Session, *, event: LoginEvent, user: User | None, context: LoginContext, features: dict | None) -> _Models:
    engine = hybrid_runtime.get_engine()
    with perf.timer("ml_inference"):
        assessment = engine.ml_assessment(features)  # MỘT lần chạy cho cả xác suất lẫn thành phần dẫn đầu (MR20)

    # Mô hình địa lý-thời gian (MR22): chỉ chấm tài khoản đã có đủ lần thành công TRƯỚC lần này — lần đầu của MỌI tài
    # khoản đều là "thiết bị mới + vị trí mới" theo định nghĩa (đo ở ml/train.py). Đếm từ chính lịch sử của ngữ cảnh.
    # MR27: không chấm lại lần thử nối tiếp phiên vừa thành công (cùng IP + thiết bị, `_continues_last_session`).
    geo = geo_label = None
    prior_successes = context.account.n_success if context.account is not None else 0
    if user is not None and prior_successes >= ml_model.cold_start_min_successes() and not _continues_last_session(db, event):
        with perf.timer("geo_model"):
            baseline = db.query(UserBaseline).filter(UserBaseline.user_id == user.id).first()
            geo_features = compute_realtime_features(
                db, user_id=user.id, baseline=baseline, country=event.country, city=event.city, latitude=event.latitude,
                longitude=event.longitude, device_fingerprint=event.device_fingerprint, created_at=event.created_at,
            )
            prediction = ml_model.predict(geo_features)
            if prediction is not None:
                geo = engine.ml_geo_probability(prediction.get("margin"), ml_model.geo_slope())
                if geo is not None:  # đặc trưng nào lệch nhiều nhất — phần diễn giải mà alert `ml_anomaly` cũ từng có
                    detail = ml_model.explain(geo_features)
                    geo_label = f"{GEO_LABEL}: {detail}" if detail else None
    return _Models(assessment=assessment, geo=geo, geo_label=geo_label)


# ------------------------------------------------------------------------------------------ bước 4: gộp điểm


def _combine(db: Session, *, event: LoginEvent, user_id: int | None, evaluation: Evaluation, models: _Models, features: dict | None) -> RiskResult:
    engine = hybrid_runtime.get_engine()
    # MR15: ngưỡng đã NỚI riêng cho tài khoản này nếu đã đủ phản hồi "báo nhầm" ròng; không có thì dùng ngưỡng nhóm.
    bands = None
    if user_id is not None:
        risk_profile = db.get(UserRiskProfile, user_id)
        if risk_profile is not None and risk_profile.threshold_delta > 0:
            bands = apply_delta(engine.profile.bands, risk_profile.threshold_delta)
    risk = engine.evaluate(
        features, evaluation.hits, bands=bands, ml=models.assessment, ml_geo=models.geo, ml_geo_label=models.geo_label
    )
    event.hybrid_risk_score = risk.score
    event.hybrid_action = risk.action
    return risk


# ------------------------------------------------------------------------------------------ bước 5: hành động


def _open_incident(db: Session, *, user_id: int | None, ip: str, at: datetime) -> Alert | None:
    """Sự cố đang mở mà lần thử này thuộc về: cùng tài khoản (hoặc cùng IP nếu tên đăng nhập không tồn tại), chưa được
    xử lý, lần GẦN NHẤT cách lần này không quá `DEDUP_WINDOW` (cửa sổ trượt). So theo THỜI ĐIỂM ĐĂNG NHẬP (`last_seen_at`
    lấy từ `LoginEvent.created_at`), không theo lúc hàng Alert được ghi — bug cùng lớp đã sửa ở MR13/MR14: hai mốc lệch
    hẳn khi nạp lại hoặc mô phỏng nhiều "ngày" trong vài giây chạy thật.

    Chặn CẢ hai phía: lần thử đến trễ (đồng thời, nạp lại sự kiện cũ) không được gộp vào một sự cố xảy ra sau nó rất lâu —
    thiếu chặn trên, một lần thử ghi lùi ngày 02/03 đã gộp vào cảnh báo của tháng 9 (tìm ra khi viết test MR23)."""
    query = db.query(Alert).filter(Alert.status == "open", Alert.last_seen_at >= at - DEDUP_WINDOW, Alert.last_seen_at <= at + DEDUP_WINDOW)
    if user_id is not None:
        query = query.filter(Alert.user_id == user_id)
    else:
        query = query.join(LoginEvent, Alert.login_event_id == LoginEvent.id).filter(Alert.user_id.is_(None), LoginEvent.ip_address == ip)
    return query.order_by(Alert.last_seen_at.desc(), Alert.id.desc()).first()


def _raise_incident(
    db: Session, *, event: LoginEvent, user: User | None, ip: str, risk: RiskResult, evaluation: Evaluation, models: _Models, context: LoginContext
) -> tuple[Alert, Incident, bool]:
    """Tạo cảnh báo cho sự cố mới, hoặc gộp lần thử vào sự cố đang mở. Trả (cảnh báo, sự cố, hành động có TĂNG không)."""
    family, confidence = alert_intelligence.suggest_attack_family(risk, ml_component=models.assessment.component)
    novelty_facts = alert_intelligence.compute_novelty(context.record, context.summary)
    priority = alert_intelligence.priority_score(novelty_facts, confidence, user.importance if user is not None else 1.0)
    evidence = alert_intelligence.evidence_of(evaluation.hits)

    alert = _open_incident(db, user_id=event.user_id, ip=ip, at=event.created_at)
    if alert is None:
        incident = Incident.start(risk, family=family, confidence=confidence, evidence=evidence)
        escalated = True
        alert = Alert(login_event_id=event.id, user_id=event.user_id, status="open")
        db.add(alert)
    else:
        previous = Incident.from_alert(alert)
        incident = previous.extend(risk, family=family, confidence=confidence, evidence=evidence)
        escalated = alert_intelligence.action_escalated(previous.action, incident.action)

    alert.risk_score = incident.score
    alert.severity = _SEVERITY[incident.action]
    alert.message = alert_intelligence.build_alert_message(
        incident, novelty_facts=novelty_facts, family=incident.family, confidence=incident.confidence, occurrence_count=incident.occurrences
    )
    alert.explanation = incident.explanation()
    alert.rule_id = incident.rule_id
    alert.attack_family = incident.family
    alert.attack_family_confidence = incident.confidence
    alert.occurrence_count = incident.occurrences
    if alert.last_seen_at is None or ensure_utc(event.created_at) > ensure_utc(alert.last_seen_at):
        alert.last_seen_at = event.created_at  # lần thử đến trễ không kéo lùi mốc của cửa sổ trượt
    alert.priority_score = max(alert.priority_score or 0.0, priority)
    db.flush()
    return alert, incident, escalated


def _respond(db: Session, *, event: LoginEvent, alert: Alert, risk: RiskResult, username: str, ip: str) -> None:
    """Đề xuất step_up/lock (MR12) và THỰC THI ngay lock (MR16) — `step_up` do `auth.py` thực thi vì phải trả OTP trong
    chính response HTTP. Chỉ gọi khi sự cố mới hoặc hành động vừa TĂNG — không lặp lại đúng đề xuất cũ mỗi lần trùng."""
    reasons = "; ".join(f"{c.label} ({c.weight:.0%})" for c in risk.contributions[:3])
    if risk.overridden_by is not None:  # MR21: nói rõ hành động đến từ luật xác định, không phải từ điểm
        reasons = f"luật {risk.overridden_by} ép mức tối thiểu '{risk.action}'; {reasons}"
    response_action = ResponseAction(
        login_event_id=event.id, alert_id=alert.id, user_id=event.user_id, action=risk.action,
        reason=f"Hybrid risk engine đề xuất (điểm {risk.score}/100): {reasons}.",
    )
    db.add(response_action)
    db.flush()
    audit_action = f"recommend_{risk.action}"
    audit_detail = {"response_action_id": response_action.id, "alert_id": alert.id, "score": risk.score}

    if risk.action == "lock":
        # Khoá áp dụng cho MỌI lần thử dẫn tới "lock" — kể cả lần SAI mật khẩu (chạy nền, không có HTTP nào đang chờ).
        kind, value = lock_kind_and_value(user_id=event.user_id, username=username, ip=ip)
        new_expiry = event.created_at + LOCK_TTL
        # "lock" có thể đến từ chính blocklist_hit (mục đã có sẵn) — UniqueConstraint(kind, value): tái dùng mục cũ, chỉ
        # GIA HẠN nếu lần khoá này đi xa hơn (không bao giờ rút ngắn một mục dài hơn/vĩnh viễn).
        block_entry = db.query(BlocklistEntry).filter(BlocklistEntry.kind == kind, BlocklistEntry.value == value).first()
        if block_entry is None:
            # MR20: một lần thử ĐỒNG THỜI khác có thể vừa chèn đúng mục này — chèn trong SAVEPOINT, trùng thì dùng mục kia.
            try:
                with db.begin_nested():
                    block_entry = BlocklistEntry(kind=kind, value=value, reason=f"Tự động khoá — {reasons}.", added_by="system", expires_at=new_expiry)
                    db.add(block_entry)
            except IntegrityError:
                block_entry = db.query(BlocklistEntry).filter(BlocklistEntry.kind == kind, BlocklistEntry.value == value).one()
            invalidate_blocklist_cache()  # lần thử NGAY SAU phải thấy mục khoá mới, không đợi hết TTL cache 15 s
        # ensure_utc: SQLite (test/mô phỏng) đọc lại `expires_at` không kèm múi giờ (lộ ra ở MR22).
        elif block_entry.expires_at is not None and ensure_utc(block_entry.expires_at) < ensure_utc(new_expiry):
            block_entry.expires_at = new_expiry
            invalidate_blocklist_cache()
        response_action.status = "executed"
        response_action.executed_at = event.created_at
        audit_action = "execute_lock"
        audit_detail.update(blocklist_entry_id=block_entry.id, blocklist_kind=kind, blocklist_value=value)

    db.add(AuditLog(actor="system", action=audit_action, target_type="login_event", target_id=event.id, detail=audit_detail))


def _correlate_campaign(db: Session, *, event: LoginEvent, alert: Alert) -> None:
    """MR14: gom cảnh báo CÙNG hạ tầng (IP hoặc ASN) nhắm vào NHIỀU tài khoản khác nhau trong `LIVE_CAMPAIGN_WINDOW` thành
    một `Campaign`. Khác sự cố (một tài khoản/IP lặp lại): ở đây là nhiều tài khoản chia sẻ hạ tầng. Lọc theo THỜI ĐIỂM
    ĐĂNG NHẬP, chuẩn hoá múi giờ bằng `ensure_utc` (SQLite đọc lại mất tzinfo)."""
    if event.ip_address is None and event.asn is None:
        return
    now = ensure_utc(event.created_at)
    window_start = now - LIVE_CAMPAIGN_WINDOW
    # MR20: lọc hạ tầng + cửa sổ ngay trong SQL (chỉ mục ip_address/asn) — trước đó nạp cả bảng alerts (~140 ms/lần).
    same_infra = []
    if event.ip_address is not None:
        same_infra.append(LoginEvent.ip_address == event.ip_address)
    if event.asn is not None:
        same_infra.append(LoginEvent.asn == event.asn)
    candidates = (
        db.query(Alert, LoginEvent)
        .join(LoginEvent, Alert.login_event_id == LoginEvent.id)
        .filter(Alert.id != alert.id, or_(*same_infra), LoginEvent.created_at >= window_start, LoginEvent.created_at <= now)
    )
    if event.user_id is not None:
        candidates = candidates.filter(or_(LoginEvent.user_id.is_(None), LoginEvent.user_id != event.user_id))
    matches = [
        (a, ensure_utc(le.created_at))
        for a, le in candidates
        if window_start <= ensure_utc(le.created_at) <= now
        and ((event.ip_address is not None and le.ip_address == event.ip_address) or (event.asn is not None and le.asn == event.asn))
        and not (le.user_id is not None and le.user_id == event.user_id)  # chính tài khoản này lặp lại là việc của sự cố, không phải chiến dịch
    ]
    existing_campaign_id = next((a.campaign_id for a, _ in matches if a.campaign_id is not None), None)
    campaign = db.get(Campaign, existing_campaign_id) if existing_campaign_id is not None else None
    if campaign is None and matches:
        shared = f"ASN {event.asn}" if event.asn is not None else f"IP {event.ip_address}"
        campaign = Campaign(label=f"Chiến dịch qua {shared}", first_seen_at=min(ts for _, ts in matches), last_seen_at=now)
        db.add(campaign)
        db.flush()
    if campaign is None:
        return
    for member in (*(a for a, _ in matches), alert):
        if member.campaign_id is None:
            member.campaign_id = campaign.id
            campaign.alert_count += 1
        if campaign.attack_family is None and member.attack_family is not None:
            campaign.attack_family = member.attack_family
    if now > ensure_utc(campaign.last_seen_at):
        campaign.last_seen_at = now
    if now < ensure_utc(campaign.first_seen_at):
        campaign.first_seen_at = now
    db.flush()


def _alert_payload(alert: Alert, *, username: str, event: LoginEvent) -> dict:
    """Payload WebSocket — cùng các trường với `AlertOut` (frontend chèn thẳng vào danh sách, thay hàng cũ cùng `id` khi
    sự cố được cập nhật) cộng toạ độ của lần thử vừa rồi. Bản đồ đọc đường bay từ `explanation.evidence.impossible_travel`."""
    return {
        "id": alert.id, "login_event_id": alert.login_event_id, "user_id": alert.user_id, "username": username,
        "severity": alert.severity, "risk_score": alert.risk_score, "message": alert.message, "resolved": False,
        "status": alert.status, "rule_id": alert.rule_id, "attack_family": alert.attack_family,
        "attack_family_confidence": alert.attack_family_confidence, "explanation": alert.explanation,
        "campaign_id": alert.campaign_id, "occurrence_count": alert.occurrence_count, "priority_score": alert.priority_score,
        "latitude": event.latitude, "longitude": event.longitude,
        "created_at": (alert.created_at or event.created_at).isoformat(),
        "last_seen_at": alert.last_seen_at.isoformat() if alert.last_seen_at else None,
    }


# ------------------------------------------------------------------------------------------ toàn bộ pipeline


def _run_detection_pipeline_sync(*, username: str, user_id: int | None, success: bool, ip: str, user_agent: str | None, timestamp: datetime) -> PipelineResult:
    """Toàn bộ việc đều ĐỒNG BỘ (psycopg2, redis-py, mô hình CPU-bound) — cố ý không phải `async def`:
    `run_detection_pipeline` chạy nó trong `asyncio.to_thread` để không chặn vòng lặp sự kiện dùng chung (đo được timeout
    thật khi nhiều /login đồng thời trước MR12)."""
    db = SessionLocal()
    started = time.perf_counter()
    try:
        user = db.get(User, user_id) if user_id else None
        event = _record_attempt(db, username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=timestamp)

        incident_alert = None
        with _isolated(db, "chấm điểm và cảnh báo", user_id=user_id, ip=ip) as scoring, perf.timer("hybrid"):
            with perf.timer("login_context"):  # bước 1: ngữ cảnh dùng chung cho luật, đặc trưng mô hình và novelty
                context = build_login_context(db, event, username=username)
            with perf.timer("rule_engine"):  # bước 2: luật
                evaluation = build_rule_engine(db, before=event.created_at, context=context).evaluate(context.attempt)
            with perf.timer("rba_features"):
                features = context.rba_features()
            models = _score_models(db, event=event, user=user, context=context, features=features)  # bước 3: mô hình
            risk = _combine(db, event=event, user_id=user_id, evaluation=evaluation, models=models, features=features)  # bước 4
            if risk.action != "allow":  # bước 5: một sự cố = một cảnh báo, phản ứng tự động
                incident_alert, incident, escalated = _raise_incident(
                    db, event=event, user=user, ip=ip, risk=risk, evaluation=evaluation, models=models, context=context
                )
                if escalated and risk.action in ("step_up", "lock"):
                    _respond(db, event=event, alert=incident_alert, risk=risk, username=username, ip=ip)

        if not scoring.committed:
            incident_alert = None  # đã bị huỷ cùng SAVEPOINT của khối chấm điểm
        if incident_alert is not None:
            with _isolated(db, "tương quan chiến dịch", user_id=user_id, ip=ip):
                _correlate_campaign(db, event=event, alert=incident_alert)

        if user is not None and success:
            with _isolated(db, "hồ sơ tài khoản", user_id=user_id):
                update_baseline_after_successful_login(db, user, event)
                record_known_device_if_new(db, user, event.device_fingerprint, user_agent)
                record_known_location_if_new(db, user, event.country, event.city)

        db.commit()
        perf.record("pipeline", (time.perf_counter() - started) * 1000)
        # Đọc TRƯỚC khi đóng session (object hết hạn sau khi đóng).
        payloads = [] if incident_alert is None else [_alert_payload(incident_alert, username=username, event=event)]
        return PipelineResult(
            alert_payloads=payloads, login_event_id=event.id, hybrid_action=event.hybrid_action, hybrid_risk_score=event.hybrid_risk_score
        )
    finally:
        db.close()


async def run_detection_pipeline(*, username: str, user_id: int | None, success: bool, ip: str, user_agent: str | None, timestamp: datetime) -> PipelineResult:
    """Chạy phần đồng bộ ở trên trong một thread riêng rồi broadcast WebSocket (thao tác `await` duy nhất cần vòng lặp sự
    kiện). Gọi qua `BackgroundTasks` (lần thử sai mật khẩu) thì giá trị trả về bị bỏ qua."""
    result = await asyncio.to_thread(
        _run_detection_pipeline_sync, username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=timestamp,
    )
    for payload in result.alert_payloads:
        await ws_manager.broadcast_json({"type": "alert", "data": payload})
    return result
