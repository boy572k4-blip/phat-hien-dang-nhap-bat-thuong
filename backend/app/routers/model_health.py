"""GET /model-health — checklist MR17 "sức khoẻ model (drift, phiên bản)": danh sách phiên bản đã đăng ký
(`model_registry`, MR12) + trôi (PSI, `ml/rba/drift.py`).

MR26 — ba nhóm số, đọc được: (1) TRÔI CỦA CHÍNH HỆ THỐNG: cửa sổ đầu của log thật so với cửa sổ gần nhất, theo đặc trưng và
theo ĐIỂM mô hình (kèm tỉ lệ lần thử mà riêng `hybrid_cp2` đủ cảnh báo); (2) KHOẢNG CÁCH RBA → HỆ THỐNG (train RBA so với
cửa sổ gần nhất) — luôn lớn, là lý do của độ lệch miền chứ không phải "trôi"; (3) độ lệch miền đang dùng và ước lượng lại
từ log thật. Trước MR26 trang chỉ có (2) nên mọi đặc trưng luôn "trôi đáng kể".

⚠️ Tính PSI cần đọc file parquet train RBA (không đổi khi chạy — cache VĨNH VIỄN trong tiến trình, không TTL) VÀ tính
lại đặc trưng RBA cho `login_events` thật (`is_synthetic=False`) — KHÔNG rẻ như `refresh_blocklist`/`refresh_rule_config`
(vài round-trip DB/dòng, xem `docs/realtime-integration.md`). Đo trực tiếp lúc dựng MR17: KHÔNG giới hạn số dòng khiến
request treo >30 GIÂY trên ~1.500 dòng thật đã tích luỹ — giới hạn `CURRENT_ROWS_LIMIT` (300 dòng GẦN NHẤT) đưa xuống
còn ~2 giây (chi tiết `docs/dashboard-v2.md`). Cache TTL DÀI (mặc định 10 phút, khác hẳn 15 giây của blocklist/rule
config, vì trôi đặc trưng không đổi nhanh) + `?refresh=true` để quản trị viên chủ động tính lại ngay khi cần.

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1).
"""

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import ModelRegistryEntry
from app.schemas import DomainShiftOut, FeatureDriftOut, ModelHealthOut, ModelVersionOut, ScoreDriftOut

router = APIRouter()

DRIFT_CACHE_TTL_SECONDS = 600.0
TOP_N_FEATURES = 15
# Mỗi dòng tốn vài round-trip DB (compute_rba_features) — đo trực tiếp: ~1.500 dòng khiến request treo >30s. Giới hạn
# ở ĐÂY (endpoint LIVE, admin đang chờ), KHÔNG giới hạn ở CLI script (python -m ml.rba.drift, chạy tay, chờ được).
# MR26: giới hạn MỖI cửa sổ (đầu và gần nhất) — tối đa 2 × 300 dòng.
CURRENT_ROWS_LIMIT = 300

_drift_cache: ModelHealthOut | None = None  # chỉ phần drift được cache — versions luôn đọc DB mới (rẻ)
_drift_cached_at = -1.0
_reference_frame_cache = None  # pd.DataFrame train RBA — KHÔNG đổi khi tiến trình đang chạy, cache vĩnh viễn (không TTL)


def invalidate_drift_cache() -> None:
    """Xoá cache DRIFT (không đụng `_reference_frame_cache` — file train RBA không đổi, xem docstring module). Gọi
    trong test setup (`conftest.py`) để một test không đọc nhầm kết quả đã cache từ DB của test KHÁC (TTL 600s dài hơn
    nhiều so với thời gian chạy một bộ test, nên rất dễ rò rỉ nếu không xoá)."""
    global _drift_cached_at
    _drift_cached_at = -1.0


def _get_reference_frame():
    global _reference_frame_cache
    if _reference_frame_cache is None:
        from ml.rba.drift import reference_frame

        _reference_frame_cache = reference_frame()
    return _reference_frame_cache


def _features_out(rows) -> list[FeatureDriftOut]:
    import numpy as np

    return [
        FeatureDriftOut(feature=r.feature, psi=None if np.isnan(r.psi) else r.psi, verdict=r.verdict, n_reference=r.n_reference, n_current=r.n_current)
        for r in rows[:TOP_N_FEATURES]
    ]


def _model_view(engine, reference, current) -> tuple[ScoreDriftOut | None, DomainShiftOut | None]:
    """Trôi điểm `hybrid_cp2` giữa hai cửa sổ và độ lệch miền (đang dùng + ước lượng lại từ trung vị lần thành công)."""
    import numpy as np

    from ml.rba.drift import MIN_CURRENT_ROWS, population_stability_index, verdict
    from ml.rba.features import FEATURE_NAMES

    profile = engine.profile
    if engine.scorer is None or profile.ml_calibration is None:
        return None, None

    def scored(frame):
        if len(frame) == 0:
            return np.array([]), np.array([], dtype=bool)
        return np.asarray(engine.scorer(frame[list(FEATURE_NAMES)].astype(float)), dtype=float), frame["cur_success"].to_numpy(dtype=float) == 1.0

    def alert_share(raw, success):
        if len(raw) == 0:
            return None
        probabilities = np.array([profile.ml_probability(r, s) for r, s in zip(raw, success)])
        return float(np.mean(np.round(probabilities * 100) >= profile.bands.alert_at))

    (raw_ref, ok_ref), (raw_cur, ok_cur) = scored(reference), scored(current)
    psi = population_stability_index(raw_ref, raw_cur) if len(raw_ref) and len(raw_cur) else float("nan")
    score = ScoreDriftOut(psi=None if np.isnan(psi) else psi, verdict=verdict(psi), ml_alert_share_reference=alert_share(raw_ref, ok_ref), ml_alert_share_current=alert_share(raw_cur, ok_cur))

    shift = profile.ml_domain_shift
    if shift is None:
        return score, None
    live_success = raw_cur[ok_cur]
    live = None
    if shift.rba_median_success is not None and len(live_success) >= MIN_CURRENT_ROWS:
        live = float(np.median(live_success)) - shift.rba_median_success
    return score, DomainShiftOut(
        success=shift.success, failure=shift.failure, ci95_success=None if shift.ci95_success is None else list(shift.ci95_success),
        source=shift.source, live_estimate=live, live_n=int(len(live_success)),
    )


def _compute_drift(db: Session) -> dict:
    from app.detection import hybrid_runtime
    from ml.rba.drift import MIN_CURRENT_ROWS, psi_report, system_windows

    reference, current = system_windows(db, CURRENT_ROWS_LIMIT)
    rows = psi_report(reference.frame, current.frame)
    rba_reference = _get_reference_frame()
    score, shift = _model_view(hybrid_runtime.get_engine(), reference.frame, current.frame)
    return {
        "drift_computed_at": datetime.now(timezone.utc),
        "drift_low_confidence": min(len(reference.frame), len(current.frame)) < MIN_CURRENT_ROWS,
        "drift_n_reference": len(reference.frame), "drift_n_current": len(current.frame),
        "drift_reference_from": reference.start, "drift_reference_to": reference.end,
        "drift_current_from": current.start, "drift_current_to": current.end,
        "drift_top_features": _features_out(rows),
        "score_drift": score, "domain_shift": shift,
        "rba_gap_n_reference": len(rba_reference), "rba_gap_top_features": _features_out(psi_report(rba_reference, current.frame)),
    }


@router.get("/model-health", response_model=ModelHealthOut)
def get_model_health(
    refresh: bool = Query(False, description="Bỏ qua cache TTL, tính lại drift ngay (chậm — quét lại toàn bộ login_events thật)"),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    global _drift_cache, _drift_cached_at

    versions = [ModelVersionOut.model_validate(row) for row in db.query(ModelRegistryEntry).order_by(ModelRegistryEntry.id.desc()).all()]

    now = time.monotonic()
    if refresh or _drift_cache is None or now - _drift_cached_at >= DRIFT_CACHE_TTL_SECONDS:
        _drift_cache = ModelHealthOut(versions=[], **_compute_drift(db))
        _drift_cached_at = now

    return _drift_cache.model_copy(update={"versions": versions})
