"""Đặc trưng RBA (MR3: `ml/rba/features.py`) tính từ DB thật cho luồng /login (MR12).

`ml/rba/features.py` là ĐẶC TẢ thuần Python của 50 đặc trưng (`HistorySummary` + `features_from_summary`); module này
chỉ dựng `HistorySummary` bằng truy vấn DB. Từ MR20 phần truy vấn nằm ở `app/detection/login_context.py` (dùng chung
với rule engine v2): lịch sử tài khoản ở dạng tổng hợp do DB tự đếm, IP/ASN 24 giờ, và MỘT bộ đếm toàn cục có khoá.
Pipeline gọi thẳng `build_login_context`; các hàm ở đây giữ cho nơi khác chỉ cần đặc trưng của một dòng (drift MR17,
`GET /model-health`, test) — cùng một đường tính, không phải bản sao công thức.

⚠️ Giả định luồng THẬT: lần thử được chấm gần như ngay khi xảy ra (bộ đếm toàn cục có thể thiếu vài chục giây gần nhất,
xem `GlobalCountsCache`). KHÔNG dùng để chấm lại log cũ hàng loạt — việc đó là của `backend/ml/rba/rule_replay.py`.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.detection.login_context import (
    GLOBAL_COUNTS_CACHE_TTL_SECONDS,
    GlobalCountsCache,
    build_history_summary,
    event_record_for,
    to_us,
)
from ml.rba.features import EventRecord, HistorySummary, features_from_summary

__all__ = [
    "GLOBAL_COUNTS_CACHE_TTL_SECONDS", "GlobalCountsCache", "build_features_and_summary", "build_history_summary",
    "compute_rba_features", "event_record_for", "to_us",
]

logger = logging.getLogger("rba_live_features")


def build_features_and_summary(
    db: Session, event: EventRecord, *, cache: GlobalCountsCache | None = None
) -> tuple[dict[str, float] | None, HistorySummary | None]:
    """Như `compute_rba_features`, nhưng trả THÊM `HistorySummary` (MR13 tính novelty từ chính bản tóm tắt này, không
    truy vấn DB lần hai). Không bao giờ raise: lỗi trả `(None, None)`."""
    try:
        summary = build_history_summary(db, event, cache=cache)
        return features_from_summary(event, summary), summary
    except Exception:  # noqa: BLE001
        logger.exception("lỗi khi tính đặc trưng RBA cho user_id=%s ip=%s — bỏ qua thành phần ML", event.user_id, event.ip)
        return None, None


def compute_rba_features(db: Session, event: EventRecord, *, cache: GlobalCountsCache | None = None) -> dict[str, float] | None:
    """50 đặc trưng RBA (`ml.rba.features.FEATURE_NAMES`) của `event`, hoặc `None` nếu có lỗi (không bao giờ raise — không
    được chặn/làm sập pipeline nền, cùng triết lý phần còn lại của `app/detection`)."""
    features, _summary = build_features_and_summary(db, event, cache=cache)
    return features
