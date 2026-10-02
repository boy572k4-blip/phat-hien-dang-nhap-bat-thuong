"""Tầng 3 — ML địa lý-thời gian (nhiệm vụ 7.1). Từ MR22 KHÔNG còn tạo alert
`ml_anomaly` riêng: là nguồn bằng chứng `ml_geo` của hybrid risk engine —
`predict()` trả biên độ so với ngưỡng quyết định của mô hình, pipeline đổi
sang xác suất qua `app.detection.hybrid.calibration.geo_probability` (độ dốc
`geo_slope()`) và chỉ chấm tài khoản đã có ít nhất `cold_start_min_successes()`
lần đăng nhập thành công (cổng cold-start, xem ml/train.py).

Dùng model Isolation Forest đã huấn luyện ở backend/ml/train.py. Nếu chưa
train (chưa chạy `python -m ml.train`), module tự chuyển sang "không khả
dụng" — không raise lỗi, không chặn luồng đăng nhập (giống triết lý xử lý
lỗi của app/detection/geoip.py).

⚠️ Giới hạn thật — xem docs/ml-evaluation.md mục 5: huấn luyện trên dữ liệu
tự sinh, chưa qua kiểm định với dữ liệu tấn công thật. Vì vậy xác suất
`ml_geo` bị chặn trên dưới ngưỡng `step_up`: một mình mô hình này chỉ đủ để
cảnh báo, không đủ để chặn hay khoá (xem `geo_probability`).
"""

from __future__ import annotations

import json
import logging
import os

import numpy as np

from ml.features import FEATURE_NAMES

logger = logging.getLogger("ml_model")

# Tên tiếng Việt dễ hiểu cho từng đặc trưng — dùng khi giải thích (explain()).
# hour_sin/hour_cos cố tình KHÔNG có trong bảng này: chỉ là mã hoá lượng
# giác của giờ, một mình chúng không có ý nghĩa để báo cho admin đọc.
_FEATURE_LABELS_VI = {
    "day_of_week": "thứ trong tuần",
    "hour_deviation_from_avg": "lệch giờ quen thuộc",
    "is_new_location": "vị trí mới",
    "is_new_device": "thiết bị mới",
    "minutes_since_last_login": "khoảng cách lần đăng nhập trước",
    "logins_last_24h": "tần suất đăng nhập 24h",
    "distance_km_from_home": "khoảng cách xa nhà",
}

_ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "artifacts")

_scaler = None
_iso_forest = None
_fast_forest = None  # bộ chấm trùng từng bit với sklearn (ml/fast_iforest.py), None nếu không qua kiểm tra -> dùng _iso_forest
_meta: dict | None = None
_load_attempted = False


def _load() -> None:
    global _scaler, _iso_forest, _fast_forest, _meta, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True

    try:
        import joblib  # import trễ — tránh phụ thuộc joblib nếu chưa cần ML

        from ml.fast_iforest import build_verified

        _scaler = joblib.load(os.path.join(_ARTIFACTS_DIR, "scaler.joblib"))
        _iso_forest = joblib.load(os.path.join(_ARTIFACTS_DIR, "isolation_forest.joblib"))
        _fast_forest = build_verified(_iso_forest)
        with open(os.path.join(_ARTIFACTS_DIR, "meta.json"), encoding="utf-8") as f:
            _meta = json.load(f)
        logger.info("Đã tải model ML tầng 3 (Isolation Forest) từ %s", _ARTIFACTS_DIR)
    except FileNotFoundError:
        logger.warning("Chưa có model ML tầng 3 (chạy `python -m ml.train` trước) — tầng 3 tạm tắt.")
        _scaler = None
        _iso_forest = None
        _fast_forest = None
        _meta = None
    except Exception:  # noqa: BLE001 — model lỗi/hỏng cũng không được chặn luồng đăng nhập
        logger.exception("Lỗi khi tải model ML tầng 3 — tầng 3 tạm tắt.")
        _scaler = None
        _iso_forest = None
        _fast_forest = None
        _meta = None


def is_available() -> bool:
    _load()
    return _iso_forest is not None and _scaler is not None


def predict(features: dict) -> dict | None:
    """Trả {"is_anomaly": bool, "anomaly_score": float, "margin": float} hoặc None nếu model chưa sẵn sàng. `margin` =
    điểm bất thường − ngưỡng quyết định của chính mô hình (> 0 <=> `is_anomaly`), đầu vào của `geo_probability` (MR22).
    Không bao giờ raise — mọi lỗi được nuốt và log lại.
    """
    _load()
    if _iso_forest is None or _scaler is None:
        return None

    try:
        vector = np.array([[features[name] for name in FEATURE_NAMES]])
        scaled = _scaler.transform(vector)
        # MỘT lần chấm thay cho predict() + score_samples() như trước (predict của sklearn tự tính lại đúng điểm này):
        # sklearn coi là bất thường khi score_samples - offset_ < 0.
        forest = _fast_forest or _iso_forest
        score = float(forest.score_samples(scaled)[0])
        margin = _iso_forest.offset_ - score
        return {"is_anomaly": bool(margin > 0), "anomaly_score": -score, "margin": float(margin)}
    except Exception:  # noqa: BLE001
        logger.exception("Lỗi khi suy luận ML tầng 3 cho 1 lần đăng nhập — bỏ qua, không chặn luồng.")
        return None


DEFAULT_COLD_START_MIN_SUCCESSES = 5  # khi meta.json cũ (trước MR22) chưa ghi giá trị đo được — xem ml/train.py


def geo_slope() -> float | None:
    """Độ dốc của đường xác suất `ml_geo` (MR22, ml/train.py), None nếu chưa có mô hình hoặc meta.json chưa có hiệu chỉnh
    (mô hình train trước MR22) — khi đó không dùng tầng 3 làm bằng chứng, không đoán bừa một độ dốc."""
    _load()
    if _iso_forest is None or _meta is None:
        return None
    calibration = _meta.get("geo_calibration")
    return None if calibration is None else float(calibration["slope"])


def cold_start_min_successes() -> int:
    """Số lần đăng nhập thành công TỐI THIỂU trước đó để tầng 3 được chấm một tài khoản (cổng cold-start, MR22)."""
    _load()
    return int((_meta or {}).get("cold_start_min_successes", DEFAULT_COLD_START_MIN_SUCCESSES))


def explain(features: dict, top_n: int = 3) -> str:
    """Giải thích NGƯỜI ĐỌC ĐƯỢC: đặc trưng nào lệch nhiều nhất so với phân
    phối "bình thường" đã học (mean/std của tập train, lưu ở meta.json).
    Dùng cho nhãn của nguồn `ml_geo` trong cảnh báo hybrid (trước MR22: message
    của Alert 'ml_anomaly') — thay vì chỉ đưa 1 điểm số, chỉ ra CỤ THỂ điều gì
    khiến lần đăng nhập này bị coi là lạ.

    Trả chuỗi rỗng nếu model/thống kê chưa sẵn sàng (không raise).
    """
    _load()
    if _meta is None or "feature_mean" not in _meta:
        return ""

    try:
        means = _meta["feature_mean"]
        stds = _meta["feature_std"]
        deviations = []
        for i, name in enumerate(FEATURE_NAMES):
            if name not in _FEATURE_LABELS_VI:
                continue
            std = stds[i] if stds[i] > 1e-6 else 1.0
            z = (features[name] - means[i]) / std
            deviations.append((abs(z), z, name))

        deviations.sort(key=lambda item: item[0], reverse=True)
        top = deviations[:top_n]

        parts = []
        for _abs_z, z, name in top:
            if abs(z) < 0.5:
                continue  # gần mức trung bình, không đáng nhắc tới
            arrow = "↑" if z > 0 else "↓"
            parts.append(f"{_FEATURE_LABELS_VI[name]} {arrow}")

        if not parts:
            return "không có yếu tố nổi bật"
        return ", ".join(parts)
    except Exception:  # noqa: BLE001
        logger.exception("Lỗi khi giải thích kết quả ML — bỏ qua.")
        return ""
