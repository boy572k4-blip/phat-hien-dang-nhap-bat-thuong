"""Phương pháp ĐỐI CHỨNG "tầng 2" (Tuần 4, nhiệm vụ 4.2): luật cộng điểm tay — chỉ để tái lập phép so sánh tầng 2 với
ML ở `ml/evaluate.py` (số liệu đã đưa vào docs/ml-evaluation.md).

Từ MR21 công thức này KHÔNG còn chạy trên luồng đăng nhập (`app/detection/scoring.py` đã xoá): các thành phần của nó là
luật v2 hoặc đặc trưng ML tương ứng (ánh xạ: docs/rule-unification.md). Giữ nguyên văn ở đây, cùng chỗ với các mô hình
khác của phép so sánh (Isolation Forest, LOF, Autoencoder), để con số "tầng 2" trong báo cáo vẫn chạy lại được từ mã.

Trọng số và ngưỡng lấy NGUYÊN VĂN checklist mục 4.2: lệch giờ +20, IP lạ +30, fail liên tiếp +40, đăng nhập thành công
ngay sau chuỗi fail +50. Dưới 40 = bình thường, 40-70 = trung bình, trên 70 = cao.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.detection.baseline import is_in_learning_mode

UNUSUAL_HOUR_WEIGHT = 20
UNKNOWN_LOCATION_WEIGHT = 30
CONSECUTIVE_FAIL_WEIGHT = 40
SUCCESS_AFTER_FAIL_STREAK_WEIGHT = 50

LOW_RISK_MAX = 40  # < 40: bình thường
MEDIUM_RISK_MAX = 70  # 40-70: trung bình, > 70: cao

# ⚠️ Giả định (docs/api-contract.md mục 6) — không có trong checklist gốc.
UNUSUAL_HOUR_STDDEV_MULTIPLIER = 2.5
MIN_STDDEV_HOURS = 0.5  # tránh stddev quá nhỏ khiến mọi lệch nhỏ đều bị tính bất thường


@dataclass
class RiskFactors:
    unusual_hour: bool = False
    unknown_location: bool = False
    consecutive_fail: bool = False
    success_after_fail_streak: bool = False

    def total_score(self) -> int:
        score = 0
        if self.unusual_hour:
            score += UNUSUAL_HOUR_WEIGHT
        if self.unknown_location:
            score += UNKNOWN_LOCATION_WEIGHT
        if self.consecutive_fail:
            score += CONSECUTIVE_FAIL_WEIGHT
        if self.success_after_fail_streak:
            score += SUCCESS_AFTER_FAIL_STREAK_WEIGHT
        return min(score, 100)


def is_unusual_hour(baseline, login_hour: float) -> bool:
    """False khi đang ở chế độ học hoặc thiếu baseline — không đủ dữ liệu để kết luận."""
    if baseline is None or is_in_learning_mode(baseline) or baseline.avg_login_hour is None:
        return False

    stddev = max(baseline.stddev_login_hour or 0.0, MIN_STDDEV_HOURS)
    # Khoảng cách theo đường tròn 24h (23h và 1h chỉ cách nhau 2h, không phải 22h).
    diff = abs(login_hour - baseline.avg_login_hour)
    diff = min(diff, 24 - diff)
    return diff > UNUSUAL_HOUR_STDDEV_MULTIPLIER * stddev


def compute_risk_score(
    *,
    baseline,
    login_hour: float,
    is_new_location: bool,
    consecutive_fail: bool,
    success_after_fail_streak: bool,
) -> tuple[int, RiskFactors]:
    in_learning_mode = baseline is None or is_in_learning_mode(baseline)

    factors = RiskFactors(
        unusual_hour=is_unusual_hour(baseline, login_hour),
        # Chế độ học: chưa đủ dữ liệu để biết "vị trí quen thuộc" là gì -> không tính lạ.
        unknown_location=is_new_location and not in_learning_mode,
        consecutive_fail=consecutive_fail,
        success_after_fail_streak=success_after_fail_streak,
    )
    return factors.total_score(), factors
