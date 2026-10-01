"""ml/tier2_baseline.py — công thức cộng điểm tay của tầng 2 (Tuần 4), từ MR21 chỉ còn là phương pháp ĐỐI CHỨNG cho phép so
sánh tầng 2 với ML ở ml/evaluate.py. Giữ các test cốt lõi của test_scoring.py cũ để con số "tầng 2" trong báo cáo vẫn tái
lập đúng công thức đã chạy thật tới MR20 (luồng thật giờ dùng luật v2: tests/test_pipeline_mr21.py)."""

from datetime import datetime, timedelta, timezone

from app.models import UserBaseline
from ml.tier2_baseline import CONSECUTIVE_FAIL_WEIGHT, SUCCESS_AFTER_FAIL_STREAK_WEIGHT, UNKNOWN_LOCATION_WEIGHT, UNUSUAL_HOUR_WEIGHT, compute_risk_score, is_unusual_hour

_MATURE_BASELINE = UserBaseline(
    user_id=1, successful_login_count=50, avg_login_hour=9.0, stddev_login_hour=1.0, first_login_at=datetime.now(timezone.utc) - timedelta(days=30),
)


def _score(baseline=_MATURE_BASELINE, *, hour=9.0, new_location=False, consecutive_fail=False, success_after_streak=False):
    return compute_risk_score(baseline=baseline, login_hour=hour, is_new_location=new_location, consecutive_fail=consecutive_fail, success_after_fail_streak=success_after_streak)


def test_weights_are_the_checklist_values_and_add_up():
    assert (UNUSUAL_HOUR_WEIGHT, UNKNOWN_LOCATION_WEIGHT, CONSECUTIVE_FAIL_WEIGHT, SUCCESS_AFTER_FAIL_STREAK_WEIGHT) == (20, 30, 40, 50)
    assert _score(hour=20.0, new_location=True)[0] == 50  # lệch giờ + vị trí lạ
    assert _score(new_location=True, success_after_streak=True)[0] == 80
    assert _score(baseline=None, consecutive_fail=True)[0] == 40
    assert _score(hour=9.1)[0] == 0  # đăng nhập bình thường


def test_learning_mode_never_flags_unusual_hour_or_location():
    new_user = UserBaseline(user_id=2, successful_login_count=2, avg_login_hour=9.0, stddev_login_hour=0.5, first_login_at=datetime.now(timezone.utc))
    score, factors = _score(new_user, hour=22.0, new_location=True)
    assert score == 0 and not factors.unusual_hour and not factors.unknown_location


def test_unusual_hour_handles_circular_wraparound():
    baseline = UserBaseline(user_id=3, successful_login_count=50, avg_login_hour=23.0, stddev_login_hour=1.0, first_login_at=datetime.now(timezone.utc) - timedelta(days=30))
    assert is_unusual_hour(baseline, 1.0) is False  # 23h -> 1h chỉ cách 2h
    assert is_unusual_hour(baseline, 12.0) is True
