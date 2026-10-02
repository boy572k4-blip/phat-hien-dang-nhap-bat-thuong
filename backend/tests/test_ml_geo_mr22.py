"""MR22 — phần offline của nguồn `ml_geo`: độ dốc xác suất và bảng cold-start (ml/train.py), bảng điểm làm việc theo kiểu
bất thường (ml/evaluate.py), bộ sinh dữ liệu có seed (ml/generate_dataset.py). Dữ liệu tổng hợp nhỏ, không cần DB hay
artifacts đã train."""

import random
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from app.detection.hybrid import ActionBands
from ml import generate_dataset
from ml.evaluate import geo_operating_points
from ml.features import FEATURE_NAMES
from ml.train import _out_of_fold_margins, cold_start_fpr, fit_geo_slope

BANDS = ActionBands(32, 58, 70)


def _frame(n_normal=300, n_anomaly=40, seed=0, successes=10):
    """Bình thường quanh 0, bất thường lệch xa — đủ để Isolation Forest tách được."""
    rng = np.random.default_rng(seed)
    normal = rng.normal(0.0, 1.0, size=(n_normal, len(FEATURE_NAMES)))
    anomaly = rng.normal(4.0, 1.0, size=(n_anomaly, len(FEATURE_NAMES)))
    df = pd.DataFrame(np.vstack([normal, anomaly]), columns=FEATURE_NAMES)
    df["is_anomaly"] = [0] * n_normal + [1] * n_anomaly
    df["anomaly_type"] = ["normal"] * n_normal + ["far"] * n_anomaly
    df["successful_login_count_so_far"] = successes
    return df


def test_the_fitted_slope_is_positive_when_anomalies_sit_beyond_the_threshold():
    rng = np.random.default_rng(1)
    margins = np.concatenate([rng.normal(-0.08, 0.03, 500), rng.normal(0.05, 0.02, 80)])
    labels = np.array([0] * 500 + [1] * 80)
    assert fit_geo_slope(margins, labels) > 0


def test_out_of_fold_margins_cover_every_row_and_rank_anomalies_higher():
    df = _frame()
    margins = _out_of_fold_margins(df, contamination=40 / 340)
    assert margins.shape == (len(df),) and np.isfinite(margins).all()
    assert margins[df.is_anomaly.values == 1].mean() > margins[df.is_anomaly.values == 0].mean()


def test_cold_start_table_reports_the_flagged_share_of_normal_logins_per_history_bucket():
    df = pd.DataFrame({name: 0.0 for name in FEATURE_NAMES}, index=range(6))
    df["successful_login_count_so_far"] = [0, 0, 1, 7, 12, 30]
    df["is_anomaly"] = [0, 0, 0, 0, 0, 1]
    df[FEATURE_NAMES[0]] = [1.0, 0.0, 1.0, 0.0, 0.0, 1.0]  # mô hình giả: gắn cờ khi đặc trưng đầu = 1
    forest = SimpleNamespace(predict=lambda X: np.where(X[:, 0] == 1.0, -1, 1))
    scaler = SimpleNamespace(transform=lambda X: X)

    rows = {r["successes_before"]: r for r in cold_start_fpr(forest, scaler, df)}

    assert rows["0"] == {"successes_before": "0", "normal_logins": 2, "flagged_share": 0.5}
    assert rows["1"]["flagged_share"] == 1.0 and rows["5-9"]["flagged_share"] == 0.0 and rows["10-19"]["normal_logins"] == 1
    assert "20+" not in rows  # dòng duy nhất ở nhóm này là bất thường — bảng chỉ đếm đăng nhập BÌNH THƯỜNG


def _fit(df):
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler().fit(df[FEATURE_NAMES].values)
    forest = IsolationForest(n_estimators=50, contamination=0.1, random_state=0).fit(scaler.transform(df[FEATURE_NAMES].values))
    return forest, scaler.transform(df[FEATURE_NAMES].values)


def test_past_the_gate_the_ml_geo_decision_is_exactly_the_models_own_threshold():
    """Điều MR22 khẳng định trong docs: neo xác suất ở ngưỡng alert nên quyết định cảnh báo của tầng 3 không đổi."""
    df = _frame(successes=10)
    forest, X = _fit(df)
    meta = {"contamination": 0.1, "geo_calibration": {"slope": 48.0}, "cold_start_min_successes": 5}

    table = geo_operating_points(forest, X, df, meta, BANDS)

    assert table["ml_geo_mr22"].tolist() == table["model_threshold"].tolist()
    assert table.loc["ALL (recall)", "ml_geo_mr22"] > 0.5


def test_the_gate_removes_accounts_below_the_minimum_history():
    df = _frame(successes=10)
    df.loc[df.index[-10:], "successful_login_count_so_far"] = 2  # 10 ca bất thường cuối: tài khoản mới
    forest, X = _fit(df)
    meta = {"contamination": 0.1, "geo_calibration": {"slope": 48.0}, "cold_start_min_successes": 5}

    table = geo_operating_points(forest, X, df, meta, BANDS)

    flagged = forest.predict(X) == -1
    anomaly, past_gate = df.is_anomaly.values == 1, df.successful_login_count_so_far.values >= 5
    assert (flagged & anomaly & ~past_gate).any()  # có ca mô hình gắn cờ nằm dưới cổng — test có ý nghĩa
    assert table.loc["ALL (recall)", "ml_geo_mr22"] == pytest.approx((flagged & anomaly & past_gate).sum() / anomaly.sum())
    assert table.loc["ALL (recall)", "model_threshold"] == pytest.approx((flagged & anomaly).sum() / anomaly.sum())


def test_a_model_without_mr22_calibration_only_gets_the_two_old_operating_points():
    df = _frame()
    forest, X = _fit(df)
    table = geo_operating_points(forest, X, df, {"contamination": 0.1}, BANDS)
    assert list(table.columns) == ["n", "documented", "model_threshold"]


def _sample(seed):
    random.seed(seed)
    profile = generate_dataset.make_user_profile(101)
    user = SimpleNamespace(id=1, username=profile["username"])
    events = generate_dataset.make_normal_events(user, profile, 5, generate_dataset.DEFAULT_REFERENCE_TIME)
    return profile, [(e.ip_address, e.user_agent, e.created_at) for e in events]


def test_the_dataset_generator_is_reproducible_from_its_seed():
    assert _sample(generate_dataset.DEFAULT_SEED) == _sample(generate_dataset.DEFAULT_SEED)
    assert _sample(generate_dataset.DEFAULT_SEED) != _sample(generate_dataset.DEFAULT_SEED + 1)
