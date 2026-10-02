"""Huấn luyện 3 mô hình ML tầng 3 (nhiệm vụ 7.1): Isolation Forest, Local
Outlier Factor (novelty detection), Autoencoder (MLP bottleneck qua
scikit-learn — không cần cài TensorFlow/PyTorch).

Train/test split THEO THỜI GIAN, RIÊNG CHO TỪNG USER (70% đầu → train, 30%
cuối → test, theo `created_at` của chính user đó) — mô phỏng đúng bài toán
thật: dự đoán các lần đăng nhập TƯƠNG LAI từ lịch sử, KHÔNG xáo trộn ngẫu
nhiên như train_test_split() mặc định (sẽ làm lẫn tương lai vào tập train).

Isolation Forest học trên TOÀN BỘ tập train (kể cả vài ca bất thường lẫn
vào — đúng bản chất "unsupervised outlier detection", nhãn chỉ dùng để
ĐÁNH GIÁ ở ml/evaluate.py, không dùng khi train). LOF và Autoencoder theo
trường phái "novelty detection" — chỉ học trên phần được xác nhận BÌNH
THƯỜNG của tập train, sau đó đo mức độ "lạ" của dữ liệu mới so với đó.

MR22 — tầng 3 thành NGUỒN BẰNG CHỨNG `ml_geo` của hybrid risk engine (không còn alert `ml_anomaly` riêng):
  - Cổng cold-start: tài khoản có ít hơn `COLD_START_MIN_SUCCESSES` lần đăng nhập thành công trước đó KHÔNG được chấm.
    Chọn bằng số đo (in ra khi train, ghi vào meta.json): lần đăng nhập ĐẦU TIÊN của mọi tài khoản đều bị chấm là bất
    thường (thiết bị + vị trí "mới" theo định nghĩa), báo nhầm giảm dần qua vài lần đầu rồi đứng ở mức nền.
  - Điểm -> xác suất trên thang của hybrid (`app/detection/hybrid/calibration.py::geo_probability`): đường logistic,
    ĐỘ DỐC học bằng hồi quy logistic trên điểm NGOÀI MẪU (5-fold) có nhãn của tập train (Isolation Forest không dùng
    nhãn khi học; nhãn chỉ dùng ở đây và ở đánh giá), còn MỐC được neo đúng ngưỡng quyết định của chính mô hình
    (`offset_`): vượt ngưỡng mô hình <=> vượt ngưỡng `alert` của hybrid. Không dùng thẳng xác suất hiệu chỉnh trên dữ
    liệu tự sinh vì tỉ lệ bất thường ở đó (~14%) cao hơn thực tế nhiều: đo được báo nhầm 4,8% ở ngưỡng `alert` (gấp ~3
    lần ngưỡng cũ của mô hình) và gần nửa số ca bất thường lên xác suất 1,0 (một mình đủ KHOÁ) — docs/geo-model-integration.md mục 3.

Chạy (sau khi đã chạy ml/generate_dataset.py và ml/extract_features.py):
    cd backend
    venv\\Scripts\\python.exe -m ml.train
"""

from __future__ import annotations

import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import KFold
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURE_NAMES

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "features.csv")
ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
TRAIN_RATIO = 0.7
RANDOM_STATE = 42
COLD_START_MIN_SUCCESSES = 5  # MR22, xem docstring module và bảng `cold_start_fpr` trong meta.json
CALIBRATION_FOLDS = 5
_HISTORY_BUCKETS = ((0, 0), (1, 1), (2, 2), (3, 4), (5, 9), (10, 19), (20, 10**9))


def _fit_isolation_forest(X_scaled: np.ndarray, contamination: float) -> IsolationForest:
    return IsolationForest(n_estimators=200, contamination=contamination, random_state=RANDOM_STATE).fit(X_scaled)


def _out_of_fold_margins(train_df: pd.DataFrame, contamination: float) -> np.ndarray:
    """Biên độ "điểm bất thường − ngưỡng quyết định" của từng dòng train, chấm bởi mô hình KHÔNG học dòng đó (5-fold):
    tránh điểm lạc quan của dữ liệu đã học khi ước lượng độ dốc xác suất."""
    margins = np.zeros(len(train_df))
    for fit_idx, held_idx in KFold(CALIBRATION_FOLDS, shuffle=True, random_state=RANDOM_STATE).split(train_df):
        scaler = StandardScaler().fit(train_df.iloc[fit_idx][FEATURE_NAMES].values)
        forest = _fit_isolation_forest(scaler.transform(train_df.iloc[fit_idx][FEATURE_NAMES].values), contamination)
        held = scaler.transform(train_df.iloc[held_idx][FEATURE_NAMES].values)
        margins[held_idx] = -forest.score_samples(held) + forest.offset_  # > 0 <=> mô hình gắn cờ bất thường
    return margins


def fit_geo_slope(margins: np.ndarray, is_anomaly: np.ndarray) -> float:
    """Độ dốc của P(bất thường | biên độ) — hồi quy logistic 1 biến (Platt). Chỉ giữ độ dốc; mốc neo ở thời điểm chấm."""
    model = LogisticRegression(C=1e6, max_iter=1000).fit(margins.reshape(-1, 1), is_anomaly.astype(int))
    return float(model.coef_[0][0])


def cold_start_fpr(forest: IsolationForest, scaler: StandardScaler, df: pd.DataFrame) -> list[dict]:
    """Tỉ lệ đăng nhập BÌNH THƯỜNG bị mô hình gắn cờ, theo số lần thành công trước đó của tài khoản — bằng chứng chọn
    `COLD_START_MIN_SUCCESSES`."""
    flagged = forest.predict(scaler.transform(df[FEATURE_NAMES].values)) == -1
    normal = df["is_anomaly"].values == 0
    count = df["successful_login_count_so_far"].values
    rows = []
    for low, high in _HISTORY_BUCKETS:
        mask = normal & (count >= low) & (count <= high)
        if mask.any():
            rows.append({"successes_before": f"{low}" if low == high else (f"{low}+" if high >= 10**9 else f"{low}-{high}"), "normal_logins": int(mask.sum()), "flagged_share": round(float(flagged[mask].mean()), 4)})
    return rows


def time_based_split_per_user(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """70% đầu / 30% cuối THEO THỜI GIAN, tính riêng cho từng user — không
    dùng sklearn.train_test_split() vì nó xáo trộn ngẫu nhiên."""
    train_parts, test_parts = [], []
    for _, group in df.groupby("username"):
        group = group.sort_values("created_at")
        split_idx = max(1, int(len(group) * TRAIN_RATIO))
        train_parts.append(group.iloc[:split_idx])
        test_parts.append(group.iloc[split_idx:])
    return pd.concat(train_parts).reset_index(drop=True), pd.concat(test_parts).reset_index(drop=True)


def main() -> None:
    df = pd.read_csv(DATA_PATH)
    train_df, test_df = time_based_split_per_user(df)

    print(f"Train: {len(train_df)} dòng ({int(train_df['is_anomaly'].sum())} bất thường)")
    print(f"Test:  {len(test_df)} dòng ({int(test_df['is_anomaly'].sum())} bất thường)")

    X_train = train_df[FEATURE_NAMES].values
    X_test = test_df[FEATURE_NAMES].values

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    _ = scaler.transform(X_test)  # chỉ để xác nhận không lỗi shape — dùng thật ở evaluate.py

    normal_mask = train_df["is_anomaly"].values == 0
    X_train_normal_scaled = X_train_scaled[normal_mask]

    contamination = max(0.01, min(0.5, float(train_df["is_anomaly"].mean())))

    models = {}

    # --- 1. Isolation Forest — học trên TOÀN BỘ train (kể cả lẫn anomaly) ---
    iso_forest = _fit_isolation_forest(X_train_scaled, contamination)
    models["isolation_forest"] = iso_forest

    # --- MR22: độ dốc xác suất (trên các dòng qua được cổng cold-start, chấm ngoài mẫu) + bảng báo nhầm theo lịch sử ---
    gated = train_df["successful_login_count_so_far"].values >= COLD_START_MIN_SUCCESSES
    margins = _out_of_fold_margins(train_df, contamination)
    geo_slope = fit_geo_slope(margins[gated], train_df["is_anomaly"].values[gated])
    history_fpr = cold_start_fpr(iso_forest, scaler, df)

    # --- 2. Local Outlier Factor (novelty=True) — chỉ học trên phần "sạch" ---
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=contamination)
    lof.fit(X_train_normal_scaled)
    models["local_outlier_factor"] = lof

    # --- 3. Autoencoder (MLP bottleneck) — chỉ học tái tạo dữ liệu "sạch" ---
    n_features = X_train_scaled.shape[1]
    bottleneck = max(2, n_features // 3)
    autoencoder = MLPRegressor(
        hidden_layer_sizes=(6, bottleneck, 6),
        activation="relu",
        max_iter=2000,
        random_state=RANDOM_STATE,
        early_stopping=True,
    )
    autoencoder.fit(X_train_normal_scaled, X_train_normal_scaled)
    models["autoencoder"] = autoencoder

    train_normal_recon = autoencoder.predict(X_train_normal_scaled)
    train_normal_mse = np.mean((X_train_normal_scaled - train_normal_recon) ** 2, axis=1)
    autoencoder_threshold = float(np.percentile(train_normal_mse, 100 * (1 - contamination)))

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    joblib.dump(scaler, os.path.join(ARTIFACTS_DIR, "scaler.joblib"))
    for name, model in models.items():
        joblib.dump(model, os.path.join(ARTIFACTS_DIR, f"{name}.joblib"))

    meta = {
        "feature_names": FEATURE_NAMES,
        "contamination": contamination,
        "autoencoder_threshold": autoencoder_threshold,
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "train_anomaly_rows": int(train_df["is_anomaly"].sum()),
        "test_anomaly_rows": int(test_df["is_anomaly"].sum()),
        # Thống kê THÔ (chưa scale) của tập train — dùng để GIẢI THÍCH lúc
        # suy luận real-time (app/detection/ml_model.py): so đặc trưng của
        # 1 lần đăng nhập với phân phối "bình thường" đã học, chỉ ra đặc
        # trưng nào lệch nhiều nhất thay vì chỉ đưa 1 con số điểm bất thường.
        "feature_mean": X_train.mean(axis=0).tolist(),
        "feature_std": X_train.std(axis=0).tolist(),
        # MR22: tầng 3 là nguồn bằng chứng `ml_geo` của hybrid (app/detection/hybrid/calibration.py::geo_probability).
        "cold_start_min_successes": COLD_START_MIN_SUCCESSES,
        "cold_start_fpr": history_fpr,
        "geo_calibration": {
            "method": "logistic slope on out-of-fold margins, anchored at the model's own decision threshold",
            "slope": geo_slope,
            "fit_rows": int(gated.sum()),
            "fit_anomalies": int(train_df["is_anomaly"].values[gated].sum()),
        },
    }
    with open(os.path.join(ARTIFACTS_DIR, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    test_df.to_csv(os.path.join(ARTIFACTS_DIR, "test_set.csv"), index=False)

    print(f"Đã lưu 3 mô hình + scaler + meta vào {os.path.abspath(ARTIFACTS_DIR)}")
    print(f"contamination ước tính từ train set: {contamination:.3f}")
    print(f"Ngưỡng reconstruction error (autoencoder): {autoencoder_threshold:.4f}")
    print(f"MR22 — độ dốc xác suất ml_geo: {geo_slope:.2f} (học trên {int(gated.sum())} dòng train đủ {COLD_START_MIN_SUCCESSES} lần thành công)")
    print("MR22 — tỉ lệ đăng nhập BÌNH THƯỜNG bị mô hình gắn cờ, theo số lần thành công trước đó (toàn bộ dữ liệu):")
    for row in history_fpr:
        print(f"  {row['successes_before']:>6} lần: {row['flagged_share']:6.1%} của {row['normal_logins']} lần đăng nhập")


if __name__ == "__main__":
    main()
