"""MR31 — đánh giá trên log thật LANL, CÙNG cách chia với Tuor et al. 2018 (arXiv:1712.00557): ngày 1–12 phát triển (học), ngày 13–58 kiểm
tra; hai mức: TỪNG SỰ KIỆN và USER-NGÀY (điểm của user-ngày = điểm cao nhất trong ngày, như bài báo). Không giám sát: nhãn red team chỉ dùng
để đo.

Chỉ số: AUC (có khoảng tin cậy 95% bootstrap theo ca dương), recall ở FPR 1%, và "AP" theo ĐÚNG định nghĩa của Tuor et al. — AVERAGE
PERCENTILE: với mỗi ca red team, thứ hạng phần trăm của điểm nó trong mọi điểm CÙNG NGÀY, lấy trung bình (không phải average precision). Hai
phương án tập kiểm tra: mọi ngày, và bỏ cuối tuần/ngày lễ như bài báo (dữ liệu đã ẩn ngày tháng nên nhận ra từ số lần đăng nhập mỗi ngày:
cuối tuần = hai "thứ" trong chu kỳ 7 ngày có trung bình thấp nhất; ngày lễ = ngày thường < 70% trung vị ngày thường).

Các bộ chấm (điểm cao = bất thường hơn):
  - `isolation_forest`: Isolation Forest học trên 1 triệu lần đăng nhập ngẫu nhiên của ngày 1–12 (không dùng nhãn) — cùng họ mô hình với
    thành phần `bat_thuong` của `hybrid_cp2` và mô hình địa lý-thời gian của đồ án;
  - `novelty_count`: số cờ "mới với tài khoản" (máy nguồn, máy đích, loại xác thực, kiểu đăng nhập) — baseline kiểu luật, không học;
  - từng đặc trưng một (vd `new_dst_1h`: số máy đích MỚI trong 1 giờ — dấu hiệu di chuyển ngang).
Số đo có trọng số lấy mẫu người dùng (`features.py`); bộ đo dùng chung với RBA (`ml/rba/metrics.py`).

    cd backend
    venv\\Scripts\\python.exe -m ml.lanl.evaluate     # in bảng, ghi ml/artifacts/lanl/evaluation.json
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ml.lanl.etl import AUTH_PARQUET
from ml.lanl.features import FEATURES, FEATURES_PARQUET
from ml.rba import metrics as M

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "lanl"
REPORT_JSON = ARTIFACT_DIR / "evaluation.json"
DEV_LAST_DAY = 12
TRAIN_SAMPLE = 1_000_000
HOLIDAY_SHARE = 0.7
N_BOOT = 200
REVIEW_BUDGETS = (10, 50, 200)  # số user-ngày người phân tích xem mỗi ngày
SEED = 0
PUBLISHED = {  # Tuor et al. 2018, tập kiểm tra ngày 13–58 (bỏ cuối tuần/ngày lễ), mọi dòng log gắn với người dùng
    "user_day": {"PCA": {"auc": 0.754, "avg_percentile": 0.739}, "Isolation Forest": {"auc": 0.763, "avg_percentile": 0.750},
                 "RNN tốt nhất (BEM, từ)": {"auc": 0.876, "avg_percentile": 0.870}},
    "event": {"RNN ký tự tốt nhất": {"auc": 0.98}},
}


def off_days(counts: dict[int, int]) -> list[int]:
    """Cuối tuần + ngày lễ từ số lần đăng nhập mỗi ngày (ngày 1 = phần tử đầu)."""
    by_residue = {r: np.mean([n for d, n in counts.items() if d % 7 == r]) for r in range(7)}
    weekend = sorted(by_residue, key=by_residue.get)[:2]
    weekdays = {d: n for d, n in counts.items() if d % 7 not in weekend}
    floor = HOLIDAY_SHARE * float(np.median(list(weekdays.values())))
    return sorted(d for d, n in counts.items() if d % 7 in weekend or n < floor)


def daily_logons(con) -> dict[int, int]:
    rows = con.sql(f"SELECT t // 86400 + 1 AS day, count(*) FROM '{AUTH_PARQUET.as_posix()}' WHERE orientation = 'LogOn' GROUP BY 1").fetchall()
    return {int(d): int(n) for d, n in rows}


def _avg_percentile(scores: np.ndarray, weights: np.ndarray, positive: np.ndarray, day: np.ndarray) -> float:
    """Trung bình (theo ca dương) thứ hạng phần trăm của điểm trong mọi điểm cùng ngày (có trọng số; điểm bằng nhau tính một nửa)."""
    out = []
    for d in np.unique(day[positive]):
        in_day = day == d
        ref = M.NegativeReference.build(scores[in_day], weights[in_day])
        pos = scores[in_day & positive]
        below = ref.total_weight - ref.weight_ge(pos)
        equal = ref.weight_ge(pos) - ref.weight_gt(pos)
        out.extend((below + 0.5 * equal) / ref.total_weight)
    return float(np.mean(out))


def _caught_in_daily_top(scores: np.ndarray, weights: np.ndarray, positive: np.ndarray, day: np.ndarray, budget: int) -> float:
    """Tỉ lệ (kỳ vọng) ca dương nằm trong `budget` user-ngày điểm cao nhất của ngày đó; thứ hạng có trọng số, các ca bằng điểm xếp ngẫu
    nhiên (điểm nhị phân như `new_dst` hoà hàng nghìn ca — không được tính là "lọt top" chỉ vì không ai cao hơn)."""
    caught = []
    for d in np.unique(day[positive]):
        in_day = day == d
        ref = M.NegativeReference.build(scores[in_day], weights[in_day])
        pos = scores[in_day & positive]
        above, tied = ref.weight_gt(pos), ref.weight_ge(pos) - ref.weight_gt(pos)
        caught.extend(np.clip((budget - above) / tied, 0.0, 1.0))
    return float(np.mean(caught))


def _metrics(scores, weights, positive, day, rng) -> dict:
    ref = M.NegativeReference.build(scores[~positive], weights[~positive])
    pos = scores[positive]
    ones = np.ones(len(pos))
    boot = [M.roc_auc(ref, sample, np.ones(len(sample))) for sample in (rng.choice(pos, len(pos)) for _ in range(N_BOOT))]
    return {
        "auc": round(M.roc_auc(ref, pos, ones), 4), "auc_ci95": [round(float(np.percentile(boot, 2.5)), 4), round(float(np.percentile(boot, 97.5)), 4)],
        "avg_percentile": round(_avg_percentile(scores, weights, positive, day), 4),
        "recall_at_fpr_1pct": round(M.recall_at_fpr(ref, pos, ones, 0.01), 4), "n_positive": int(positive.sum()),
    }


def _user_days(scores, red, weights, user_codes, day):
    frame = pd.DataFrame({"key": user_codes.astype(np.int64) * 100 + day.astype(np.int64), "score": scores, "red": red, "w": weights, "day": day})
    grouped = frame.groupby("key", sort=False).agg(score=("score", "max"), red=("red", "max"), w=("w", "first"), day=("day", "first"))
    return grouped["score"].to_numpy(), grouped["red"].to_numpy(bool), grouped["w"].to_numpy(), grouped["day"].to_numpy()


def run() -> dict:
    con = duckdb.connect()
    started = time.perf_counter()
    path = FEATURES_PARQUET.as_posix()
    train = con.sql(f"""SELECT {', '.join(FEATURES)} FROM (SELECT * FROM '{path}' WHERE day <= {DEV_LAST_DAY})
                        USING SAMPLE {TRAIN_SAMPLE} ROWS (reservoir, {SEED})""").fetchnumpy()
    forest = IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1).fit(np.column_stack([np.asarray(train[f], dtype=np.float32) for f in FEATURES]))
    print(f"Isolation Forest học trên {len(train[FEATURES[0]]):,} lần đăng nhập ngày 1–{DEV_LAST_DAY} ({time.perf_counter() - started:,.0f} s)", flush=True)
    low_days = off_days(daily_logons(con))
    print(f"cuối tuần/ngày lễ: {low_days}", flush=True)

    report = {"split": {"dev_days": f"1-{DEV_LAST_DAY}", "test_days": f"{DEV_LAST_DAY + 1}-58"}, "off_days": low_days,
              "train_events": int(len(train[FEATURES[0]])), "published": PUBLISHED, "periods": {}}
    rng = np.random.default_rng(SEED)
    for period, where in (("dev", f"day <= {DEV_LAST_DAY}"), ("test", f"day > {DEV_LAST_DAY}")):
        data = con.sql(f"SELECT {', '.join(FEATURES)}, weight, is_red, user, day FROM '{path}' WHERE {where}").fetchnumpy()
        X = np.column_stack([np.asarray(data[f], dtype=np.float32) for f in FEATURES])
        red, weights, day = np.asarray(data["is_red"], bool), np.asarray(data["weight"], float), np.asarray(data["day"], np.int64)
        user_codes, _ = pd.factorize(np.asarray(data["user"]))
        scorers = {
            "isolation_forest": -forest.score_samples(X),
            "novelty_count": X[:, FEATURES.index("new_src")] + X[:, FEATURES.index("new_dst")] + X[:, FEATURES.index("new_auth")] + X[:, FEATURES.index("new_logon")],
            **{f: X[:, FEATURES.index(f)] for f in ("new_dst_1h", "new_dst", "new_src", "new_auth", "events_1h", "hour_rarity")},
        }
        rows = {}
        for variant, keep in (("all_days", np.ones(len(day), bool)), ("weekdays", ~np.isin(day, low_days))):
            for name, score in scorers.items():
                score = np.asarray(score, dtype=np.float64)[keep]
                ev = _metrics(score, weights[keep], red[keep], day[keep], rng)
                ud_score, ud_red, ud_w, ud_day = _user_days(score, red[keep], weights[keep], user_codes[keep], day[keep])
                ud = _metrics(ud_score, ud_w, ud_red, ud_day, rng)
                ud["n_user_days"] = int(len(ud_score))
                ud["users_per_day"] = round(float(ud_w.sum()) / len(np.unique(ud_day)))
                ud["caught_in_daily_top"] = {str(k): round(_caught_in_daily_top(ud_score, ud_w, ud_red, ud_day, k), 4) for k in REVIEW_BUDGETS}
                rows.setdefault(variant, {})[name] = {"event": ev, "user_day": ud}
                print(f"[{period}/{variant}] {name:16s} sự kiện AUC {ev['auc']:.3f} (AvgPct {ev['avg_percentile']:.3f}, recall@1% {ev['recall_at_fpr_1pct']:.3f}) | "
                      f"user-ngày AUC {ud['auc']:.3f} [{ud['auc_ci95'][0]:.3f}–{ud['auc_ci95'][1]:.3f}] AvgPct {ud['avg_percentile']:.3f} "
                      f"(n+ {ud['n_positive']}) | top/ngày {ud['caught_in_daily_top']}", flush=True)
        report["periods"][period] = {"n_events": int(len(red)), "n_red_events": int(red.sum()), "variants": rows}
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"xong sau {time.perf_counter() - started:,.0f} s -> {REPORT_JSON}", flush=True)
    return report


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    run()
