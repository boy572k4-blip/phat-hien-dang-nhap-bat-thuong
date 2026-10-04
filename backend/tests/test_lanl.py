"""MR31 — kiểm chứng trên LANL: gán nhãn red team, đặc trưng chỉ dùng quá khứ của tài khoản, nhận ngày nghỉ, chỉ số theo ngày.

Dữ liệu ở đây là vài dòng tự dựng (không cần tải LANL)."""

import duckdb
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from ml.lanl import evaluate as E
from ml.lanl import features as F

DAY = 86400


def _auth_rows():
    #       t,          user,  src,  dst,  auth,       logon,     orientation, success
    return [
        (100,           "U1", "C1", "C1", "Kerberos", "Network", "LogOn", True),
        (200,           "U1", "C1", "C2", "Kerberos", "Network", "LogOn", True),
        (300,           "U1", "C1", "C2", "Kerberos", "Network", "LogOff", True),   # LogOff: bỏ
        (DAY + 50,      "U1", "C9", "C3", "NTLM",     "Network", "LogOn", True),    # sự kiện red team
        (DAY + 60,      "U1", "C9", "C4", "NTLM",     "Network", "LogOn", False),
        (DAY + 4000,    "U1", "C1", "C2", "Kerberos", "Network", "LogOn", True),    # ngoài cửa sổ 1 giờ của hai lần trên
    ]


def _write(path, names, rows):
    pq.write_table(pa.table({n: [r[i] for r in rows] for i, n in enumerate(names)}), path)


@pytest.fixture
def lanl_files(tmp_path, monkeypatch):
    auth, red = tmp_path / "auth_users.parquet", tmp_path / "redteam.parquet"
    _write(auth, ("t", "user", "src_pc", "dst_pc", "auth_type", "logon_type", "orientation", "success"), _auth_rows())
    _write(red, ("t", "user", "src_pc", "dst_pc"), [(DAY + 50, "U1", "C9", "C3")])
    monkeypatch.setattr(F, "AUTH_PARQUET", auth)
    monkeypatch.setattr(F, "REDTEAM_PARQUET", red)
    monkeypatch.setattr(F, "SORTED_PARQUET", tmp_path / "sorted.parquet")
    monkeypatch.setattr(F, "FEATURES_PARQUET", tmp_path / "features.parquet")
    return tmp_path


def test_sample_keeps_red_users_with_weight_one_and_labels_by_exact_tuple(lanl_files):
    F.sort_sample(duckdb.connect())
    rows = pq.read_table(F.SORTED_PARQUET).to_pylist()
    assert [r["t"] for r in rows] == [100, 200, DAY + 50, DAY + 60, DAY + 4000]  # chỉ LogOn, theo thời gian
    assert all(r["weight"] == 1.0 and r["red_user"] for r in rows)
    assert [r["is_red"] for r in rows] == [False, False, True, False, False]


def test_features_use_only_the_accounts_past(lanl_files):
    F.sort_sample(duckdb.connect())
    assert F.compute() == (5, 1, 1)
    out = pq.read_table(F.FEATURES_PARQUET).to_pydict()
    assert out["new_src"] == [1, 0, 1, 0, 0]
    assert out["new_dst"] == [1, 1, 1, 1, 0]
    assert out["new_auth"] == [1, 0, 1, 0, 0]
    assert out["new_dst_1h"] == [1, 2, 1, 2, 0]       # gồm chính sự kiện; lần cuối: hai lần trước đã ra khỏi cửa sổ, C2 đã quen
    assert out["events_1h"] == [1, 2, 1, 2, 1]
    assert out["fails_1h"] == [0, 0, 0, 1, 0]
    assert out["log_prior"] == pytest.approx(list(np.log1p([0, 1, 2, 3, 4])))
    assert out["day"] == [1, 1, 2, 2, 2]
    assert out["hour_rarity"][1] == pytest.approx(1 - 2 / 3)  # giờ 0 đã gặp 1 lần trong 1 lần trước


def test_off_days_finds_weekends_by_weekly_cycle_and_holidays_below_share():
    counts = {d: 1000 for d in range(1, 29)}
    for d in counts:
        if d % 7 in (4, 5):
            counts[d] = 700          # cuối tuần: không dưới ngưỡng tuyệt đối, chỉ thấp theo chu kỳ
    counts[15] = 600                 # ngày lễ giữa tuần
    counts[16] = 750                 # ngày thường hơi thấp: giữ
    assert E.off_days(counts) == [4, 5, 11, 12, 15, 18, 19, 25, 26]


def test_daily_top_and_average_percentile_are_per_day_and_weighted():
    scores = np.array([9.0, 1, 2, 3, 5, 4, 6, 7])
    weights = np.array([1.0, 1, 1, 1, 1, 5, 1, 1])
    positive = np.array([True, False, False, False, True, False, False, False])
    day = np.array([1, 1, 1, 1, 2, 2, 2, 2])
    # ngày 1: ca dương cao nhất; ngày 2: hai user-ngày điểm cao hơn (6, 7)
    assert E._caught_in_daily_top(scores, weights, positive, day, 1) == 0.5
    assert E._caught_in_daily_top(scores, weights, positive, day, 3) == 1.0
    # ngày 2: dưới nó có trọng số 5 (điểm 4) trên tổng 8 (gồm chính nó, tính một nửa)
    assert E._avg_percentile(scores, weights, positive, day) == pytest.approx((3.5 / 4 + 5.5 / 8) / 2)


def test_daily_top_breaks_ties_at_random_instead_of_counting_them_as_caught():
    scores = np.array([1.0, 1, 1, 1, 0])
    weights = np.ones(5)
    positive = np.array([True, False, False, False, False])
    day = np.ones(5, dtype=int)
    assert E._caught_in_daily_top(scores, weights, positive, day, 1) == pytest.approx(0.25)
    assert E._caught_in_daily_top(scores, weights, positive, day, 4) == 1.0


def test_user_days_take_the_highest_score_of_the_day():
    scores = np.array([0.1, 0.9, 0.3, 0.2])
    red = np.array([False, True, False, False])
    weights = np.array([5.0, 5, 5, 1])
    users, day = np.array([0, 0, 0, 1]), np.array([1, 1, 2, 1])
    s, r, w, d = E._user_days(scores, red, weights, users, day)
    got = sorted(zip(d.tolist(), s.tolist(), r.tolist(), w.tolist()))
    assert got == [(1, 0.2, False, 1.0), (1, 0.9, True, 5.0), (2, 0.3, False, 5.0)]
