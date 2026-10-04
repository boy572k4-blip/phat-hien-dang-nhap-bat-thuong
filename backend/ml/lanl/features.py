"""MR31 — đặc trưng theo TÀI KHOẢN cho từng sự kiện xác thực LANL, cùng triết lý với hệ thống đồ án: chỉ dùng QUÁ KHỨ của chính tài khoản
(không rò rỉ tương lai), "mới với chính tài khoản" + đếm trong cửa sổ 1 giờ + lệch thói quen giờ.

| Đặc trưng LANL        | Tương ứng trong hệ thống đồ án                         |
|-----------------------|--------------------------------------------------------|
| `new_src`             | thiết bị mới (`known_devices`, `is_new_device`)          |
| `new_dst`             | vị trí/đích mới (`is_new_location`) — di chuyển ngang    |
| `new_auth`, `new_logon`| User-Agent/kiểu truy cập mới (`new_ua`)                 |
| `hour_rarity`         | lệch giờ quen (`hour_deviation_from_avg`)                |
| `events_1h`           | tốc độ (`u_attempts_1h`)                                |
| `new_dst_1h`          | lan sang nhiều máy trong thời gian ngắn                  |
| `fails_1h`            | lần sai gần đây (`u_fails_24h`, luật dò mật khẩu)         |
| `log_prior`           | độ dày lịch sử (cổng cold-start)                         |

Chỉ sự kiện ĐĂNG NHẬP (`orientation = LogOn`, thành công hay thất bại): tương ứng một lần gọi `/login` của hệ thống, và cả 701 sự kiện
red team đều là LogOn (NTLM, Network); bỏ LogOff/TGS/TGT/AuthMap (~63% số dòng) cho vừa máy 16 GB — lịch sử "mới với tài khoản" vì thế
tính trên các lần đăng nhập trước, đúng như hệ thống. Khác Tuor et al. 2018 (giữ mọi dòng gắn với người dùng) — ghi ở báo cáo.

Lấy mẫu người dùng như RBA (MR2): MỌI người dùng có sự kiện red team + 20% người dùng còn lại (chọn bằng băm tên, tái lập được), trọng số 5
cho nhóm lấy mẫu — số đo quy về toàn bộ người dùng. Nhãn: sự kiện trùng (thời điểm, người dùng, máy nguồn, máy đích) với `redteam.txt`.

Cách tính: DuckDB sắp xếp MỘT lần theo (người dùng, thời điểm), rồi đọc tuần tự và cập nhật lịch sử từng tài khoản (tập máy nguồn/đích đã
thấy, đếm theo giờ, hàng đợi 1 giờ) — đúng cách hệ thống dựng lịch sử tài khoản; sáu hàm cửa sổ của DuckDB trên hàng chục triệu dòng thì
tràn bộ nhớ trên máy 16 GB (đã thử). Sự kiện cùng thời điểm: xử lý theo thứ tự đọc, sự kiện sau thấy sự kiện trước.

    cd backend
    venv\\Scripts\\python.exe -m ml.lanl.features     # ghi ml/data/lanl/features.parquet
"""

from __future__ import annotations

import sys
import time
from collections import deque

import duckdb
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from ml.lanl.etl import AUTH_PARQUET, DATA_DIR, REDTEAM_PARQUET

FEATURES_PARQUET = DATA_DIR / "features.parquet"
SORTED_PARQUET = DATA_DIR / "logon_sorted.parquet"
SAMPLE_MOD = 5  # 1/5 người dùng không có red team được giữ (trọng số 5)
FEATURES = ("new_src", "new_dst", "new_auth", "new_logon", "hour_rarity", "events_1h", "new_dst_1h", "fails_1h", "log_prior")
WINDOW_S = 3600


def sort_sample(con: duckdb.DuckDBPyConnection) -> None:
    """Sự kiện LogOn của người dùng trong mẫu, sắp theo (người dùng, thời điểm), kèm trọng số và nhãn red team."""
    auth, red = AUTH_PARQUET.as_posix(), REDTEAM_PARQUET.as_posix()
    con.execute(f"""
        COPY (
            WITH red_users AS (SELECT DISTINCT user FROM '{red}'),
                 users AS (
                     SELECT DISTINCT a.user, (r.user IS NOT NULL) AS red_user,
                            CASE WHEN r.user IS NOT NULL THEN 1.0 ELSE {SAMPLE_MOD}.0 END AS weight
                     FROM (SELECT DISTINCT user FROM '{auth}') a LEFT JOIN red_users r USING (user)
                     WHERE r.user IS NOT NULL OR hash(a.user) % {SAMPLE_MOD} = 0),
                 red AS (SELECT DISTINCT t, user, src_pc, dst_pc, TRUE AS is_red FROM '{red}')
            SELECT a.t, a.user, a.src_pc, a.dst_pc, a.auth_type, a.logon_type, a.success, u.weight, u.red_user,
                   coalesce(r.is_red, FALSE) AS is_red
            FROM '{auth}' a JOIN users u USING (user) LEFT JOIN red r USING (t, user, src_pc, dst_pc)
            WHERE a.orientation = 'LogOn'
            ORDER BY a.user, a.t
        ) TO '{SORTED_PARQUET.as_posix()}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 1000000)
    """)


def compute() -> tuple[int, int, int]:
    """Đọc tuần tự bản đã sắp xếp, ghi đặc trưng theo từng lô (không giữ cả bảng trong bộ nhớ)."""
    reader = pq.ParquetFile(SORTED_PARQUET)
    writer = None
    n_rows = n_red = n_users = 0
    user = None
    for batch in reader.iter_batches(batch_size=1_000_000):
        cols = batch.to_pydict()
        n = len(cols["t"])
        out = {name: np.zeros(n, dtype=np.float32) for name in FEATURES}
        for i in range(n):
            u = cols["user"][i]
            if u != user:
                user, n_users = u, n_users + 1
                srcs, dsts, auths, logons = set(), set(), set(), set()
                prior = 0
                by_hour = [0] * 24
                recent = deque()  # (t, new_dst, failed) trong 1 giờ gần nhất
            t = cols["t"][i]
            src, dst = cols["src_pc"][i], cols["dst_pc"][i]
            new_src, new_dst = src not in srcs, dst not in dsts
            new_auth, new_logon = cols["auth_type"][i] not in auths, cols["logon_type"][i] not in logons
            hour = (t % 86400) // 3600
            failed = not cols["success"][i]
            while recent and recent[0][0] < t - WINDOW_S:
                recent.popleft()
            recent.append((t, new_dst, failed))
            out["new_src"][i], out["new_dst"][i] = new_src, new_dst
            out["new_auth"][i], out["new_logon"][i] = new_auth, new_logon
            out["hour_rarity"][i] = 1.0 - (by_hour[hour] + 1.0) / (prior + 2.0)
            out["events_1h"][i] = len(recent)
            out["new_dst_1h"][i] = sum(1 for e in recent if e[1])
            out["fails_1h"][i] = sum(1 for e in recent if e[2])
            out["log_prior"][i] = np.log1p(prior)
            srcs.add(src)
            dsts.add(dst)
            auths.add(cols["auth_type"][i])
            logons.add(cols["logon_type"][i])
            by_hour[hour] += 1
            prior += 1
        table = pa.table({
            "t": cols["t"], "day": [t // 86400 + 1 for t in cols["t"]], "user": cols["user"], "auth_type": cols["auth_type"],
            "weight": cols["weight"], "red_user": cols["red_user"], "is_red": cols["is_red"], **{k: v for k, v in out.items()},
        })
        writer = writer or pq.ParquetWriter(FEATURES_PARQUET, table.schema, compression="zstd")
        writer.write_table(table)
        n_rows += n
        n_red += sum(cols["is_red"])
        print(f"  {n_rows:,} sự kiện", flush=True)
    if writer is not None:
        writer.close()
    return n_rows, n_red, n_users


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    started = time.perf_counter()
    con = duckdb.connect()
    con.execute(f"SET temp_directory = '{(DATA_DIR / 'duckdb_tmp').as_posix()}'")
    con.execute("SET memory_limit = '6GB'")
    sort_sample(con)
    print(f"đã sắp xếp mẫu ({time.perf_counter() - started:,.0f} s)", flush=True)
    rows, red, users = compute()
    print(f"features.parquet: {rows:,} sự kiện ({users:,} người dùng trong mẫu), {red:,} sự kiện red team; "
          f"{time.perf_counter() - started:,.0f} s", flush=True)


if __name__ == "__main__":
    main()
