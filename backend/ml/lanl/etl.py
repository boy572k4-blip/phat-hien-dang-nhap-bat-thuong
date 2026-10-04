"""MR31 — ETL: `auth.txt.gz` (~1,05 tỉ sự kiện, 7,6 GB nén) -> parquet chỉ gồm sự kiện của TÀI KHOẢN NGƯỜI DÙNG (`U…@DOM…`).

Bỏ tài khoản máy (`C…$@…`), `SYSTEM`, `LOCAL SERVICE`, `ANONYMOUS LOGON`: red team của LANL dùng thông tin đăng nhập của người dùng (`U…`),
và hệ thống đồ án cũng là phát hiện theo tài khoản người dùng. Một lượt đọc luồng bằng DuckDB (không giải nén ra đĩa, không nạp vào RAM).

    cd backend
    venv\\Scripts\\python.exe -m ml.lanl.etl        # ~vài chục phút; ghi ml/data/lanl/auth_users.parquet, redteam.parquet
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import duckdb

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "lanl"
AUTH_GZ = DATA_DIR / "auth.txt.gz"
REDTEAM_GZ = DATA_DIR / "redteam.txt.gz"
AUTH_PARQUET = DATA_DIR / "auth_users.parquet"
REDTEAM_PARQUET = DATA_DIR / "redteam.parquet"

AUTH_COLUMNS = (
    "{'t': 'BIGINT', 'src_user': 'VARCHAR', 'dst_user': 'VARCHAR', 'src_pc': 'VARCHAR', 'dst_pc': 'VARCHAR', "
    "'auth_type': 'VARCHAR', 'logon_type': 'VARCHAR', 'orientation': 'VARCHAR', 'outcome': 'VARCHAR'}"
)


def run() -> None:
    con = duckdb.connect()
    con.execute("SET preserve_insertion_order = false")
    started = time.perf_counter()
    con.execute(f"""
        COPY (
            SELECT t, split_part(src_user, '@', 1) AS user, src_pc, dst_pc, auth_type, logon_type, orientation, outcome = 'Success' AS success
            FROM read_csv('{AUTH_GZ.as_posix()}', header = false, columns = {AUTH_COLUMNS}, compression = 'gzip')
            WHERE src_user LIKE 'U%@%'
        ) TO '{AUTH_PARQUET.as_posix()}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 1000000)
    """)
    con.execute(f"""
        COPY (
            SELECT t, split_part(user_domain, '@', 1) AS user, src_pc, dst_pc
            FROM read_csv('{REDTEAM_GZ.as_posix()}', header = false, compression = 'gzip',
                          columns = {{'t': 'BIGINT', 'user_domain': 'VARCHAR', 'src_pc': 'VARCHAR', 'dst_pc': 'VARCHAR'}})
        ) TO '{REDTEAM_PARQUET.as_posix()}' (FORMAT parquet)
    """)
    rows = con.sql(f"SELECT count(*), max(t), count(DISTINCT user) FROM '{AUTH_PARQUET.as_posix()}'").fetchone()
    print(f"auth_users.parquet: {rows[0]:,} sự kiện, {rows[2]:,} người dùng, t tối đa {rows[1]:,} s ({rows[1] / 86400:.1f} ngày); "
          f"{time.perf_counter() - started:,.0f} s", flush=True)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    run()
