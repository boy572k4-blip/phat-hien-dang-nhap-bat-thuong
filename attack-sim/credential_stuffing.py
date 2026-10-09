"""Giả lập credential stuffing: thử NHIỀU username khác nhau từ CÙNG một
IP (nhiệm vụ 6.1). Kỳ vọng: dashboard nổi alert `credential_stuffing`.

Ngưỡng backend (backend/app/detection/rules.py):
  CREDENTIAL_STUFFING_FAIL_THRESHOLD = 10 lần fail / 5 phút
  CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES = 5 username khác nhau
Mặc định bắn 12 username để vượt cả 2 ngưỡng cùng lúc.

Chạy:
    python credential_stuffing.py
"""

from __future__ import annotations

import argparse
import time

from common import add_common_args, make_client

DEFAULT_VICTIM_COUNT = 12


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--victims", type=int, default=DEFAULT_VICTIM_COUNT, help="Số username khác nhau sẽ thử")
    parser.add_argument("--prefix", default="stuffing_victim", help="Tiền tố username giả")
    add_common_args(parser, default_source_ip="203.0.113.20")  # TEST-NET-3 (RFC 5737): IP giả, không thuộc ai
    args = parser.parse_args()

    print(f"[credential_stuffing] Thử {args.victims} username khác nhau, cùng 1 IP nguồn...")
    with make_client(args) as client:
        for i in range(1, args.victims + 1):
            username = f"{args.prefix}_{i}"
            response = client.post(
                f"{args.base_url}/login",
                json={"username": username, "password": "doan-mo-khong-biet"},
            )
            print(f"  {username}: HTTP {response.status_code}")
            time.sleep(args.delay)

    print("[credential_stuffing] Xong. Dashboard -> cảnh báo nhóm 'Đoán và dò mật khẩu' (tên không tồn tại -> username_enumeration) và IP nguồn bị khoá (423).")


if __name__ == "__main__":
    main()
