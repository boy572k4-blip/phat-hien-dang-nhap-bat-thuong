"""Giả lập chuỗi fail rồi đăng nhập ĐÚNG ngay sau đó (nhiệm vụ 6.1). Kỳ
vọng: risk_score tăng vọt (+50, xem SUCCESS_AFTER_FAIL_STREAK_WEIGHT ở
backend/app/detection/scoring.py) và alert `high_risk_score` xuất hiện
ngay ở lần đăng nhập cuối cùng.

Cần MẬT KHẨU ĐÚNG của tài khoản để demo — user sinh bởi
scripts/generate_labeled_anomalies.py dùng chung mật khẩu Demo@12345.

Ngưỡng backend: SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS = 3 — mặc định bắn 4
lần fail để chắc chắn vượt.

Chạy:
    python success_after_fail.py --target user001 --correct-password Demo@12345
"""

from __future__ import annotations

import argparse
import time

from common import add_common_args, make_client

DEFAULT_FAIL_COUNT = 5  # MR34: đúng ngưỡng min_fails = 5 của luật success_after_failures (4 lần thì luật không chạy)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Username")
    parser.add_argument("--correct-password", required=True, help="Mật khẩu ĐÚNG của tài khoản")
    parser.add_argument("--fail-count", type=int, default=DEFAULT_FAIL_COUNT)
    add_common_args(parser, default_source_ip="203.0.113.30")  # TEST-NET-3 (RFC 5737): IP giả, không thuộc ai
    args = parser.parse_args()

    print(f"[success_after_fail] {args.fail_count} lần sai rồi 1 lần đúng cho '{args.target}'...")
    with make_client(args) as client:
        for i in range(1, args.fail_count + 1):
            client.post(f"{args.base_url}/login", json={"username": args.target, "password": f"sai-{i}"})
            print(f"  fail {i}/{args.fail_count}")
            time.sleep(args.delay)

        response = client.post(
            f"{args.base_url}/login",
            json={"username": args.target, "password": args.correct_password},
        )
        print(f"  đăng nhập ĐÚNG: HTTP {response.status_code} -> {response.json()}")

    print("[success_after_fail] Xong. Lần đúng phải bị bắt xác thực thêm (step_up_required, luật success_after_failures) + cảnh báo trên dashboard.")


if __name__ == "__main__":
    main()
