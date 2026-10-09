"""Giả lập brute force: gửi liên tục request sai mật khẩu tới CÙNG một
tài khoản (nhiệm vụ 6.1). Kỳ vọng: dashboard nổi cảnh báo "Dò mật khẩu" (luật `brute_force`).

Ngưỡng: luật `brute_force` 5 lần sai / 5 phút (backend/app/detection/engine/rules_auth.py, mức tối thiểu "alert" — chỉ cảnh
báo, không khoá vì đa số là người quên mật khẩu) — mặc định bắn 6 lần để chắc chắn vượt.

Chạy:
    python brute_force.py --target user001
"""

from __future__ import annotations

import argparse
import time

from common import add_common_args, make_client

DEFAULT_ATTEMPTS = 6


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Username bị tấn công")
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    add_common_args(parser, default_source_ip="203.0.113.10")  # TEST-NET-3 (RFC 5737): IP giả, không thuộc ai
    args = parser.parse_args()

    print(f"[brute_force] Bắn {args.attempts} lần sai mật khẩu vào tài khoản '{args.target}'...")
    with make_client(args) as client:
        for i in range(1, args.attempts + 1):
            response = client.post(
                f"{args.base_url}/login",
                json={"username": args.target, "password": f"mat-khau-sai-{i}"},
            )
            print(f"  lần {i}/{args.attempts}: HTTP {response.status_code}")
            time.sleep(args.delay)

    print("[brute_force] Xong. Dashboard -> cảnh báo 'Dò mật khẩu' (luật brute_force) cho tài khoản này.")


if __name__ == "__main__":
    main()
