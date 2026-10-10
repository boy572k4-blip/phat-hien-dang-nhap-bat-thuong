"""MR36 — chạy lần lượt 7 kịch bản tấn công cho buổi demo, có lời dẫn và dừng chờ giữa các bước.

Mỗi kịch bản nhắm MỘT tài khoản riêng và đến từ MỘT IP giả riêng (qua X-Forwarded-For) — cảnh báo không bị gộp vào nhau (một sự cố trên
cùng tài khoản = một cảnh báo, MR23) và khoá tự động không rơi vào máy người trình bày. Chạy trên dữ liệu demo sạch (demo\\reset.ps1),
dashboard mở sẵn để xem cảnh báo hiện real-time.

    cd attack-sim
    ..\\backend\\venv\\Scripts\\python.exe demo_all.py            # dừng chờ Enter giữa các kịch bản
    ..\\backend\\venv\\Scripts\\python.exe demo_all.py --auto 8   # tự chạy, nghỉ 8 giây giữa các kịch bản
    ..\\backend\\venv\\Scripts\\python.exe demo_all.py --only 4   # chỉ chạy kịch bản 4
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys
import time
from pathlib import Path

from common import BROWSER_UA, DEFAULT_BASE_URL

import httpx

HERE = Path(__file__).resolve().parent
THREAT_INTEL = HERE.parent / "backend" / "threat_intel"
PASSWORD = "Demo@12345"


def _first_entry(name: str) -> str:
    for line in (THREAT_INTEL / name).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    raise SystemExit(f"{name} rỗng — chạy backend\\venv\\Scripts\\python.exe -m scripts.update_threat_feeds")


def _login(base_url: str, username: str, password: str, ip: str) -> str:
    with httpx.Client(timeout=15.0, headers={"user-agent": BROWSER_UA, "x-forwarded-for": ip}) as client:
        response = client.post(f"{base_url}/login", json={"username": username, "password": password})
    body = response.json()
    if response.status_code == 423:
        return "423 — bị KHOÁ"
    if body.get("step_up_required"):
        return f"200 — phải nhập OTP (mã demo {body.get('demo_otp_code')})"
    return f"{response.status_code} — {'đăng nhập thành công' if body.get('success') else body.get('message')}"


def _script(name: str, *args: str) -> None:
    sys.stdout.flush()  # lời dẫn in TRƯỚC đầu ra của script con (khi đầu ra bị chuyển hướng, stdout có bộ đệm)
    subprocess.run([sys.executable, str(HERE / name), *args], check=False)


def scenarios(base_url: str, delay: str) -> list[tuple[str, str, str, callable]]:
    common = ["--base-url", base_url, "--delay", delay]
    tor_ip = _first_entry("tor_exit_ips.txt")
    datacenter_ip = str(ipaddress.ip_network(_first_entry("datacenter_cidrs.txt"), strict=False).network_address + 10)
    return [
        ("Dò mật khẩu một tài khoản", "6 lần sai mật khẩu vào user011 từ IP 203.0.113.10",
         "cảnh báo 'Dò mật khẩu' (luật brute_force) — chỉ cảnh báo, không khoá: đa số là người quên mật khẩu",
         lambda: _script("brute_force.py", "--target", "user011", *common)),
        ("Dò danh sách tài khoản", "12 tên đăng nhập không tồn tại từ một IP 203.0.113.20",
         "cảnh báo 'Đoán và dò mật khẩu' (username_enumeration); IP nguồn bị KHOÁ — các lần cuối nhận 423; panel 'Khoá tạm & chặn' có IP",
         lambda: _script("credential_stuffing.py", *common)),
        ("Đoán trúng mật khẩu sau chuỗi sai", "5 lần sai rồi 1 lần đúng vào user012 từ IP 203.0.113.30",
         "lần đúng KHÔNG vào được: phải nhập OTP (success_after_failures), hoặc bị khoá hẳn nếu mô hình học máy cũng thấy lạ — điểm ML phụ "
         "thuộc giờ/thứ lúc chạy nên có lúc ra OTP, có lúc ra khoá",
         lambda: _script("success_after_fail.py", "--target", "user012", "--correct-password", PASSWORD, *common)),
        ("Di chuyển bất khả thi", "user013 đăng nhập ở TP.HCM rồi vài giây sau ở Brisbane (Úc)",
         "cảnh báo 'Cách ~6.500 km chỉ sau 0 phút' (impossible_travel), lần thứ hai bị khoá, bản đồ vẽ đường nối",
         lambda: _script("impossible_travel.py", "--target", "user013", "--password", PASSWORD, *common)),
        ("Đăng nhập qua Tor", f"user014 đăng nhập ĐÚNG mật khẩu từ nút thoát Tor {tor_ip}",
         "cảnh báo 'Danh tiếng hạ tầng' (tor_exit) — mật khẩu đúng vẫn bị khoá",
         lambda: print(f"  user014 từ {tor_ip}: {_login(base_url, 'user014', PASSWORD, tor_ip)}")),
        ("Công cụ tự động (script)", "user015 bị thử mật khẩu bằng script python-httpx từ IP 203.0.113.50",
         "cảnh báo 'Tự động hoá' (scripted_client) — khoá ngay lần thử đầu",
         lambda: _script("brute_force.py", "--target", "user015", "--attempts", "2", "--tool-ua", "--source-ip", "203.0.113.50", *common)),
        ("Mật khẩu đúng nhưng qua datacenter + thiết bị lạ", f"user016 đăng nhập ĐÚNG mật khẩu từ máy chủ thuê {datacenter_ip}",
         "phải nhập OTP (hoặc bị khoá nếu điểm vượt 70) — cảnh báo 'Danh tiếng hạ tầng': người có mật khẩu bị lộ thường giấu nguồn bằng VPN/VPS",
         lambda: print(f"  user016 từ {datacenter_ip}: {_login(base_url, 'user016', PASSWORD, datacenter_ip)}")),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--delay", default="0.4", help="giây nghỉ giữa các request trong một kịch bản")
    parser.add_argument("--auto", type=float, default=None, help="không chờ Enter: nghỉ chừng này giây giữa các kịch bản")
    parser.add_argument("--only", type=int, default=None, help="chỉ chạy kịch bản số này (1-7)")
    args = parser.parse_args()

    try:
        httpx.get(f"{args.base_url}/health", timeout=5.0).raise_for_status()
    except httpx.HTTPError:
        raise SystemExit(f"Backend {args.base_url} không trả lời — chạy demo\\start.ps1 trước.")

    items = scenarios(args.base_url, args.delay)
    chosen = [(i, s) for i, s in enumerate(items, 1) if args.only in (None, i)]
    for n, (i, (title, attack, expect, run)) in enumerate(chosen):
        print(f"\n=== Kịch bản {i}/{len(items)}: {title}")
        print(f"  Tấn công : {attack}")
        print(f"  Quan sát : {expect}", flush=True)
        run()
        if n < len(chosen) - 1:
            if args.auto is None:
                input("\n  [Enter] để sang kịch bản tiếp theo...")
            else:
                time.sleep(args.auto)
    print("\nXong. Dashboard: mỗi kịch bản một cảnh báo; 'Chiến dịch' gom theo IP; 'Khoá tạm & chặn' có nút mở khoá.")


if __name__ == "__main__":
    main()
