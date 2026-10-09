"""Tham số & helper dùng chung cho 4 script giả lập tấn công (nhiệm vụ 6.1).

Dùng chung venv của backend (đã có httpx cài sẵn từ Tuần 1 cho test):

    cd backend && venv\\Scripts\\activate
    cd ..\\attack-sim
    python brute_force.py --target user001

Tốc độ gửi request (--delay, giây nghỉ giữa mỗi lần) và số lần thử tham
số hoá ở đầu mỗi file / qua CLI — chỉnh để phù hợp trình diễn trực tiếp
(không quá nhanh để người xem kịp theo dõi trên dashboard, không quá chậm
làm mất thời gian).
"""

from __future__ import annotations

import argparse
import sys

import httpx

# MR34: 127.0.0.1 thay "localhost" (Windows thử IPv6 trước, +2 s mỗi kết nối mới — docs/performance.md); in tiếng Việt không cần
# đặt PYTHONIOENCODING (console Windows mặc định cp1252 ném UnicodeEncodeError).
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
DEFAULT_DELAY_SECONDS = 0.4


# MR34: User-Agent của trình duyệt thật làm mặc định — UA mặc định của httpx khớp luật `scripted_client` và khoá ngay lần thử đầu,
# nên mọi kịch bản chỉ còn hiện "client kịch bản" thay vì tín hiệu riêng của nó. `--tool-ua` để trình diễn đúng phát hiện đó.
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def add_common_args(parser: argparse.ArgumentParser, default_source_ip: str | None = None) -> None:
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Địa chỉ backend")
    # MR34: IP kẻ tấn công giả lập qua X-Forwarded-For (cần TRUST_FORWARDED_FOR=true, mặc định khi demo). Không có thì mọi kịch bản
    # đến từ 127.0.0.1 — chính máy người trình bày — và khoá tự động theo IP khoá luôn form đăng nhập của người trình bày 30 phút.
    parser.add_argument("--source-ip", default=default_source_ip, help="IP nguồn giả lập (mặc định %(default)s)")
    parser.add_argument("--tool-ua", action="store_true", help="gửi User-Agent mặc định của httpx (công cụ tự động) thay vì trình duyệt")
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_SECONDS,
        help="Giây nghỉ giữa mỗi request — chỉnh tốc độ demo (mặc định %(default)s)",
    )


def make_client(args: argparse.Namespace) -> httpx.Client:
    headers = {} if args.tool_ua else {"user-agent": BROWSER_UA}
    if args.source_ip:
        headers["x-forwarded-for"] = args.source_ip
    return httpx.Client(timeout=10.0, headers=headers)
