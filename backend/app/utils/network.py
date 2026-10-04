"""Xác định IP nguồn của request (nhiệm vụ 6.1 — cần cho
scripts/impossible_travel giả lập IP nguồn khác nhau qua header khi demo).

MR32: header `X-Forwarded-For` chỉ được tin khi (1) `TRUST_FORWARDED_FOR=true` VÀ (2) kết nối TCP đến từ một máy trong
`TRUSTED_PROXIES` (mặc định chỉ chính máy chạy backend). Đọc từ PHẢI sang trái, bỏ qua các proxy tin cậy: mỗi proxy NỐI địa chỉ nó
thấy vào cuối header, còn phần đầu do client tự khai — lấy phần tử đầu tiên (như trước MR32) thì kể cả khi đứng sau reverse proxy
thật, client vẫn tự chọn được IP nguồn. Phần tử không phải địa chỉ IP hợp lệ -> dùng IP TCP.
"""

from __future__ import annotations

import ipaddress

from fastapi import Request

from app.config import get_settings


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def resolve_client_ip(request: Request) -> str:
    """Mặc định dùng IP TCP thật. Chỉ đọc X-Forwarded-For khi
    `TRUST_FORWARDED_FOR=true` được bật tường minh trong .env (xem cảnh
    báo trong app/config.py) và kết nối đến từ proxy tin cậy.
    """
    peer = request.client.host if request.client else "unknown"
    settings = get_settings()
    trusted = settings.trusted_proxy_hosts
    if not settings.trust_forwarded_for or peer not in trusted:
        return peer

    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer
    hops = [hop.strip() for hop in forwarded.split(",")]
    for hop in reversed(hops):
        ip = _valid_ip(hop)
        if ip is None:
            return peer
        if ip not in trusted:
            return ip
    return peer
