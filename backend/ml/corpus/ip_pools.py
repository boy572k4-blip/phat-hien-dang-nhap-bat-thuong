"""Kho IP THẬT cho bộ dữ liệu hiệu chỉnh (MR24): lấy mẫu có seed trong các dải của nhà mạng, rồi CHỈ giữ IP mà cơ sở GeoIP
trên máy (GeoLite2-City/ASN, `app/detection/geoip.py`) xác nhận đúng quốc gia + ASN kỳ vọng và có toạ độ — không bịa IP, không
gán tay quốc gia. IP ẩn danh lấy từ chính các danh sách tình báo đã tải (`backend/threat_intel/`, MR9).

Kết quả phụ thuộc phiên bản GeoLite trên máy (đổi bản cập nhật thì kho có thể đổi) — bộ dữ liệu ghi lại quốc gia/ASN/thành phố
của từng IP đã dùng nên vẫn tra lại được."""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

THREAT_INTEL_DIR = Path(__file__).resolve().parents[2] / "threat_intel"
POOL_SIZE = 30

# tên kho -> (dải ứng viên, quốc gia kỳ vọng, ASN kỳ vọng — None = chấp nhận mọi ASN của quốc gia đó)
_SPECS: dict[str, tuple[tuple[str, ...], str, frozenset[int] | None]] = {
    "vn_fpt": (("42.112.0.0/13", "118.68.0.0/14", "210.245.0.0/17", "1.52.0.0/14"), "VN", frozenset({18403})),
    "vn_vnpt": (("14.160.0.0/11", "113.160.0.0/11", "123.16.0.0/12"), "VN", frozenset({45899})),
    "vn_viettel": (("27.64.0.0/12", "171.224.0.0/11", "116.96.0.0/12", "125.234.0.0/15"), "VN", frozenset({7552, 24086})),
    "us": (("73.0.0.0/8", "24.0.0.0/8", "98.0.0.0/8"), "US", None),
    "sg": (("116.86.0.0/15", "175.156.0.0/14"), "SG", None),
    "th": (("49.228.0.0/14", "171.96.0.0/13"), "TH", None),
    "kr": (("211.36.0.0/14", "121.128.0.0/10"), "KR", None),
    "cn": (("116.224.0.0/12", "58.32.0.0/11"), "CN", None),
    "de": (("79.192.0.0/10", "91.0.0.0/10"), "DE", None),
    "ru": (("95.24.0.0/13", "178.64.0.0/13"), "RU", None),
}
VN_POOLS = ("vn_fpt", "vn_vnpt", "vn_viettel")
FOREIGN_POOLS = ("us", "sg", "th", "kr", "cn", "de", "ru")
TRAVEL_POOLS = ("sg", "th", "kr")  # điểm đến công tác/du lịch gần, hợp lý cho người dùng Việt Nam
ANONYMIZER_POOLS = ("tor", "datacenter", "vpn")
VN_DATACENTER_POOLS = ("datacenter_vn",)  # MR29: dải datacenter (danh sách threat_intel) đặt ở Việt Nam — VPS thuê trong nước


@dataclass(frozen=True)
class IpInfo:
    ip: str
    pool: str
    country: str | None
    city: str | None
    asn: int | None
    latitude: float | None
    longitude: float | None


def _random_host(net: ipaddress.IPv4Network, rng: random.Random) -> str:
    return str(net.network_address + rng.randrange(1, max(2, net.num_addresses - 1)))


def _geo_pool(name: str, size: int) -> tuple[IpInfo, ...]:
    from app.detection.geoip import lookup_asn, lookup_ip

    nets, country, asns = _SPECS[name]
    rng = random.Random(f"ip-pool:{name}")
    found: list[IpInfo] = []
    seen: set[str] = set()
    for _ in range(size * 40):
        if len(found) >= size:
            break
        ip = _random_host(ipaddress.ip_network(rng.choice(nets)), rng)
        if ip in seen:
            continue
        seen.add(ip)
        geo, asn = lookup_ip(ip), lookup_asn(ip)
        if geo is None or asn is None or geo.country != country or geo.city is None or geo.latitude is None:
            continue
        if asns is not None and asn.asn not in asns:
            continue
        found.append(IpInfo(ip, name, geo.country, geo.city, asn.asn, geo.latitude, geo.longitude))
    return tuple(found)


def _intel_pool(name: str, size: int) -> tuple[IpInfo, ...]:
    from app.detection.geoip import lookup_asn, lookup_ip

    rng = random.Random(f"ip-pool:{name}")
    if name == "tor":
        lines = [line.strip() for line in (THREAT_INTEL_DIR / "tor_exit_ips.txt").read_text(encoding="utf-8").splitlines()]
        ips = [ip for ip in lines if ip and not ip.startswith("#") and ":" not in ip]
        chosen = rng.sample(ips, min(size, len(ips)))
    else:
        file = {"datacenter": "datacenter_cidrs.txt", "vpn": "vpn_cidrs.txt"}[name]
        lines = [line.strip() for line in (THREAT_INTEL_DIR / file).read_text(encoding="utf-8").splitlines()]
        nets = [ipaddress.ip_network(c) for c in lines if c and not c.startswith("#") and ":" not in c]
        chosen = [_random_host(rng.choice(nets), rng) for _ in range(size)]
    out = []
    for ip in chosen:
        geo, asn = lookup_ip(ip), lookup_asn(ip)
        out.append(IpInfo(ip, name, geo.country if geo else None, geo.city if geo else None, asn.asn if asn else None,
                          geo.latitude if geo else None, geo.longitude if geo else None))
    return tuple(out)


def _vn_datacenter_pool(size: int) -> tuple[IpInfo, ...]:
    """MR29: IP trong các dải datacenter của danh sách threat_intel mà GeoLite đặt ở Việt Nam (VPS/đám mây trong nước) — kẻ tấn công "ở cùng
    nước" với nạn nhân. Không đòi có thành phố (dải hosting thường chỉ định vị được quốc gia)."""
    from app.detection.geoip import lookup_asn, lookup_ip

    rng = random.Random("ip-pool:datacenter_vn")
    lines = [line.strip() for line in (THREAT_INTEL_DIR / "datacenter_cidrs.txt").read_text(encoding="utf-8").splitlines()]
    nets = [ipaddress.ip_network(c) for c in lines if c and not c.startswith("#") and ":" not in c]

    def first_host(net):
        return str(net.network_address + 1) if net.num_addresses > 2 else str(net.network_address)

    vn = [net for net in nets if (geo := lookup_ip(first_host(net))) is not None and geo.country == "VN"]
    found, seen = [], set()
    for _ in range(size * 40):
        if len(found) >= size or not vn:
            break
        ip = _random_host(rng.choice(vn), rng)
        if ip in seen:
            continue
        seen.add(ip)
        geo, asn = lookup_ip(ip), lookup_asn(ip)
        if geo is None or geo.country != "VN":
            continue
        found.append(IpInfo(ip, "datacenter_vn", "VN", geo.city, asn.asn if asn else None, geo.latitude, geo.longitude))
    return tuple(found)


@lru_cache(maxsize=1)
def build_pools(size: int = POOL_SIZE) -> dict[str, tuple[IpInfo, ...]]:
    """Mọi kho IP, xác định theo seed (cùng máy, cùng bản GeoLite -> cùng kết quả). Lỗi rõ ràng nếu thiếu GeoLite."""
    pools = {name: _geo_pool(name, size) for name in _SPECS}
    pools.update({name: _intel_pool(name, size) for name in ANONYMIZER_POOLS})
    pools["datacenter_vn"] = _vn_datacenter_pool(size)
    empty = [name for name, ips in pools.items() if len(ips) < 5]
    if empty:
        raise RuntimeError(f"Kho IP quá nhỏ {empty} — thiếu cơ sở GeoLite2 (backend/geoip/) hoặc danh sách threat_intel?")
    return pools
