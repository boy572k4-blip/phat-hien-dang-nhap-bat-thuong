"""Tính toán địa lý dùng chung: khoảng cách great-circle giữa hai toạ độ.

Trước MR21 nằm trong `app/detection/rules.py` (tầng 1, đã xoá); luật `impossible_travel` của rule engine v2
(`app/detection/engine/rules_context.py`) và đặc trưng ML tầng 3 (`ml/features.py`) đều dùng hàm này.
"""

from __future__ import annotations

import math

EARTH_RADIUS_KM = 6371.0


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Khoảng cách great-circle giữa 2 toạ độ (km)."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))
