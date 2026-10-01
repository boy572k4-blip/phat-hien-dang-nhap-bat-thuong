"""app/utils/geo.py — khoảng cách great-circle (chuyển từ app/detection/rules.py của tầng 1 khi xoá tầng 1 ở MR21)."""

from app.utils.geo import haversine_distance


def test_haversine_distance_known_value():
    # 1 độ kinh độ tại xích đạo ~ 111.19 km (bán kính Trái Đất 6371km).
    assert abs(haversine_distance(0, 0, 0, 1) - 111.19) < 0.5


def test_haversine_distance_same_point_is_zero():
    assert haversine_distance(21.03, 105.85, 21.03, 105.85) == 0


def test_haversine_distance_hanoi_to_new_york_is_about_13_thousand_km():
    assert 12_500 < haversine_distance(21.03, 105.85, 40.71, -74.01) < 13_500
