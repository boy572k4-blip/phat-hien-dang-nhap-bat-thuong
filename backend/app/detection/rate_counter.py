"""Kết nối Redis dùng chung cho phần phát hiện.

Tuần 3 (nhiệm vụ 3.2) module này chứa bộ đếm cửa sổ trượt riêng của tầng 1 (sorted set: đếm lần sai theo tài khoản/IP,
số tên đăng nhập khác nhau của một IP). Từ MR21 tầng 1 đã gộp vào rule engine v2: mọi cửa sổ thời gian giờ nằm ở
`app/detection/engine/state.py` (`RedisStore`, cùng kỹ thuật sorted set + cắt theo thời gian SỰ KIỆN, có TTL để khoá không
sống mãi) — module này chỉ còn giữ MỘT kết nối Redis mà `rule_engine_runtime.build_rule_engine` dùng. Giữ tên module để
test và các script mô phỏng thay `redis_client` bằng fakeredis ở đúng một chỗ như trước.
"""

from __future__ import annotations

import redis

from app.config import get_settings

_settings = get_settings()
redis_client = redis.Redis.from_url(_settings.redis_url, decode_responses=True)
