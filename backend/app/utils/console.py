"""MR33 — in tiếng Việt ra console Windows không lỗi.

Khi stdout bị chuyển hướng (pipe, file, công cụ chạy nền) Python trên Windows dùng mã trang của hệ thống (cp1252), và `print` một chuỗi có
dấu như "Đã tạo admin" ném `UnicodeEncodeError` — script dừng giữa chừng dù việc chính đã xong. Trước MR33 phải đặt `PYTHONIOENCODING=utf-8`
trước mỗi lệnh. Gọi từ `scripts/__init__.py` và `ml/__init__.py` nên mọi `python -m scripts.…`/`python -m ml.…` đều được áp dụng.
"""

from __future__ import annotations

import sys


def use_utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError, OSError):  # luồng đã bị thay (pytest, IDE) — giữ nguyên
            pass
