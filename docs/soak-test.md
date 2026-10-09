# Soak test — tải nhẹ liên tục (MR19, chạy lại ở MR34)

Chạy thật 60 phút, nhịp mục tiêu 1 request/giây, luân phiên 25 tài khoản demo (user001-025), 90% mật khẩu đúng / 10% sai — không dùng lại một tài khoản như `benchmark_login.py` để tránh tự làm phình lịch sử của chính tài khoản đang đo (xem `docs/performance.md`).

## Tổng quan

- Tổng số request `/login`: **3599**
- Tổng số request `/health` (xen kẽ, 1/10 vòng lặp): **359**
- Request `/login` có status KHÔNG mong đợi (khác 200/401/423): **0**
- Request `/health` khác 200: **0**
- Số lần bị khoá (423 — hành vi ĐÚNG như thiết kế nếu brute_force vô tình chạm ngưỡng, không tính là lỗi): **0**
- Xu hướng độ trễ median theo thời gian (cửa sổ 2 phút, so cụm đầu với cụm cuối): **+203.5 ms (median cửa sổ cuối trừ cửa sổ đầu)**
- Bộ nhớ tiến trình server (MR34): đầu **290.3 MB**, cuối **211.5 MB**, thấp nhất 211.4 MB, cao nhất 290.5 MB (359 lần đo)

## Theo cửa sổ 2 phút

| Phút bắt đầu | Số request | Median (ms) | p95 (ms) | Bị khoá (423) | Status lạ | Bộ nhớ server (MB) |
|---|---|---|---|---|---|---|
| 0.0 | 120 | 311.3 | 348.7 | 0 | 0 | 290.3 |
| 2.0 | 120 | 314.6 | 359.2 | 0 | 0 | 290.5 |
| 4.0 | 120 | 315.3 | 573.1 | 0 | 0 | 290.4 |
| 6.0 | 120 | 317.5 | 580.7 | 0 | 0 | 290.5 |
| 8.0 | 120 | 319.5 | 589.9 | 0 | 0 | 290.5 |
| 10.0 | 120 | 321.7 | 582.2 | 0 | 0 | 290.5 |
| 12.0 | 120 | 323.0 | 585.4 | 0 | 0 | 290.5 |
| 14.0 | 120 | 328.9 | 580.7 | 0 | 0 | 290.5 |
| 16.0 | 120 | 555.5 | 584.4 | 0 | 0 | 290.5 |
| 18.0 | 120 | 561.4 | 582.3 | 0 | 0 | 290.5 |
| 20.0 | 120 | 563.0 | 578.3 | 0 | 0 | 290.5 |
| 22.0 | 120 | 569.3 | 582.9 | 0 | 0 | 287.8 |
| 24.0 | 120 | 571.9 | 603.0 | 0 | 0 | 281.9 |
| 26.0 | 120 | 571.2 | 587.7 | 0 | 0 | 277.1 |
| 28.0 | 120 | 563.2 | 583.6 | 0 | 0 | 277.1 |
| 30.0 | 120 | 566.2 | 595.9 | 0 | 0 | 241.1 |
| 32.0 | 120 | 571.7 | 596.1 | 0 | 0 | 215.4 |
| 34.0 | 120 | 563.2 | 586.6 | 0 | 0 | 215.2 |
| 36.0 | 120 | 571.4 | 591.6 | 0 | 0 | 212.9 |
| 38.0 | 119 | 560.4 | 583.5 | 0 | 0 | 213.0 |
| 40.0 | 120 | 564.0 | 591.0 | 0 | 0 | 212.4 |
| 42.0 | 120 | 562.9 | 578.8 | 0 | 0 | 212.0 |
| 44.0 | 120 | 566.1 | 591.1 | 0 | 0 | 212.0 |
| 46.0 | 120 | 570.7 | 601.1 | 0 | 0 | 211.7 |
| 48.0 | 120 | 567.4 | 594.6 | 0 | 0 | 211.7 |
| 50.0 | 120 | 570.6 | 588.5 | 0 | 0 | 211.6 |
| 52.0 | 120 | 574.2 | 607.6 | 0 | 0 | 211.4 |
| 54.0 | 120 | 572.3 | 585.5 | 0 | 0 | 211.4 |
| 56.0 | 120 | 577.9 | 654.8 | 0 | 0 | 211.5 |
| 58.0 | 120 | 577.3 | 600.9 | 0 | 0 | 211.5 |

## Đọc kết quả

- **Tỉ lệ lỗi thật** = status không mong đợi (khác 200 thành công / 401 sai mật khẩu / 423 khoá đúng thiết kế) chia cho tổng request — 0 nghĩa là không có request nào thất bại ngoài dự kiến trong suốt phiên.
- **Rò rỉ/suy giảm** biểu hiện qua median TĂNG DẦN đơn điệu qua các cửa sổ — một vài cửa sổ nhiễu cao hơn cửa sổ khác là bình thường (GC, cache miss định kỳ của `GlobalCountsCache`, xem `docs/performance.md`), xu hướng tăng liên tục nhiều cửa sổ liên tiếp mới đáng lo.
- Đây là tải THẤP có chủ đích (khác benchmark tải cao ngắn hạn) — mục tiêu là phát hiện suy giảm theo THỜI GIAN, không phải theo TẢI (đã đo riêng ở `docs/performance.md`).

## MR34 — đọc lần chạy 60 phút

- **Ổn định:** 3.599 lần đăng nhập + 359 lần `/health`, **0 lỗi, 0 timeout** (MR19, 12 phút: 1 timeout). **Không rò rỉ bộ nhớ**: tiến
  trình server 290 MB lúc đầu, giảm về 211 MB sau phút 30 và giữ nguyên tới cuối.
- **Độ trễ tăng bậc ở phút 16 (~320 → ~560 ms) KHÔNG phải suy giảm** mà do chính phát hiện: 25 tài khoản ở nhịp 1 request/giây = mỗi
  tài khoản ~22 lần thành công/10 phút từ một IP suốt một giờ — luật `success_burst` (≥ 8 lần thành công/10 phút, MR27) cùng hai mô hình
  đẩy dần các lần đăng nhập lên "xác thực thêm" (tỉ lệ trong DB tạm theo 4 phút: 0% → 1% → 8% → 24% → 44% → 51% → … → 88–91%). Mỗi lần
  đòi OTP băm mã bằng bcrypt (~230 ms) → p95 nhảy khi tỉ lệ vượt 5% (phút 4), trung vị nhảy khi vượt 50% (phút 16) — đúng hai mốc
  trong bảng. Không lần nào bị khoá.
- Hệ quả cho cách đo: soak muốn đo riêng nền tảng (không lẫn phát hiện) cần nhiều tài khoản hơn hẳn để mỗi tài khoản đăng nhập thưa như
  người thật — ghi lại cho lần đo sau.
