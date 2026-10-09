# MR34 — Nghiệm thu toàn bộ

Môi trường: máy dev Windows 11, Postgres 16 + Redis 7 (Docker), backend uvicorn một tiến trình. Mọi phép đo trên hệ thống chạy thật
dùng **bản sao DB tạm** (`lad_bench`, khôi phục từ DB dev) và Redis db 1, xoá sau khi đo — DB dev không bị ghi thêm. Tài khoản quản trị
thử tạo riêng trong bản sao.

## 1. Kiểm thử hồi quy và độ phủ

- **900/900 test qua** (`pytest`, SQLite + fakeredis, không cần Docker).
- **Độ phủ** (`pytest --cov`, coverage 7.16 — cài ở MR34):

| Phần | Dòng được chạy / tổng | Độ phủ |
|---|---|---|
| `app/` — router, cấu hình, bảo mật | 1.125 / 1.150 | **97,8%** |
| `app/detection/` — pipeline, ngữ cảnh, hybrid, phản ứng | 1.475 / 1.537 | **96,0%** |
| `app/detection/engine/` — rule engine | 1.421 / 1.458 | **97,5%** |
| `ml/rba/` — dữ liệu RBA, huấn luyện, hiệu chỉnh | 3.605 / 4.126 | 87,4% |
| `ml/corpus/` — bộ dữ liệu có nhãn, đo hành vi | 890 / 1.064 | 83,6% |
| `ml/lanl/` — kiểm chứng LANL | 134 / 204 | 65,7% |
| `ml/` gốc — mô hình địa lý–thời gian (script huấn luyện) | 389 / 783 | 49,7% |
| `scripts/` — công cụ chạy tay (benchmark, mô phỏng, sinh dữ liệu) | 400 / 1.413 | 28,3% |
| **Tổng** | **9.439 / 11.735** | **80,4%** |

  Mã chạy thật khi đăng nhập (`app/`) được phủ 96–98%; phần thấp là script dòng lệnh và script huấn luyện chạy một lần (đã kiểm bằng
  chính số đo chúng sinh ra). File thấp nhất trong `app/`: `ws_manager.py` 77,8% (nhánh client mất kết nối giữa lúc gửi), `geoip.py`
  86,6% (nhánh thiếu file GeoLite2).
- **Kiểm tra lỗi tĩnh** (`ruff check`, chỉ nhóm bắt lỗi F/E9 — cấu hình `backend/ruff.toml`): sạch sau khi sửa 7 f-string thừa, 5 biến
  và 1 import không dùng. Cảnh báo "hàm bắt biến vòng lặp" (14) đã xem từng chỗ: hàm được gọi ngay trong vòng lặp, không phải lỗi.
- Frontend: `npm run lint` (oxlint) không lỗi; `npm run build` thành công.

## 2. Kiểm thử đầu-cuối trên trình duyệt

Backend + frontend chạy thật, thao tác qua giao diện thật (form `/login`, dashboard), tấn công qua 4 script `attack-sim/` gửi HTTP thật.

| # | Thao tác | Kết quả |
|---|---|---|
| TC1 | Đăng nhập quản trị | Vào dashboard, trạng thái "Real-time" (WebSocket xác thực bằng subprotocol, MR32) ✅ |
| TC2 | Form `/login`: `user020` sai mật khẩu 5 lần rồi đúng | Bị đòi OTP; mã sai → "Mã xác thực không đúng hoặc đã hết hạn"; mã đúng → đăng nhập thành công ✅. Dashboard hiện real-time cảnh báo kèm giải thích: "Dò mật khẩu 'user020': 5 lần sai/5 phút", "Đăng nhập thành công 'user020' sau 6 lần sai/10 phút" ✅ |
| TC3 | `brute_force.py` (`user011`, 6 lần sai) | Cảnh báo `brute_force` (chỉ cảnh báo, không khoá — đúng mức tối thiểu của luật) ✅ |
| TC4 | `credential_stuffing.py` (12 tên không tồn tại, một IP) | Cảnh báo `username_enumeration`, IP nguồn bị khoá từ lần thứ 11 (423) ✅ |
| TC5 | `success_after_fail.py` (`user012`, 5 sai + 1 đúng) | Lần đúng bị đòi OTP (`success_after_failures`) ✅ |
| TC6 | `impossible_travel.py` (`user013`, TP.HCM → Brisbane) | Cảnh báo "Cách 6.566 km chỉ sau 0 phút", khoá; bản đồ vẽ đường nối ✅ |
| TC7 | Bấm "🔓 Mở khoá" cho 3 mục khoá | Panel cập nhật ngay, hết khoá ✅ |
| TC8 | Phản hồi "👍 Đúng" trên cảnh báo | "Đã xác nhận: đúng" ✅ |
| TC9 | Trang Chiến dịch, Luật, Mô hình, Hồ sơ người dùng | Hiển thị đủ (chiến dịch tự gom theo IP; trang Mô hình lần đầu mất ~5–10 giây để tính trôi dữ liệu) ✅ |
| TC10 | Log máy chủ, console trình duyệt suốt phiên | Không lỗi ✅ |

Các hành vi cần hạ tầng mạng đặc biệt (Tor, VPN, datacenter, ASN, botnet nhiều IP, đổi User-Agent...) không thao tác được qua giao
diện — đã đo trên bộ dữ liệu có nhãn 39 họ (MR24–MR29, [`behavior-coverage-matrix.md`](behavior-coverage-matrix.md)).

## 3. Hiệu năng (tài khoản mới, trạng thái sạch)

| | MR20 | MR34 |
|---|---|---|
| Tuần tự 50 lần — trung vị | 319 ms | **311 ms** (hai lượt: 310,8 / 311,3) |
| Tuần tự — p95 / max | — | 323–331 / 327–499 ms |
| 10 request đồng thời, 100 lần — trung vị / p95 / max | 542 / 855 / — ms | **448 / 791 / 830 ms** |
| Lỗi, timeout | 0 | 0 (150/150 thành công) |

Thêm 8 luật và cổng tự bảo vệ sau MR20 mà độ trễ không tăng (bcrypt ~210 ms chiếm phần lớn).

## 4. Soak test 60 phút

Chi tiết: [`soak-test.md`](soak-test.md). 1 request/giây luân phiên 25 tài khoản demo, 10% sai mật khẩu, server tạm, đo bộ nhớ tiến trình
server mỗi 10 giây.

| | MR19 (12 phút) | MR34 (60 phút) |
|---|---|---|
| Đăng nhập / `/health` | 691 / 69 | **3.599 / 359** |
| Lỗi, timeout | 1 timeout | **0** |
| Bộ nhớ server | không đo | 290 MB → 211 MB (không rò rỉ) |
| Độ trễ trung vị | 568–715 ms | 311–329 ms (16 phút đầu), ~560–575 ms sau đó |

Bước nhảy độ trễ ở phút 16 là do phát hiện, không phải suy giảm: mỗi tài khoản đăng nhập ~22 lần/10 phút suốt một giờ khớp luật
`success_burst`, tỉ lệ bị đòi OTP tăng dần tới ~90%, mỗi lần đòi OTP thêm một lần bcrypt (~230 ms) để băm mã — trung vị nhảy đúng lúc tỉ lệ
vượt 50%. Không lần nào bị khoá. Soak đo riêng nền tảng cần nhiều tài khoản hơn để mỗi tài khoản đăng nhập thưa như người thật.

## 5. Lỗi tìm thấy và đã sửa

| # | Mức | Lỗi | Sửa |
|---|---|---|---|
| L1 | **Chặn demo** | Đang đăng nhập dashboard, chỉ cần gõ sai mật khẩu ở form `/login` (cùng trình duyệt) là quản trị viên bị đăng xuất: bộ chặn 401 của MR32 coi 401 "sai mật khẩu" là token hết hạn; gốc rễ là frontend gắn token quản trị vào **mọi** request, kể cả `/login` công khai | Không gắn token cho route công khai; chỉ tự đăng xuất khi chính request bị 401 có mang token. Kiểm lại: sai 5 lần, admin vẫn đăng nhập |
| L2 | **Chặn demo** | Script `attack-sim` gửi từ 127.0.0.1 — chính máy người trình bày — với User-Agent `python-httpx`: khoá ngay lần thử đầu vì "client kịch bản", khoá luôn IP 127.0.0.1 30 phút (form đăng nhập của người trình bày bị 423), sau đó luật `blocked_retry` đòi OTP mọi đăng nhập từ máy đó 1 giờ | IP kẻ tấn công giả lập qua `X-Forwarded-For` (dải TEST-NET-3), User-Agent trình duyệt làm mặc định, `--tool-ua` khi muốn trình diễn phát hiện công cụ tự động |
| L3 | Trung bình | `success_after_fail.py` chỉ sai 4 lần — dưới ngưỡng 5 của luật, không kích hoạt gì | 5 lần |
| L4 | Trung bình | `impossible_travel.py` bắt đầu từ 8.8.8.8 (datacenter Mỹ) — tự nó đã bị đòi OTP, không tới bước 2 | Bắt đầu từ nhà mạng TP.HCM (14.161.1.1) |
| L5 | Trung bình | Benchmark đăng nhập 50 lần liên tiếp vào MỘT tài khoản — nay khớp luật `success_burst` (≥ 8 lần thành công/10 phút, MR27) nên đo phần lớn là lần bị khoá trả về nhanh | `--accounts K` xoay vòng tài khoản mới; đo trên DB/Redis sạch |
| L6 | Thấp | Soak test và tài liệu cài đặt ghi 30 tài khoản demo, dữ liệu chỉ có `user001-025` — 1/6 lưu lượng soak trước đây vào tài khoản không tồn tại | Soak dùng 25 tài khoản (tài liệu sửa ở MR35) |
| L7 | Thấp | Soak không đo bộ nhớ server; dùng "localhost" (+2 s mỗi kết nối mới trên Windows) | Ghi bộ nhớ tiến trình server (`--server-pid`); 127.0.0.1 |

Ngoài dự án: Docker Desktop trên máy dev không khởi động được (file socket cũ trong `%LOCALAPPDATA%\Docker\run` sau lần tắt không sạch
ngày 04/10) — đã dọn; ghi vào hướng dẫn xử lý sự cố ở MR35.

**Ghi nhận, không sửa:** khi quản trị viên đã mở khoá một sự cố, lần thử tiếp theo được gộp vào cùng sự cố mà vẫn bị chấm "khoá" sẽ bị từ
chối (423) nhưng không tạo lại mục khoá — sự cố gộp (MR23) chỉ thực thi lại khi mức hành động tăng. Từng lần thử vẫn bị chặn đúng.

## 6. Hội đồng có thể hỏi

- **"Độ phủ 80% có thấp không?"** — Mã chạy thật phủ 96–98%; 20% còn lại chủ yếu là script dòng lệnh/huấn luyện chạy một lần.
- **"Kiểm thử đầu-cuối thế nào?"** — Trình duyệt thật + HTTP thật trên bản sao DB; 10 test case, phát hiện và sửa 2 lỗi chặn demo mà test
  tự động không bắt được (một lỗi chỉ xuất hiện khi hai tab cùng trình duyệt — dashboard và web app — dùng chung bộ nhớ).
- **"Hệ thống chịu tải bao nhiêu?"** — Đo được: 10 request đồng thời p95 791 ms, không lỗi; một tiến trình uvicorn. Mở rộng cần nhiều
  worker + Redis pub/sub cho WebSocket (chưa làm).
- **"Sao benchmark cũ không dùng được nữa?"** — Chính các luật mới (MR27–MR28) coi 50 lần đăng nhập/vài giây vào một tài khoản là bất
  thường — hệ thống làm đúng; phép đo phải mô phỏng người dùng hợp lệ.
