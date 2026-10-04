# MR32 — Hệ thống tự bảo vệ mình: rà soát bảo mật và dữ liệu cá nhân

Một hệ thống phát hiện đăng nhập bất thường mà chính cửa quản trị của nó không được bảo vệ thì sẽ bị hỏi ngay. MR32 rà toàn bộ
backend (mọi router, cấu hình, JWT, CORS, cách lấy IP nguồn), frontend (lưu token, WebSocket, xử lý phiên), `docker-compose.yml` và
lịch sử git. Rà thủ công từng tệp; quét lịch sử git tìm khoá bí mật (`.env`, khoá MaxMind, khoá riêng, khoá AWS): **không có gì bị
commit**. Không chạy công cụ quét lỗ hổng thư viện (`pip-audit`, `npm audit` — cần gửi danh sách thư viện ra dịch vụ ngoài, chờ chủ dự
án đồng ý).

## 1. Phát hiện và cách xử lý

| # | Mức | Phát hiện | Xử lý |
|---|---|---|---|
| S1 | **Cao** | `POST /admin/login` thử không giới hạn, không ghi vết, không có gì theo dõi | **Đã sửa**: giới hạn theo IP và theo tài khoản, khoá tạm, ghi vết mọi lần thử, bảng "Đăng nhập quản trị gần đây" trên dashboard (mục 2) |
| S2 | **Cao** | Khoá ký JWT mặc định là chuỗi mẫu công khai trong mã nguồn và `.env.example` — **`.env` của máy dev đang dùng đúng chuỗi đó**: ai đọc repo cũng ký được token quản trị hợp lệ | **Đã sửa**: khoá mẫu hoặc ngắn hơn 32 byte → `APP_ENV=production` từ chối khởi động; môi trường khác dùng khoá ngẫu nhiên riêng cho tiến trình (đăng nhập lại sau mỗi lần khởi động) và in cảnh báo (`app/config.py`) |
| S3 | Trung bình | `/login` và `/admin/login` không chạy bcrypt khi tên không tồn tại → trả lời trong vài ms thay vì ~230 ms, **thời gian phản hồi lộ tài khoản nào có thật** dù thông báo lỗi giống hệt nhau (phát hiện ở MR20) | **Đã sửa**: so với một hash giả cùng độ khó (`check_password`). Đo: trung vị 212,9 ms (tài khoản có thật, sai mật khẩu) so với 209,2 ms (không tồn tại) |
| S4 | Trung bình | Token quản trị gửi qua `?token=` của WebSocket — uvicorn ghi nguyên văn URL vào access log; token dùng được cho mọi route quản trị trong 60 phút | **Đã sửa**: token đi trong header `Sec-WebSocket-Protocol: bearer, <jwt>`; không nhận `?token=` nữa. Đã kiểm trên log thật: dòng log chỉ còn `"WebSocket /ws/alerts" [accepted]` |
| S5 | Trung bình | Khi bật `TRUST_FORWARDED_FOR` (`.env` dev đang bật để demo), mọi máy kết nối được đều tự khai IP nguồn; và lấy phần tử ĐẦU của `X-Forwarded-For` — phần client tự viết, nên kể cả đứng sau reverse proxy thật vẫn giả được IP, né mọi luật theo IP | **Đã sửa**: chỉ tin header khi kết nối đến từ `TRUSTED_PROXIES` (mặc định `127.0.0.1,::1`), đọc từ phải sang trái bỏ qua proxy tin cậy, phần tử không phải IP hợp lệ → dùng IP TCP (`app/utils/network.py`) |
| S6 | Trung bình | Postgres và Redis mở cổng trên **mọi** giao diện mạng (`0.0.0.0:5432`, `0.0.0.0:6379` — kiểm bằng `docker ps`); Redis không mật khẩu: máy khác cùng Wi-Fi xoá được bộ đếm của rule engine | **Đã sửa trong `docker-compose.yml`** (chỉ `127.0.0.1`). Áp dụng khi tạo lại container: `docker compose up -d` (giữ nguyên dữ liệu) |
| S7 | Thấp | CORS bật `allow_credentials` và cho mọi phương thức/header | **Đã sửa**: không dùng cookie nên tắt `allow_credentials`; chỉ `GET/POST/PUT/DELETE`, header `Authorization`, `Content-Type` |
| S8 | Thấp | Mật khẩu không giới hạn độ dài (bcrypt chỉ dùng 72 byte đầu, phần còn lại vẫn phải nhận và mã hoá) | **Đã sửa**: tối đa 128 ký tự → 422 |
| S9 | Thấp | JWT không bắt buộc có `exp` (một token ký đúng mà thiếu hạn dùng sẽ dùng mãi) | **Đã sửa**: bắt buộc `exp`, `iat`, `sub` |
| S10 | Thấp | Mã OTP demo trả thẳng trong response — người cầm mật khẩu tự nhận được mã, bước xác thực thêm không chặn được ai | **Giữ cho demo** (giao diện cần hiện mã), **tắt khi `APP_ENV=production`**: mã chỉ ghi ra log máy chủ như một kênh gửi mô phỏng |
| S11 | Thấp | Token hết hạn thì dashboard im lặng báo lỗi tải; không có nút đăng xuất | **Đã sửa**: gặp 401 thì xoá token và về trang đăng nhập quản trị; thêm nút "Đăng xuất" |

**Rủi ro chấp nhận (ghi để trả lời, không sửa trong phạm vi đồ án):**

- **Token lưu `localStorage`** — một lỗ XSS sẽ đọc được. Giảm thiểu: React tự thoát ký tự khi hiển thị, mã không dùng
  `dangerouslySetInnerHTML`, không nạp script bên thứ ba. Chuyển sang cookie `HttpOnly` thì phải thêm chống CSRF.
- **Không thu hồi token phía máy chủ**: đăng xuất chỉ xoá token ở trình duyệt; đổi mật khẩu/xoá admin không vô hiệu token cũ — giới
  hạn bằng hạn dùng 60 phút.
- **Quản trị viên chưa có xác thực hai lớp**, chỉ một vai trò quản trị (không phân quyền chi tiết).
- **Không có HTTPS khi chạy dev** (`http://localhost`) — triển khai thật phải đặt sau reverse proxy có TLS (mật khẩu đi trên đường truyền).
- **Mỗi lần đăng nhập quản trị bị từ chối vẫn ghi một dòng audit** — tấn công dồn dập về số lượng là việc của reverse proxy/WAF.
- **`/login/verify-otp` không gắn với phiên** (web app mẫu không có phiên): cần đúng mã thử thách + mã OTP; mỗi mã tối đa 5 lần sai, luật
  `otp_guessing` khoá khi đoán nhiều mã.
- Mật khẩu DB mẫu trong `.env.example`/`docker-compose.yml` chỉ dành cho máy dev.

## 2. Bảo vệ cửa quản trị (`app/admin_guard.py`)

| Lớp | Quy tắc | Vì sao |
|---|---|---|
| Theo IP | ≥ 10 lần sai trong 15 phút từ một IP (với mọi tên) → IP đó nhận **429** + `Retry-After` | Chặn một máy rải mật khẩu qua nhiều tên |
| Theo tài khoản | ≥ 5 lần sai trong 15 phút vào một tên → tên đó nhận 429, **đếm riêng IP quen và IP lạ** | "Khoá thông minh": IP quen = đã đăng nhập quản trị thành công bằng tên đó trong 90 ngày. Kẻ tấn công từ IP lạ chỉ khoá được cửa IP lạ — quản trị viên ở máy quen vẫn vào được, nên cơ chế khoá không thành công cụ để chặn chính quản trị viên |
| Ghi vết | Mọi lần thử (thành công / sai / bị từ chối) vào `audit_log` kèm IP, User-Agent, IP quen hay lạ | Quản trị viên xem ở dashboard; là chính nguồn dữ liệu để đếm (không cần bảng mới hay Redis) |

Chi tiết đáng hỏi:

- **Bị từ chối thì không chạy bcrypt** (kiểm tra trước khi băm) và **không tính là lần sai** — cứ thử tiếp không kéo dài khoá mãi; khoá
  tự hết khi lần sai cũ ra khỏi cửa sổ 15 phút. Đăng nhập đúng xoá bộ đếm của cửa đó.
- **Không vượt được giới hạn bằng request song song**: dòng của lần thử được ghi trước (tạm coi là sai) rồi mới đếm, bcrypt chạy sau —
  trong N request đồng thời, request có dòng thứ 6 chắc chắn đếm thấy đủ 5 lần trước và bị từ chối. Nếu đếm trước rồi mới ghi, 100
  request gửi cùng lúc sẽ đều qua được bước đếm (bcrypt mất ~230 ms).
- **Không dùng danh sách khoá (`blocklist`) của phần phát hiện cho cửa quản trị**: script tấn công demo chạy cùng máy (127.0.0.1) với
  quản trị viên — khoá tự động theo IP sẽ khoá luôn người cần vào để mở khoá.
- Đổi lại: kẻ tấn công vẫn khoá được cửa IP lạ, nên quản trị viên đăng nhập lần đầu từ máy mới trong lúc bị tấn công phải chờ 15 phút.

## 3. Kiểm chứng

- **Test** (`tests/test_security_mr32.py`, 16 test; cập nhật `test_admin.py`, `test_auth.py`, `test_network.py`): khoá sau 5 lần sai kể cả
  mật khẩu đúng, không chạy bcrypt khi bị khoá, IP quen không bị khoá bởi kẻ tấn công từ IP lạ, IP quen có bộ đếm riêng, đăng nhập đúng xoá
  bộ đếm, khoá hết hạn và lần bị từ chối không kéo dài khoá, lần thử đang dở được đếm trước bcrypt, một IP rải nhiều tên bị chặn, tên không
  tồn tại vẫn chạy bcrypt (cả `/login`), mọi lần thử có vết và chỉ admin xem được, khoá JWT mẫu bị thay/bị từ chối ở production, token
  thiếu `exp` bị từ chối, CORS lạ bị từ chối, OTP không trả về ở production, mật khẩu > 128 ký tự → 422, WebSocket nhận subprotocol và
  từ chối `?token=`, `X-Forwarded-For` chỉ tin từ proxy tin cậy và đọc từ phải.
- **Trình duyệt, trên bản sao DB tạm** (`lad_bench`, Redis db 1 — xoá sau khi đo; DB dev không có dòng nào ghi thêm): đăng nhập quản trị →
  dashboard "Real-time" (WebSocket qua subprotocol), log máy chủ không chứa token; sai mật khẩu 5 lần rồi nhập đúng → giao diện báo
  "Đăng nhập quản trị sai quá nhiều lần — tạm khoá, thử lại sau khoảng 15 phút"; bảng "Đăng nhập quản trị gần đây" hiện đủ các lần thử;
  khởi động lại backend (khoá JWT tạm đổi) → lần gọi API kế tiếp nhận 401 → tự về trang đăng nhập. Lần kiểm này bắt được một lỗi của
  chính bản sửa (bộ chặn 401 bỏ qua cả `/admin/login-attempts` vì so tiền tố) — đã sửa thành so khớp đúng đường dẫn.
- Script mô phỏng MR16 (`scripts/automated_response_sim.py`) cho kết quả y hệt trước (khoá + OTP), sau khi sửa thêm một lỗi có sẵn từ
  MR20 làm kịch bản OTP không chạy được.

## 4. Dữ liệu cá nhân

**Dữ liệu hệ thống lưu:**

| Dữ liệu | Nơi lưu | Mục đích | Ai xem được |
|---|---|---|---|
| Tên đăng nhập, thời điểm, thành công/thất bại | `login_events` | phát hiện tấn công, điều tra | quản trị viên (JWT) |
| Địa chỉ IP, ASN/nhà mạng, thành phố–quốc gia ước lượng từ IP (GeoLite2) | `login_events`, `known_locations` | luật theo IP, vị trí lạ, di chuyển bất khả thi | quản trị viên |
| User-Agent, dấu vân tay thiết bị | `login_events`, `known_devices` | thiết bị lạ, công cụ tự động | quản trị viên |
| Điểm rủi ro, cảnh báo, phản hồi của quản trị viên | `alerts`, `user_risk_profiles`, `audit_log` | phát hiện, học từ phản hồi | quản trị viên |
| Lần đăng nhập quản trị (IP, User-Agent) | `audit_log` | bảo vệ cửa quản trị | quản trị viên |

**Không lưu**: mật khẩu (chỉ bcrypt), mã OTP (chỉ bcrypt), vị trí GPS (chỉ ước lượng cấp thành phố từ IP), nội dung request đăng nhập
(không ghi log thân request).

**Cơ sở pháp lý tham khảo** (đồ án không tự kết luận pháp lý): Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15 (thông qua 26/6/2025, hiệu lực
01/01/2026) và Nghị định 356/2025/NĐ-CP hướng dẫn luật (hiệu lực 01/01/2026, thay Nghị định 13/2023/NĐ-CP). Danh mục dữ liệu nhạy cảm
của Nghị định 356 có vị trí cá nhân xác định qua dịch vụ định vị và dữ liệu theo dõi hành vi sử dụng dịch vụ trực tuyến — nhật ký đăng
nhập có IP, thiết bị, vị trí ước lượng nên được đối xử thận trọng như dữ liệu nhạy cảm. Hệ thống đồ án chỉ chạy trên tài khoản giả lập
(`user001…`), bộ RBA tổng hợp và log LANL đã ẩn danh — không có dữ liệu của người thật.

**Nếu triển khai thật, cần thêm** (chưa làm trong đồ án):

1. Thông báo xử lý dữ liệu trên trang đăng nhập và cơ sở pháp lý (sự đồng ý hoặc trường hợp luật cho phép), hồ sơ đánh giá tác động xử lý
   dữ liệu cá nhân.
2. **Thời hạn lưu giữ** — đề xuất: `login_events` 12 tháng; `known_devices`/`known_locations` tới khi tài khoản bị xoá hoặc 180 ngày
   không dùng; `alerts` và `audit_log` 1 năm (bằng chứng điều tra). Không cắt `login_events` ngắn hơn được ngay: luật
   `dormant_account_login` cần biết lần thành công cuối cách đây ≥ 90 ngày và đặc trưng ML đọc toàn bộ lịch sử tài khoản, cả hai đang tính
   thẳng từ `login_events` (`app/detection/login_context.py`) — xoá log thô sau 90 ngày thì tài khoản ngủ đông trông như tài khoản mới.
   Muốn ngắn hơn phải lưu tổng hợp theo tài khoản trước (lần thành công cuối, số lần, quốc gia/thiết bị quen). **Hiện chưa có tác vụ
   xoá tự động** — dữ liệu demo sinh lại được bằng script.
3. Xoá theo yêu cầu của chủ dữ liệu: xoá các dòng theo `user_id` trong `login_events`, `known_devices`, `known_locations`,
   `user_risk_profiles`, `otp_challenges` và che tên đăng nhập trong `alerts`/`audit_log` (giữ sự kiện, bỏ danh tính).
4. Giảm dữ liệu: cắt IP về dải /24 và bỏ User-Agent đầy đủ sau thời hạn trên nếu cần giữ thống kê lâu hơn.

## 5. Việc chủ dự án cần làm trên máy mình

- Đặt khoá JWT riêng trong `.env` (máy dev hiện dùng khoá mẫu → từ MR32 backend tự dùng khoá tạm và phải đăng nhập quản trị lại sau mỗi lần
  khởi động): `JWT_SECRET_KEY=` + kết quả của `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- Tạo lại container để cổng Postgres/Redis chỉ mở trên máy mình: `docker compose up -d` (dữ liệu giữ nguyên trong volume).

## 6. Hội đồng có thể hỏi

- **"Hệ thống phát hiện đăng nhập bất thường mà trang admin không được bảo vệ?"** — Từ MR32: giới hạn theo IP và theo tài khoản, khoá thông
  minh tách IP quen/IP lạ, khoá tạm 15 phút, mọi lần thử có vết và hiện trên dashboard; thời gian phản hồi không lộ tên quản trị có thật.
- **"Kẻ tấn công cố tình nhập sai để khoá admin thì sao?"** — Chỉ khoá được cửa IP lạ; quản trị viên ở máy quen vẫn vào được.
- **"Sao admin login không đi qua chính bộ phát hiện?"** — Bộ phát hiện học hành vi người dùng web app (bảng `users`, lịch sử dài); quản
  trị viên ít, tách bảng, và khoá tự động theo IP của bộ phát hiện có thể khoá luôn quản trị viên khi demo cùng máy với script tấn công.
- **"Sao biết không còn lộ tài khoản qua thời gian phản hồi?"** — Đo: 212,9 ms so với 209,2 ms (trung vị); test kiểm bcrypt luôn chạy.
- **"JWT để ở localStorage có an toàn không?"** — Rủi ro XSS đã ghi nhận; giảm thiểu bằng React tự thoát ký tự, không HTML thô, hạn 60 phút.
- **"Lưu IP, thiết bị, vị trí người dùng có vi phạm dữ liệu cá nhân không?"** — Mục 4: lưu gì, để làm gì, ai xem; không lưu mật khẩu, OTP,
  GPS; căn cứ Luật 91/2025/QH15 và Nghị định 356/2025/NĐ-CP; triển khai thật cần thông báo, thời hạn lưu giữ và quy trình xoá — đồ án
  chỉ dùng dữ liệu giả lập.
- **"Đã quét lỗ hổng thư viện chưa?"** — Chưa (cần gửi danh sách thư viện ra dịch vụ ngoài); đã rà thủ công mã và quét lịch sử git.
