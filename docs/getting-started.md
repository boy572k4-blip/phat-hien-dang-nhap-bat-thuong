# Hướng dẫn khởi động dự án

> **Chỉ muốn chạy demo?** Một lệnh `demo\start.ps1` làm hết các bước dưới trên DB demo riêng — [`demo-guide.md`](demo-guide.md). Tài liệu này
> dành cho môi trường phát triển (DB `lad_db`). Kiến trúc hiện hành: [`architecture.md`](architecture.md).

Máy đã cài sẵn mọi thứ (Docker, venv, node_modules). Đây là các bước để
**chạy lại từ đầu mỗi khi mở máy/mở lại dự án**. Mở 2 cửa sổ terminal
(PowerShell hoặc Git Bash) — 1 cho backend, 1 cho frontend.

## Bước 1 — Bật Docker Desktop

Mở app **Docker Desktop**, đợi tới khi icon cá voi hết loading (khoảng
30s-1 phút). Sau đó ở terminal bất kỳ:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong
docker compose up -d
docker ps
```

Phải thấy `lad_postgres` và `lad_redis` ở trạng thái `healthy`. Nếu lệnh
`docker compose` báo lỗi kết nối → Docker Desktop chưa khởi động xong, đợi
thêm rồi thử lại.

## Bước 2 — Chạy backend (terminal 1)

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
```

Kiểm tra: mở `http://localhost:8000/health` phải thấy
`{"status":"ok","database":"connected"}`. Tài liệu API tự sinh ở
`http://localhost:8000/docs`.

> Terminal này phải để chạy liên tục (không đóng) trong lúc dùng hệ thống.

## Bước 3 — Chạy frontend (terminal 2, cửa sổ khác)

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\frontend
npm run dev
```

Mở `http://localhost:5173` trên trình duyệt.

## Bước 4 — Đăng nhập thử

Web app mẫu ở `http://localhost:5173/login`. Tài khoản có sẵn (do script
sinh dữ liệu tạo — xem Bước 5):

- Username: `user001` đến `user025` (dữ liệu demo dashboard, Tuần 2-3)
- Password: `Demo@12345` (giống nhau cho tất cả)

> Riêng `user101`-`user140` là dữ liệu HUẤN LUYỆN ML (Tuần 7, xem Bước 5b)
> — không dùng để demo web app mẫu, chỉ tồn tại trong DB để chấm điểm mô hình.

Đăng nhập đúng sẽ chuyển sang `/dashboard` của **web app mẫu** — trang này
không phải dashboard giám sát.

## Bước 4b — Vào Dashboard giám sát (cần tài khoản admin riêng)

`/dashboard` (giám sát, real-time) **khác** `/login` ở Bước 4 — đây là khu
vực quản trị, yêu cầu đăng nhập admin riêng ở `http://localhost:5173/admin/login`
(Tuần 5, tách biệt hoàn toàn khỏi tài khoản web app mẫu). Nếu chưa có tài
khoản admin, tạo bằng:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
python -m scripts.create_admin --username admin --password "MatKhauManh123!"
```

Đăng nhập ở `/admin/login` bằng tài khoản vừa tạo, hệ thống tự chuyển sang
`/dashboard` — góc trên bên phải tiêu đề hiện `● real-time` nghĩa là
WebSocket đã kết nối, cảnh báo mới sẽ hiện popup + cập nhật bảng/biểu đồ
ngay lập tức, không cần reload trang.

> Từ giai đoạn mở rộng AI (MR14-17), khu quản trị còn có: **Campaigns** (chiến
> dịch tấn công gom nhiều tài khoản/alert theo hạ tầng chung), **Rules** (bật/tắt
> và chỉnh tham số 24 luật mà không cần sửa code, xem
> [`docs/dashboard-v2.md`](dashboard-v2.md)), **Model Health** (trôi PSI của chính
> hệ thống: cửa sổ đầu so với gần nhất; khoảng cách so với dữ liệu train RBA và độ lệch
> miền — MR26), và trang hồ sơ rủi ro theo từng user.

## Bước 5 — (Tuỳ chọn) Sinh lại dữ liệu mẫu

Chỉ cần chạy lại khi muốn dữ liệu mới hoặc lần đầu setup máy mới. Dữ liệu
hiện tại (25 user, 924 bản ghi có nhãn) đã có sẵn trong Postgres, **không
cần chạy lại** trừ khi bạn muốn.

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
python -m scripts.generate_labeled_anomalies --reset
```

## Bước 5b — (Tuỳ chọn) Huấn luyện lại mô hình địa lý–thời gian (`ml_geo`, trước MR22 gọi là "tầng 3")

Model đã train sẵn và có trong git (`backend/ml/artifacts/isolation_forest.joblib`, `scaler.joblib`, `meta.json` — từ
10/10/2026). Chỉ chạy lại 3 lệnh dưới khi muốn huấn luyện lại; nếu thiếu tệp, hệ thống tự tắt mô hình này một cách an toàn,
không lỗi:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
python -m ml.generate_dataset --reset    # 40 user + 5 kiểu bất thường (nếu chưa có)
python -m ml.extract_features             # trích đặc trưng
python -m ml.train                        # huấn luyện 3 mô hình -> backend/ml/artifacts/
python -m ml.evaluate                     # (tuỳ chọn) xuất lại biểu đồ so sánh
```

## Bước 5c — (Tuỳ chọn) Nạp mô hình ML hybrid (`hybrid_cp2`, giai đoạn mở rộng AI)

Từ MR12, `/login` chấm điểm rủi ro bằng mô hình `hybrid_cp2` (huấn luyện trên bộ dữ liệu học thuật RBA — xem
[`docs/model-card-rba.md`](model-card-rba.md)). Tệp mô hình `backend/ml/artifacts/rba/hybrid_cp2.joblib` có sẵn trong git (từ
10/10/2026) nên clone về là chạy được. Chỉ cần huấn luyện lại khi đổi đặc trưng (log backend báo `chưa có artifact ...` hoặc chữ
ký đặc trưng không khớp):

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
python -m ml.check_env                # kiểm tra tìm thấy rba-dataset.zip chưa (xem docs/rba-data-card.md mục 7)
python -m ml.rba.selection all        # ~15-20 phút — chọn đặc trưng + huấn luyện hybrid_cp2 -> ml/artifacts/rba/hybrid_cp2.joblib
```

⚠️ **Nếu thiếu artifact, hệ thống KHÔNG lỗi** — `hybrid_runtime.py` tự rơi về hồ sơ dự phòng (chỉ luật + danh tiếng,
không có thành phần ML) để không tắt hẳn detection, nhưng recall sẽ thấp hơn số đã công bố ở
[`docs/ml-evaluation-v2.md`](ml-evaluation-v2.md). Không có script nạp riêng — mô hình tự đăng ký vào bảng
`model_registry` ở lần khởi động backend kế tiếp sau khi artifact xuất hiện.

## Bước 6 — Thử kịch bản tấn công (attack-sim)

Mở dashboard (Bước 4b) trước để xem cảnh báo hiện real-time, rồi ở
terminal khác:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\attack-sim
"..\backend\venv\Scripts\python.exe" demo_all.py                    # 7 kịch bản, Enter để sang kịch bản tiếp
"..\backend\venv\Scripts\python.exe" brute_force.py --target user011  # hoặc từng script riêng — attack-sim/README.md
```

Các script giả lập IP kẻ tấn công qua `X-Forwarded-For` nên cần `TRUST_FORWARDED_FOR=true` trong `.env` (mặc định tắt — chỉ bật khi
demo cục bộ; header chỉ được tin khi gửi từ chính máy chạy backend) rồi khởi động lại backend. Không bật thì mọi kịch bản đến từ
127.0.0.1 — khoá tự động theo IP sẽ khoá luôn chính máy của bạn.

## Bước 6b — (Tuỳ chọn) Thư viện kịch bản tấn công mô phỏng v2 (MR18)

`attack-sim/` (Tuần 6) chỉ có 4 kịch bản cơ bản. Giai đoạn mở rộng AI thêm một thư viện 9 kịch bản thực tế hơn (IP/ASN
thật qua GeoIP, botnet, dò danh sách tài khoản, kẻ tấn công tinh vi...), chạy thẳng qua HTTP như người dùng thật, tự
tính điểm phát hiện theo từng tầng và xuất báo cáo:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
python -m scripts.attack_scenario_runner   # ghi lại docs/attack-scenarios-v2.md
```

Các script mô phỏng khác (không phải test, dùng để khảo sát/minh chứng — mỗi script tự dựng CSDL/Redis riêng trong bộ
nhớ, không đụng dữ liệu dev thật, KHÔNG chạy qua pytest): tương quan cảnh báo/chiến dịch
(`scripts.alert_intelligence_sim`, MR13), vòng phản hồi + ngưỡng thích nghi (`scripts.feedback_loop_sim`, MR15),
phản ứng tự động — OTP/khoá tài khoản (`scripts.automated_response_sim`, MR16). Đọc kết quả tương ứng ở
[`docs/attack-scenarios-v2.md`](attack-scenarios-v2.md), [`docs/feedback-loop.md`](feedback-loop.md),
[`docs/automated-response.md`](automated-response.md) trước khi chạy lại — mỗi script mất vài phút và một số dùng dữ
liệu ngẫu nhiên không hạt giống cố định nên số liệu có thể lệch nhẹ giữa các lần chạy.

## Dừng hệ thống khi xong việc

- Terminal backend/frontend: `Ctrl+C`.
- Docker: `docker compose down` (giữ lại dữ liệu DB) hoặc để chạy nền cũng
  không sao — không tốn tài nguyên đáng kể khi máy rảnh.

## Lỗi thường gặp

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| `uvicorn` báo lỗi bind port 8000 | Còn tiến trình cũ chưa tắt | Đóng terminal cũ đang chạy uvicorn, hoặc `netstat -ano \| findstr :8000` rồi `taskkill /F /PID <pid>` |
| Vite báo "Port 5173 is in use" | Tương tự, tiến trình cũ | Đóng terminal cũ hoặc kill theo PID như trên |
| Chữ tiếng Việt lỗi (`UnicodeEncodeError`) khi chạy script Python | Console Windows dùng codepage cp1252 | Từ MR33 các lệnh `python -m scripts.…` / `python -m ml.…` và `attack-sim/` tự đặt UTF-8; script khác: `set PYTHONIOENCODING=utf-8` |
| `docker compose up` báo lỗi kết nối tới Docker | Docker Desktop chưa khởi động xong | Mở Docker Desktop, đợi rồi thử lại |
| Docker Desktop không bao giờ lên, log có "The file cannot be accessed by the system" | File socket cũ sau lần tắt máy đột ngột | Quit Docker Desktop rồi chạy `demo\start.ps1` (tự dời `%LOCALAPPDATA%\Docker\run` và `%LOCALAPPDATA%\docker-secrets-engine` khi Docker đang tắt) |
| Frontend gọi API bị lỗi CORS | Backend chưa chạy, hoặc chạy sai port | Đảm bảo backend chạy ở port 8000 (khớp `VITE_API_BASE_URL` trong `.env`) |

## Chạy test

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
pytest -q
```

Không cần Docker chạy — test dùng SQLite in-memory + Redis giả lập
(fakeredis), tách biệt hoàn toàn khỏi dữ liệu dev thật.
