# Hệ thống phát hiện đăng nhập bất thường

Đồ án tốt nghiệp — Anomaly Login Detection System. Mỗi lần đăng nhập vào một web app mẫu được chấm điểm rủi ro 0–100 bằng **24 luật**
(cấu hình được lúc chạy) kết hợp **hai mô hình học máy** (`hybrid_cp2` học trên bộ dữ liệu học thuật RBA, và mô hình địa lý–thời gian),
ra MỘT hành động — cho qua / cảnh báo / xác thực thêm bằng OTP / khoá tạm — và hiện tức thời trên dashboard quản trị kèm giải thích
bằng tiếng Việt. Mỗi sự cố là một cảnh báo; nhiều tài khoản bị tấn công từ cùng hạ tầng được gom thành chiến dịch.

**Kiến trúc hiện hành:** [`docs/architecture.md`](docs/architecture.md) · **mục lục tài liệu:** [`docs/README.md`](docs/README.md)

## Thành phần

- **backend/** — FastAPI + PostgreSQL + Redis: API đăng nhập, pipeline phát hiện, mô hình, WebSocket.
- **frontend/** — React (Vite): web app đăng nhập mẫu + khu quản trị real-time.
- **attack-sim/** — script giả lập tấn công gửi HTTP thật (7 kịch bản một lệnh: `demo_all.py`).
- **demo/** — khởi động / làm sạch / dừng demo một lệnh.
- **docs/** — kiến trúc, đánh giá, quyết định, checklist.

## Phân công

- **Thành viên A — Backend & Detection**: schema DB, API backend, toàn bộ detection engine, bảo mật API/WebSocket.
- **Thành viên B — Frontend, Dashboard & Kiểm thử**: web app mẫu, dashboard, real-time, script tấn công, đo precision/recall.

## Chạy demo (một lệnh)

```
powershell -ExecutionPolicy Bypass -File demo\start.ps1
```

Bật Docker, dựng dữ liệu demo riêng (DB `lad_demo`), kiểm tra 15 điều kiện, mở backend + frontend và trình duyệt. Tài khoản, kịch bản
demo 12 phút, tấn công một lệnh và xử lý sự cố: [`docs/demo-guide.md`](docs/demo-guide.md).

## Chạy môi trường phát triển

Yêu cầu: Docker Desktop, Python 3.11+, Node 20+, GeoLite2 ([`docs/geoip-setup.md`](docs/geoip-setup.md)).

```bash
cp .env.example .env              # đặt JWT_SECRET_KEY ngẫu nhiên; không commit .env
docker compose up -d              # PostgreSQL + Redis (chỉ mở trên 127.0.0.1)

cd backend
python -m venv venv
venv\Scripts\activate             # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
python -m scripts.create_admin --username admin --password "MatKhauManh123!"
uvicorn app.main:app --reload --port 8000

cd ../frontend
npm install
npm run dev                       # http://localhost:5173 — /login: web app mẫu, /admin/login: quản trị
```

Tệp mô hình đã có trong git (`backend/ml/artifacts/`), nên clone về là chạy đầy đủ. Chi tiết, dữ liệu mẫu và lỗi thường gặp:
[`docs/getting-started.md`](docs/getting-started.md). Tái lập toàn bộ số đo: [`docs/reproduction-guide.md`](docs/reproduction-guide.md).

Kiểm thử: `cd backend && venv\Scripts\python.exe -m pytest` (903 test, không cần Docker).

## Kết quả chính

| | Kết quả | Chi tiết |
|---|---|---|
| Hành vi trên bộ kịch bản có nhãn 39 họ | 21/23 hành vi bị bắt; 18/23 đạt "vững" (tín hiệu riêng bắt ≥ 50% biến thể, báo nhầm ≤ 1%) | [`behavior-coverage-matrix.md`](docs/behavior-coverage-matrix.md) |
| Người dùng hợp lệ (gồm VPN, đổi máy, quên mật khẩu...) | 1,35% bị đòi OTP/khoá; 27,1% bị cảnh báo cho quản trị viên | [`combined-rules.md`](docs/combined-rules.md) |
| Log thật LANL (tấn công thật của red team) | AUC user-ngày 0,873 — kiểm chứng phương pháp, không phải hệ thống web | [`lanl-validation.md`](docs/lanl-validation.md) |
| Hiệu năng | `/login` trung vị 311 ms, 10 đồng thời p95 791 ms, soak 60 phút 0 lỗi | [`acceptance-mr34.md`](docs/acceptance-mr34.md) |
| Bảo mật | 11 vấn đề đã rà và sửa, cổng quản trị tự bảo vệ | [`security-review.md`](docs/security-review.md) |

⚠️ Bộ RBA là dữ liệu **tổng hợp** và bộ 39 họ do nhóm **tự dựng** — không phải tấn công thật ngoài đời; bằng chứng trên tấn công thật chỉ
có LANL. Giới hạn đã biết: [`docs/architecture.md`](docs/architecture.md) mục 6.

## Lịch sử phát triển

Tuần 1–8 (khung hệ thống), MR1–MR19 (mở rộng ML trên RBA, rule engine v2, phản ứng tự động), MR20–MR36 (hợp nhất kiến trúc, hiệu chỉnh
cho người dùng Việt Nam, mở rộng hành vi, kiểm chứng LANL, bảo mật, nghiệm thu, demo): [`docs/history.md`](docs/history.md),
[`docs/checklist.md`](docs/checklist.md).
