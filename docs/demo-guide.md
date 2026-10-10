# Hướng dẫn demo (MR36)

Demo chạy trên **DB riêng `lad_demo`** + Redis db 3 — dữ liệu dev (`lad_db`) không bị đụng. Dữ liệu demo là giả lập: 25 tài khoản
`user001`–`user025`, mỗi tài khoản 60 ngày lịch sử đăng nhập kết thúc hôm qua, sinh lại y hệt mỗi lần làm sạch.

| | Địa chỉ | Tài khoản |
|---|---|---|
| Quản trị (dashboard) | http://localhost:5173/admin/login | `admin_demo` / `Admin@Demo2026` |
| Web app mẫu (bị giám sát) | http://localhost:5173/login | `user001` … `user025` / `Demo@12345` |

## 1. Ba lệnh

Chạy từ PowerShell ở thư mục gốc dự án:

```
powershell -ExecutionPolicy Bypass -File demo\start.ps1    # bật Docker → DB → kiểm tra → backend + frontend → mở trình duyệt
powershell -ExecutionPolicy Bypass -File demo\reset.ps1    # làm sạch dữ liệu demo (xoá cảnh báo, khoá...) rồi khởi động lại
powershell -ExecutionPolicy Bypass -File demo\stop.ps1     # đóng backend + frontend (Docker vẫn chạy)
```

`start.ps1` tự: bật Docker Desktop nếu đang tắt (và dời file socket cũ gây lỗi khởi động — mục 4), `docker compose up -d`, dựng DB demo
nếu chưa có, **kiểm tra 15 điều kiện** (DB, Redis, 4 tệp mô hình, mô hình nạp được thật, GeoIP, danh sách Tor/VPN, cổng trống...), mở
backend và frontend thành 2 cửa sổ "DEMO backend :8000" / "DEMO frontend :5173" (đừng đóng trong lúc demo), mở 2 tab trình duyệt.

Kịch bản tấn công một lệnh (cửa sổ PowerShell thứ ba):

```
cd attack-sim
..\backend\venv\Scripts\python.exe demo_all.py            # 7 kịch bản, Enter để sang kịch bản tiếp
..\backend\venv\Scripts\python.exe demo_all.py --only 4   # chạy lại riêng một kịch bản
```

## 2. Trước buổi bảo vệ

- **Hôm trước:** chạy `start.ps1` một lần, đi hết mục 3, rồi `stop.ps1`.
- **15 phút trước:** `reset.ps1` — mọi dòng kiểm tra phải là ✓ ("Sẵn sàng demo."). Đăng nhập quản trị sẵn ở một tab, để tab web app
  mẫu cạnh bên; cửa sổ PowerShell thứ ba đứng sẵn ở `attack-sim`.
- Không cần Internet trừ bản đồ (tile OpenStreetMap); mất mạng thì bản đồ trống, mọi thứ khác vẫn chạy.

## 3. Kịch bản demo (~12 phút)

| # | Làm | Chỉ cho hội đồng thấy | Thời gian |
|---|---|---|---|
| 1 | Dashboard đã mở, góc phải "Real-time" | Bốn khu: bản đồ, biểu đồ điểm rủi ro (3 vạch ngưỡng 32/58/70), log đăng nhập, cảnh báo | 1' |
| 2 | Tab web app: `user020` / `Demo@12345` | Đăng nhập thành công; dòng mới hiện ngay trong log (trình duyệt lạ với tài khoản nên có thể là "Cảnh báo" điểm thấp — vẫn cho qua) | 1' |
| 3 | Tab web app: `user020` sai mật khẩu 5 lần rồi đúng | Không vào thẳng được — màn hình OTP; nhập sai mã → bị từ chối; nhập mã đúng → vào được. Dashboard: cảnh báo "Dò mật khẩu… 5 lần sai/5 phút" kèm giải thích | 2' |
| 4 | `demo_all.py`, kịch bản 1–2 | Dò mật khẩu chỉ **cảnh báo** (người quên mật khẩu cũng vậy); dò danh sách tài khoản thì **khoá IP** — panel "Khoá tạm & chặn" có IP | 2' |
| 5 | Kịch bản 3–4 | Đoán trúng mật khẩu sau chuỗi sai → OTP hoặc khoá; di chuyển TP.HCM → Brisbane trong vài giây → khoá, **bản đồ vẽ đường nối** | 2' |
| 6 | Kịch bản 5–7 | Tor → khoá dù đúng mật khẩu; script tự động → khoá ngay; datacenter + thiết bị lạ → OTP. Mở một cảnh báo: "Bằng chứng" liệt kê luật + hai mô hình học máy với tỉ lệ đóng góp | 2' |
| 7 | Bấm "🔓 Mở khoá" một mục; bấm "👍 Đúng" / "👎 Báo nhầm" một cảnh báo | Quản trị viên có quyền cuối; phản hồi được ghi để chỉnh ngưỡng riêng từng tài khoản | 1' |
| 8 | Trang Chiến dịch → Luật → Mô hình → bấm tên một tài khoản | Cảnh báo gom theo IP; bật/tắt, chỉnh ngưỡng luật không cần sửa code; sức khoẻ mô hình (lần đầu tính ~10 giây); hồ sơ rủi ro từng người | 1' |

Kết quả kịch bản 3 và 7 có thể là OTP **hoặc** khoá: điểm mô hình học máy phụ thuộc giờ và thứ trong tuần lúc chạy. Cả hai đều là phát
hiện đúng — nói thẳng điều này nếu hội đồng hỏi.

Muốn demo cổng quản trị tự bảo vệ (MR32): đăng xuất, nhập sai mật khẩu quản trị 5 lần → "tạm khoá, thử lại sau khoảng 15 phút"; bảng
"Đăng nhập quản trị gần đây" ghi lại từng lần. **Làm ở cuối buổi** (hoặc `reset.ps1` sau đó) vì chính máy demo bị khoá cửa quản trị 15 phút.

## 4. Sự cố thường gặp

| Hiện tượng | Cách xử lý |
|---|---|
| Docker Desktop không lên, log có "The file cannot be accessed by the system" (sau khi tắt máy đột ngột) | **Quit** Docker Desktop (khay hệ thống → Quit) rồi chạy lại `start.ps1` — script dời thư mục socket cũ (`%LOCALAPPDATA%\Docker\run`, `%LOCALAPPDATA%\docker-secrets-engine`) khi Docker đang tắt rồi bật lại. Gặp thật ngày 09/10/2026 |
| `start.ps1` báo cổng 8000 hoặc 5173 đang bận | Một backend/frontend khác đang chạy (cửa sổ uvicorn / `npm run dev` cũ) — đóng nó, hoặc `stop.ps1` nếu là demo cũ |
| ✗ "mô hình hybrid_cp2 nạp được" | Thiếu tệp trong `backend/ml/artifacts/` hoặc mã đặc trưng đổi sau khi huấn luyện — hệ thống vẫn chạy bằng luật nhưng số đo khác báo cáo; chép lại thư mục `backend/ml/artifacts` từ máy đã huấn luyện |
| Đăng nhập web app từ chính máy demo bị 423 | Một kịch bản đã khoá tài khoản đó — mở khoá ở panel "Khoá tạm & chặn", hoặc `reset.ps1` |
| Kịch bản không ra cảnh báo mới | Tài khoản đã có sự cố đang mở thì lần mới **gộp** vào cảnh báo cũ (một sự cố = một cảnh báo) — `reset.ps1` rồi chạy lại |
| Dashboard tự về trang đăng nhập quản trị | Token hết hạn (60 phút) — đăng nhập lại |

## 5. Hội đồng có thể hỏi

- **"Dữ liệu demo là thật à?"** — Không, giả lập (25 tài khoản, lịch sử 60 ngày); tấn công do script gửi HTTP thật tới hệ thống đang chạy,
  IP kẻ tấn công giả lập qua header `X-Forwarded-For` (chỉ tin khi gửi từ chính máy demo). Bằng chứng trên log thật: LANL
  ([`lanl-validation.md`](lanl-validation.md)).
- **"Sao kịch bản 3 lần này khoá, lúc thử lại OTP?"** — Luật ép tối thiểu OTP; mô hình học máy cộng thêm điểm theo độ lạ (giờ, thứ, thiết
  bị) — vượt 70 thì khoá.
- **"Demo hỏng thì sao?"** — `reset.ps1` đưa về trạng thái sạch trong ~1 phút; `start.ps1` kiểm tra 15 điều kiện trước khi mở.
