# attack-sim — Script giả lập tấn công (nhiệm vụ 6.1)

4 script test hệ thống tự phát hiện đúng loại tấn công tương ứng. Chạy
bằng venv của backend (đã có `httpx` cài sẵn):

```bash
cd backend
venv\Scripts\activate
cd ..\attack-sim

python brute_force.py --target user011
python credential_stuffing.py
python success_after_fail.py --target user012 --correct-password Demo@12345
python impossible_travel.py --target user013 --password Demo@12345
```

| Script | Kịch bản | Kết quả kỳ vọng (đo ở MR34, [`docs/acceptance-mr34.md`](../docs/acceptance-mr34.md)) |
|---|---|---|
| `brute_force.py` | 6 lần sai mật khẩu, cùng 1 tài khoản | Cảnh báo "Dò mật khẩu" (`brute_force`) — chỉ cảnh báo, không khoá |
| `credential_stuffing.py` | 12 tên đăng nhập khác nhau, cùng 1 IP | Cảnh báo `username_enumeration` (tên không tồn tại), IP nguồn bị khoá |
| `success_after_fail.py` | 5 lần sai rồi đăng nhập đúng | Lần đúng bị đòi OTP (`success_after_failures`) |
| `impossible_travel.py` | TP.HCM rồi ngay sau đó Brisbane | Cảnh báo `impossible_travel` + khoá + đường nối trên bản đồ |

Mọi script nhận:

- `--base-url` (mặc định `http://127.0.0.1:8000`), `--delay` (giây nghỉ giữa các request, chỉnh tốc độ khi trình diễn) — xem `common.py`;
- `--source-ip`: IP kẻ tấn công giả lập qua header `X-Forwarded-For` (mặc định một IP trong dải TEST-NET-3 `203.0.113.0/24` — IP giả,
  không thuộc ai). Nhờ vậy khoá tự động theo IP rơi vào IP giả, **không khoá máy người trình bày** (127.0.0.1);
- `--tool-ua`: gửi User-Agent mặc định của httpx thay vì trình duyệt — để trình diễn luật phát hiện công cụ tự động (`scripted_client`
  khoá ngay lần thử đầu, nên mặc định dùng User-Agent trình duyệt để thấy tín hiệu riêng của từng kịch bản).

`--source-ip` và `impossible_travel.py` cần backend bật `TRUST_FORWARDED_FOR=true` trong
`.env` (mặc định TẮT, chỉ dùng demo cục bộ; header chỉ được tin khi kết nối đến từ chính máy chạy backend — xem
`backend/app/utils/network.py` và `docs/api-contract.md` mục 3). Không bật thì mọi kịch bản đến từ 127.0.0.1.

Một sự cố trên cùng tài khoản được gộp thành một cảnh báo (MR23) — chạy lại một kịch bản vào tài khoản vừa dùng sẽ cập nhật cảnh báo cũ
thay vì tạo cảnh báo mới; muốn thấy cảnh báo mới thì đổi `--target`.

Kết quả kiểm thử end-to-end: [`docs/acceptance-mr34.md`](../docs/acceptance-mr34.md) (bản mới nhất),
[`docs/e2e-test-report.md`](../docs/e2e-test-report.md) (Tuần 6).
