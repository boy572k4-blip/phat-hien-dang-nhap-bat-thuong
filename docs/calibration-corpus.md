# Bộ dữ liệu hiệu chỉnh có nhãn (MR24) — data card

**Dữ liệu TỰ SINH.** Các lần đăng nhập do bộ sinh của nhóm tạo ra theo các họ tấn công và họ hợp lệ định nghĩa sẵn; nhãn
đúng theo định nghĩa của chính bộ sinh. Chỉ địa chỉ IP là thật (đối chiếu GeoLite2 trên máy, hoặc lấy từ danh sách tình báo
Tor/datacenter/VPN đã tải). Dùng để HIỆU CHỈNH và SO SÁNH cấu hình của hệ thống, không phải bằng chứng hiệu quả trên tấn công
thật ngoài đời.

Mã: [`ml/corpus/`](../backend/ml/corpus/) — `ip_pools.py` (kho IP), `families.py` (các họ), `run.py` (chạy qua pipeline thật).

```bash
cd backend
venv\Scripts\python.exe -m ml.corpus.run --split both --workers 6   # ~3 phút -> ml/artifacts/corpus/ (không commit)
```

## Thành phần

- **15 họ tấn công**: dò mật khẩu (có thể đoán trúng), nhồi thông tin, rải mật khẩu chậm, botnet phân tán, xoay User-Agent,
  dò danh sách tài khoản, di chuyển bất khả thi, tài khoản ngủ đông, mô phỏng tinh vi, proxy cùng nước, thành công sau chuỗi
  sai, đăng nhập qua Tor/datacenter/VPN, client bot/kịch bản, thử từ nhiều quốc gia, nhịp đều như máy.
- **10 họ hợp lệ "khó"**: dùng theo thói quen, tài khoản mới, gõ sai 1–3 lần, quên mật khẩu (sai 4–6 lần rồi đúng), người
  dùng VPN, văn phòng chung một IP (NAT), đi công tác nước ngoài (thời gian bay hợp lý), thiết bị mới, đổi wifi/4G nhiều nhà
  mạng Việt Nam, đăng nhập ban đêm.
- **30 biến thể mỗi họ mỗi bộ**, ngẫu nhiên có seed (nạn nhân, IP, nhịp, số bước, giờ quen, thiết bị); bộ hiệu chỉnh dùng seed
  0–29, bộ đánh giá seed 1000–1029, không giao nhau. Tổng: 2 × 750 biến thể, ~4.700 lần thử mỗi bộ.
- **Nhãn từng lần thử**: lần thử của kẻ tấn công = độc hại; lần thử của chính chủ (kể cả trong kịch bản tấn công) = hợp lệ.
- **Kho IP thật** (13 kho × 30 IP): FPT, VNPT, Viettel (đúng ASN, nhiều tỉnh thành), Mỹ, Singapore, Thái Lan, Hàn Quốc, Trung
  Quốc, Đức, Nga, Tor exit, datacenter, VPN.
- **Mỗi lần thử ghi**: hành động, điểm, luật đã khớp (kèm shadow), xác suất `hybrid_cp2` và `ml_geo`, luật đã ép hành động —
  đủ để tính lại điểm với trọng số/ngưỡng khác mà không chạy lại pipeline (MR25/MR26).

## Số đo nền (cấu hình sau MR23)

| | Bộ hiệu chỉnh | Bộ đánh giá |
|---|---|---|
| Lần thử hợp lệ bị cảnh báo trở lên | **31,4%** (406/1.291) | **33,5%** (443/1.321) |
| AUC `hybrid_cp2` (độc hại vs hợp lệ, mọi lần thử) | **0,234** | **0,228** |
| AUC `ml_geo` (lần thử đã qua cổng cold-start) | 0,932 | 0,922 |
| AUC điểm cuối | 0,650 | 0,639 |

- **Báo nhầm rất cao** trên lưu lượng hợp lệ khó: VPN 100% lần thử, đi công tác 56–65%, thiết bị mới 51–57%, gõ sai 33–41%,
  văn phòng NAT 32%, cả dùng theo thói quen 14–18%. Ba phần tư số báo nhầm do `hybrid_cp2` một mình vượt ngưỡng.
- **`hybrid_cp2` trông như ngược chiều trên lưu lượng kiểu Việt Nam**: trung vị 0,29 cho lần thử hợp lệ, 0,06 cho lần thử tấn
  công. ⚠️ Đính chính ở MR26 ([`vn-recalibration.md`](vn-recalibration.md)): AUC 0,23 là **nghịch lý Simpson** — tách theo kết
  quả đăng nhập thì AUC 0,88 (thành công) và 0,94 (thất bại). Lần thất bại (đa số là tấn công) chỉ được 1/3 thành phần chấm nên
  điểm thấp; lần thành công (đa số hợp lệ) được cả 3 thành phần chấm VÀ bị lệch miền (mạng Việt Nam hiếm trong RBA). Phần phát hiện tấn công hiện đến chủ yếu từ
  `ml_geo` (~85% số lần thử tấn công bị cảnh báo).
- Vì nền báo nhầm cao, tỉ lệ "phát hiện" của các họ tấn công (đa số 100%) **chưa có ý nghĩa** — kể cả "mô phỏng tinh vi", vốn
  thiết kế để khó, cũng 100%. Phải hạ báo nhầm trước (MR25–MR26), rồi đo lại trên bộ đánh giá.

## Mở rộng ở MR27

Thêm 2 họ tấn công (`distributed_botnet_local` — botnet IP Việt Nam nhiều nhà mạng; `login_burst` — đăng nhập thành công dồn dập) và
2 họ hợp lệ khó (`relogin` — đăng nhập lại 2–8 lần liền; `office_nat_day` — 15–25 nhân viên sau một NAT cả ngày, nhiều người gõ sai
một lần): 29 họ, 870 biến thể mỗi phần. Bản chạy mở rộng ghi ra `ml/artifacts/corpus/mr27/` — bản MR24 (`ml/artifacts/corpus/*.jsonl`)
giữ nguyên vì số "trước" của MR25 dựa trên nó. Mỗi luật khớp ghi thêm cờ `forces` (MR27). Số đo: [`behavior-expansion-1.md`](behavior-expansion-1.md).

## Giới hạn

- Hành vi của kẻ tấn công và người dùng do nhóm định nghĩa — ví dụ kẻ tấn công thường dùng IP nước ngoài/ẩn danh, người dùng
  ở Việt Nam. Thứ tự AUC ở trên phản ánh một phần chính lựa chọn đó. Hiệu chỉnh trên bộ hiệu chỉnh, báo số trên bộ đánh giá
  (seed khác) để tránh tự chấm điểm cho mình; cả hai vẫn cùng một bộ sinh.
- Kho IP phụ thuộc phiên bản GeoLite trên máy; từng IP đã dùng được ghi kèm quốc gia/ASN trong kết quả.
- Không có người dùng hợp lệ sống lâu dài ở nước ngoài; IP tấn công Việt Nam chỉ chiếm khoảng một phần ba số kẻ tấn công có
  lựa chọn nguồn — chưa có họ riêng cho botnet hoàn toàn trong nước.
