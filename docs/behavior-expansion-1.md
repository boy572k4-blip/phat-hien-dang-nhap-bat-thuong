# MR27 — Mở rộng hành vi, đợt 1

Mã: [`ml/corpus/behaviors.py`](../backend/ml/corpus/behaviors.py) (đánh giá "hành vi vững"), luật trong
[`rules_auth.py`](../backend/app/detection/engine/rules_auth.py) / [`rules_automation.py`](../backend/app/detection/engine/rules_automation.py),
cổng "cùng phiên" trong [`pipeline.py`](../backend/app/detection/pipeline.py), họ dữ liệu mới trong
[`ml/corpus/families.py`](../backend/ml/corpus/families.py) · test: `test_rule_engine_rules.py`, `test_hybrid_combine.py`,
`test_pipeline_mr22.py`, `test_behaviors.py`, `test_calibration_corpus.py`. Dữ liệu: bộ MR24 mở rộng (**tự sinh**, 29 họ, 870 biến
thể mỗi phần) chạy lại vào `ml/artifacts/corpus/mr27/`; RBA (**tổng hợp**) cho phép đo báo nhầm trên quy mô lớn.

```
cd backend
venv\Scripts\python.exe -m ml.corpus.run --split both --with-model-inputs --out-dir ml/artifacts/corpus/mr27
venv\Scripts\python.exe -m ml.corpus.behaviors --write
```

## 1. Định nghĩa "vững" — đo được, đặt trước khi đo

Theo giai đoạn I của checklist: kịch bản tấn công có cảnh báo nhờ **chính** tín hiệu của nó, và lưu lượng hợp lệ khó không vượt mục
tiêu báo nhầm. Cụ thể: chấm lại từng lần thử bằng `combine_risk` **chỉ với tín hiệu riêng** của hành vi (luật của nó — tôn trọng
shadow/enforce, hành động tối thiểu, cờ `forces` — hoặc nguồn mô hình), rồi:
- **phát hiện nhờ chính tín hiệu** ≥ 50% biến thể tấn công (bộ đánh giá có cả biến thể dưới ngưỡng, cố ý);
- **báo nhầm của chính tín hiệu** ≤ 1% lần thử của các họ hợp lệ.

## 2. Thay đổi

1. **Phạm vi ASN không ép hành động tối thiểu** (`Finding.forces` / `RuleHit.forces`). Đo trên RBA (val, lần khớp trên dòng bình
   thường / 10.000 đăng nhập hợp lệ thành công): `credential_stuffing` phạm vi IP **0,7**, phạm vi ASN **684**; `password_spray_slow`
   IP 24, ASN 532. Một nhà mạng gom hàng triệu người dùng thật (Viettel/VNPT ở Việt Nam). Phạm vi ASN vẫn là bằng chứng có trọng
   số, chỉ không tự ép `alert`. Trước MR27, trên RBA, `credential_stuffing` ép cảnh báo ở ~6,8% dòng bình thường — số này không có
   trong báo cáo MR11 (đo trên xác suất gộp, chưa tính hành động tối thiểu của MR21).
2. **`password_spray_slow`**: thêm điều kiện **tỉ lệ thành công của IP ≤ 0,2** (đặt trước khi đo — NAT văn phòng lớn có nhiều người gõ
   sai rải rác nhưng phần lớn lần thử thành công; IP rải mật khẩu gần như không bao giờ) và hành động tối thiểu **`alert` ở phạm vi
   IP**. Replay RBA (đến hết 08/2020): phạm vi IP từ 23,6 → **7,8**/10.000 (train), 24,1 → **10,7** (val); độ chính xác train 21% → 39%.
3. **Luật mới `success_burst`** ("Đăng nhập thành công dồn dập", nhóm Tự động hoá, T1078): ≥ **8** lần thành công vào một tài khoản
   trong **10 phút** (đặt trước khi đo). Thay cho kiểu `rapid_fire` của tầng 3 (bắt 0%). Trọng số đo bằng phương pháp MR25: LR → 0,72–0,97,
   giữ trần **0,57** (một mình chỉ cảnh báo). Chỉ mục mới `ok:u:<tài khoản>`.
4. **Cổng "cùng phiên" của `ml_geo`**: lần thử ≤ 30 phút sau một lần THÀNH CÔNG cùng IP + cùng thiết bị thì mô hình địa lý-thời gian
   không chấm lại. Phát hiện khi đo: sau khi MR23 sửa lệch đặc trưng `minutes_since_last_login`, mô hình (học trên dữ liệu chỉ có
   khoảng cách ngắn ở nhãn bất thường `rapid_fire`) cảnh báo **53%** lần chính chủ đăng nhập lại vài lần liền — cũng là điều người
   xem demo sẽ gặp khi đăng xuất rồi đăng nhập lại.
5. **Bộ dữ liệu** thêm 4 họ: `distributed_botnet_local` (5–10 IP dân cư Việt Nam, nhiều nhà mạng — MR18 chỉ bắt botnet nước ngoài
   nhờ khoảng cách địa lý), `login_burst` (5–20 lần thành công bằng thông tin đã đánh cắp, có biến thể dưới ngưỡng); hợp lệ khó:
   `relogin` (đăng nhập lại 2–8 lần liền, 8 lần ở ~10% biến thể), `office_nat_day` (15–25 nhân viên sau một NAT cả ngày, 60–90% gõ sai
   một lần — đúng dáng rải mật khẩu).

**Vì sao ngưỡng 8 mà không phải 3–4 như nhãn `rapid_fire` cũ:** replay RBA cho thấy ≥ 3 lần thành công/10 phút khớp **352–449** lần trên
10.000 đăng nhập hợp lệ (3,5–4,5%), ≥ 8 lần chỉ **6,5–12,7**. Đăng nhập lại 3–4 lần là hành vi thường của người thật; độ chính xác ở mọi
ngưỡng xấp xỉ tỉ lệ nền (thời điểm RBA có thành phần ngẫu nhiên — không dùng RBA để đo trọng số luật này).

## 3. Kết quả trên bộ đánh giá (29 họ, 3.043 lần thử hợp lệ)

| Hành vi | Phát hiện nhờ chính tín hiệu | Mọi nguồn | Báo nhầm của chính tín hiệu | Vững |
|---|---|---|---|---|
| Dò mật khẩu một tài khoản | 100% | 100% | 0,82% (riêng "quên mật khẩu": 13,7%) | ✓ ⚠️ |
| Nhồi thông tin đăng nhập | 100% | 100% | 0% | ✓ |
| **Rải mật khẩu chậm** | **100%** | 100% | **0%** (kể cả NAT văn phòng cả ngày) | **✓ mới** |
| Botnet phân tán (IP nước ngoài/ẩn danh) | 87% | 100% | 0% | ✓ |
| **Botnet phân tán cùng khu vực (IP Việt Nam)** | **83%** | 100% | 0% | **✓ mới đo** |
| Dò danh sách tài khoản | 100% | 100% | 0% | ✓ |
| Thành công sau chuỗi sai | 100% | 100% | 0,66% (riêng "quên mật khẩu": 11,0%) | ✓ ⚠️ |
| Xoay User-Agent | 100% | 100% | 0% | ✓ |
| Nhịp thử đều như máy | 67% | 100% | 0% | ✓ |
| Bot / client kịch bản | 100% | 100% | 0% | ✓ |
| Thử từ nhiều quốc gia | 100% | 100% | 0% | ✓ |
| Đăng nhập qua Tor | 100% (7 biến thể) | 100% | 0% | ✓ |
| Di chuyển bất khả thi | 93% | 100% | 0% | ✓ |
| **Đăng nhập thành công dồn dập** | **80%** (đúng các biến thể ≥ 8 lần) | 100% | **0,03%** ("đăng nhập lại": 0,8%) | **✓ mới** |
| Đăng nhập qua VPN/datacenter | 0% (cố ý — trần MR25) | 100% | 0% | ✗ |
| Tài khoản ngủ đông | 37% | 37% | 10,2% (`ml_geo`) | ✗ |
| Proxy cùng nước, nhà mạng lạ | 83% | 83% | 10,2% (`ml_geo`) | ✗ |
| Mô phỏng tinh vi | 100% | 100% | 10,2% (`ml_geo`) | ✗ (mơ hồ có chủ đích) |

**14/18** hành vi đo được trên bộ dữ liệu là vững. ⚠️ Hai hành vi dò mật khẩu chỉ dưới 1% vì bộ hợp lệ có nhiều họ khác; với riêng họ
"quên mật khẩu" (sai 4–6 lần rồi đúng) thì 11–14% — đếm số lần sai không phân biệt được hai trường hợp (MR25). Ba hành vi dựa vào `ml_geo`
không vững theo định nghĩa này vì `ml_geo` một mình cảnh báo (không cản) ở các họ khác thường nhưng hợp lệ — giữ theo quyết định CP5.

**Cả hệ thống**, trên đúng 25 họ của MR26: hợp lệ bị cảnh báo **19,3%**, OTP/khoá **1,67%**, phát hiện trung bình **94,7%** — **không đổi**.
Họ hợp lệ mới: "đăng nhập lại" 38/121 lần thử bị cảnh báo (trước cổng "cùng phiên": 64) — cùng máy với lần ngay trước **0/57**; 28 là
thiết bị chưa từng dùng (đúng mục đích `ml_geo`, như họ "thiết bị mới"); **10 là quay lại máy quen ngay sau khi vừa đăng nhập bằng máy
khác** (cổng chỉ áp khi cùng máy, nên khoảng cách vài chục giây vẫn bị coi là lạ — giới hạn còn lại, mục 4). "NAT văn phòng cả ngày"
64/1.601 (`ml_geo`: lệch giờ quen, nhân viên đăng nhập rải trong 8 giờ). 29 họ gộp: 11,7% / 0,76%.

**20 kịch bản** (bộ chạy CP4): không kịch bản nào đổi bước phát hiện hay hành động; "rải mật khẩu chậm" cảnh báo đủ 18/18 tài khoản
(trước 17); cảnh báo 43 → 44. **RBA**: cảnh báo bị ép trên dòng bình thường từ ~685 xuống ~11 trên 10.000 (phạm vi IP của nhồi thông tin
0,7 + rải mật khẩu có điều kiện 10,7); `success_burst` một mình cảnh báo thêm ~6,5/10.000 (không ép, qua trọng số).

## 4. Giới hạn

- Họ dữ liệu mới do nhóm thiết kế; ngưỡng luật đặt trước khi đo nhưng các họ được dựng quanh ngưỡng (có biến thể dưới ngưỡng).
- `success_burst` không đo được trên RBA (thời điểm ngẫu nhiên); trọng số chỉ từ bộ tự sinh — bị trần 0,57.
- Kẻ tấn công rải mật khẩu từ CHÍNH một NAT có nhiều người dùng thật (tỉ lệ thành công cao) sẽ lọt điều kiện mới — đánh đổi có chủ đích.
- `ml_geo` vẫn chấm cả lần thử thất bại (học chỉ trên lần thành công) — một phần báo nhầm ở "NAT văn phòng cả ngày" là lần gõ sai; chưa đổi.
- Gốc của báo nhầm "đăng nhập lại" là mô hình địa lý-thời gian học trên dữ liệu (Tuần 7) chỉ có khoảng cách ngắn ở nhãn bất thường; cổng
  "cùng phiên" chỉ chữa trường hợp cùng máy. Sửa tận gốc cần train lại mô hình với lưu lượng đăng nhập lại hợp lệ — không làm ở MR27 (giữ
  nguyên số đo đã công bố của MR22).

## 5. Hội đồng có thể hỏi

- **"Sao phạm vi ASN không được tự cảnh báo?"** Một nhà mạng là hàng triệu người; đo trên RBA phạm vi ASN báo nhầm gấp ~1.000 lần phạm
  vi IP. Vẫn là bằng chứng — kèm tín hiệu khác thì vẫn cảnh báo.
- **"Ngưỡng 0,2 / 8 lần / 30 phút lấy đâu ra?"** Đặt trước khi đo, theo lập luận vận hành (NAT, hết phiên); số đo sau đó (RBA và bộ
  MR24) ở mục 2–3 — kể cả đường cong theo từng ngưỡng để thấy không chọn ngưỡng cho đẹp.
- **"Tầng 3 từng có `rapid_fire`, sao bỏ?"** Nhãn đó là 3–4 lần đăng nhập lại cùng máy — trên RBA chuyện này xảy ra ở 3,5–4,5% đăng
  nhập hợp lệ. Đăng nhập dồn dập thật (≥ 8 lần/10 phút) giờ có luật riêng, giải thích được.
- **"Không chấm lại lần đăng nhập thứ hai thì kẻ tấn công lợi dụng được?"** Chỉ bỏ qua khi CÙNG IP và CÙNG thiết bị với lần thành
  công ngay trước — ngữ cảnh đó vừa được chấm; đổi IP hoặc thiết bị là chấm lại; đăng nhập dồn dập do `success_burst` bắt.
