# MR25 — Hiệu chỉnh lại trọng số luật và mức hành động tối thiểu

Mã: [`backend/ml/corpus/calibrate_rules.py`](../backend/ml/corpus/calibrate_rules.py) · hồ sơ đang dùng:
[`rba_calibrated.json`](../backend/app/detection/hybrid/profiles/rba_calibrated.json) · test:
[`test_rule_recalibration.py`](../backend/tests/test_rule_recalibration.py) · dữ liệu: bộ MR24 ([`calibration-corpus.md`](calibration-corpus.md),
**dữ liệu tự sinh**, đo trên bộ hiệu chỉnh seed 0–29, báo số trên bộ đánh giá seed 1000–1029).

```
cd backend
venv\Scripts\python.exe -m ml.corpus.calibrate_rules          # in bảng + ghi ml/artifacts/corpus/mr25_report.json
venv\Scripts\python.exe -m ml.corpus.calibrate_rules --write  # và ghi trọng số vào hồ sơ đang dùng
```

## 1. Cách đo

- **Giữ trọng số RBA** cho 5 luật đo hợp lệ trên RBA ở MR11 (`brute_force`, `credential_stuffing`, `password_spray_slow`,
  `dormant_account_login`, `rare_network_login`). Đo lại các luật RBA không đo được (mặc định 5%) hoặc ra 0% vì mẫu quá nhỏ.
- **Không dùng độ chính xác thô** trên bộ MR24: tỉ lệ tấn công ở đó (~70% lần thử) do nhóm chọn, sẽ thổi phồng trọng số. Đo
  **tỉ số khả năng** LR = P(khớp | độc hại) / P(khớp | hợp lệ) (cộng 0,5 mỗi ô), rồi đổi về **cùng thang với trọng số RBA**:
  w = π·LR / (π·LR + 1 − π), π = 8,40% (tỉ lệ lần thử từ IP tấn công, trọng số dân số, val RBA bỏ warm-up — đúng khung MR11
  đo độ chính xác). Luật khớp như nhau ở hai phía thì w = π đúng bằng "không mang thông tin". ⚠️ Bản đầu của MR25 dùng
  π = 6,32% (sai khung dữ liệu), sửa ở MR26: 10 trọng số bị trần không đổi, `success_after_failures` 0,041 → 0,055,
  `vpn_ip` 0,203 → 0,257; bảng và số dưới đây là bản đã sửa.
- Khoảng tin cậy 95%: bootstrap 500 lần theo **biến thể** (các lần thử trong một biến thể không độc lập).
- Luật khớp < 20 lần trên bộ hiệu chỉnh giữ trọng số cũ (`multi_context_simultaneous`, `blocklist_hit`).
- **Hai trần**, đặt theo ngưỡng hành động (cùng kiểu trần 0,382 của `ml_geo`, MR22), không phải số chọn tay:
  - mọi trọng số đo trên bộ tự dựng ≤ **0,57** (ngay dưới `step_up`): một mình luật chỉ đủ **cảnh báo**. 10 luật không khớp lần
    thử hợp lệ nào nên LR chỉ bị chặn bởi cỡ mẫu (~1.300 lần thử hợp lệ) và ra 0,75–0,99 — con số đó nói "luật mạnh trên kịch
    bản nhóm tự dựng", không chứng minh được báo nhầm thật < 1/1.300. Để nguyên thì MỘT luật tự **khoá** người dùng (vd di
    chuyển bất khả thi — VPN bật/tắt là nguồn báo nhầm kinh điển của luật này).
  - `datacenter_ip`, `vpn_ip` ≤ **0,31** (ngay dưới `alert`): một mình loại IP không đủ cảnh báo. Tử số LR ("bao nhiêu phần
    tấn công đi qua datacenter") do nhóm chọn khi dựng họ tấn công; VPN công ty/đám mây là chuyện thường của người dùng thật.
- **Nhóm danh tiếng gộp bằng max** (trước là noisy-OR): Tor/datacenter/VPN/blocklist là thuộc tính của CÙNG một IP — 43/56 lần
  thử VPN hợp lệ ở bộ hiệu chỉnh khớp cả `vpn_ip` lẫn `datacenter_ip`. Cùng lập luận "hai mô hình gộp bằng max" của MR22.
- Đánh giá "sau" = **phát lại** mọi lần thử của bộ đánh giá qua đúng `combine_risk` (luật đã khớp + xác suất hai mô hình ghi sẵn
  ở MR24). Kiểm độ trung thực: phát lại với cấu hình lúc chạy MR24 ra **đúng hành động thật 4.738/4.756** lần thử; 18 lần khác
  đều là lần khớp ≥ 2 luật danh tiếng (đúng thay đổi max ở trên), **0** khác không giải thích được.

## 2. Trọng số trước / sau

| Luật | Trước (nguồn) | LR → w đo được | KTC 95% | Sau | Khớp ở bộ đánh giá: độc hại / hợp lệ |
|---|---|---|---|---|---|
| `brute_force` | 0,101 (rba) | — | 0,00–0,26 | **0,101** rba | 489 / 25 |
| `credential_stuffing` | 0,346 (rba) | — | 0,30–0,40 | **0,346** rba | 339 / 0 |
| `password_spray_slow` | 0,102 (rba) | — | 0,08–0,13 | **0,102** rba | 231 / 0 |
| `distributed_bruteforce` | 0 (rba, n = 2) | 0,899 | 0,84–0,93 | **0,570** trần | 125 / 0 |
| `username_enumeration` | 0,05 (mặc định) | 0,944 | 0,91–0,96 | **0,570** trần | 243 / 0 |
| `success_after_failures` | 0 (rba) | 0,055 | 0,03–0,09 | **0,055** | 43 / 20 |
| `bot_user_agent` | 0,05 (mặc định) | 0,752 | 0,57–0,84 | **0,570** trần | 21 / 0 |
| `scripted_client` | 0,05 (mặc định) | 0,985 | 0,98–0,99 | **0,570** trần | 1.001 / 0 |
| `ua_rotation` | 0,05 (mặc định) | 0,892 | 0,84–0,92 | **0,570** trần | 85 / 0 |
| `regular_rhythm` | 0,05 (mặc định) | 0,855 | 0,79–0,89 | **0,570** trần | 76 / 0 |
| `impossible_travel` | 0,05 (mặc định) | 0,965 | 0,95–0,97 | **0,570** trần | 395 / 0 |
| `multi_context_simultaneous` | 0 (rba) | — (< 20 lần khớp) | — | **0** rba | 3 / 0 |
| `country_hop` | 0 (rba) | 0,956 | 0,94–0,97 | **0,570** trần | 300 / 0 |
| `dormant_account_login` | 0,025 (rba) | — | 0,02–0,04 | **0,025** rba | 24 / 0 |
| `rare_network_login` | 0,026 (rba) | — | 0,00–0,05 | **0,026** rba | 0 / 0 |
| `tor_exit` | 0,05 (mặc định) | 0,966 | 0,95–0,97 | **0,570** trần | 517 / 0 |
| `datacenter_ip` | 0,05 (mặc định) | 0,432 | 0,34–0,56 | **0,310** trần IP | 870 / 44 |
| `vpn_ip` | 0,05 (mặc định) | 0,257 | 0,17–0,38 | **0,257** | 387 / 52 |
| `blocklist_hit` | 0,05 (mặc định) | — (không có mẫu) | — | **0,05** + `min_action=lock` | 0 / 0 |

Mọi trọng số trong hồ sơ giờ có trường `source`: `rba` / `default` / `corpus_mr24` / `corpus_mr24_capped`.

## 3. Mức hành động tối thiểu — chốt bằng số đo (giữ cả năm mức của MR21)

| Luật | Mức | Lần thử hợp lệ bị chính luật ép (bộ đánh giá) | Quyết định |
|---|---|---|---|
| `credential_stuffing` | alert | 0 (kể cả 5–15 đồng nghiệp sau một NAT văn phòng) | giữ |
| `impossible_travel` | alert | 0 (kể cả đi công tác bằng máy bay) | giữ |
| `blocklist_hit` | lock | không đo được (không có mẫu) — quyết định của quản trị viên | giữ |
| `success_after_failures` | step_up | 20 (1,5%) — toàn bộ "quên mật khẩu" (sai 4–6 lần rồi đúng) | giữ: bỏ thì chỉ 27% biến thể "đoán trúng mật khẩu" còn bị luật chặn |
| `brute_force` | alert | 25 (1,85%) — toàn bộ "quên mật khẩu" | giữ, xem dưới |

`brute_force`: đã thử bỏ mức ép (báo nhầm lớp luật 3,4% → 1,5%), nhưng 30% biến thể dò mật khẩu từ IP dân cư Việt Nam bằng
trình duyệt thường không còn được luật tự cảnh báo, và "nhập sai 5 lần" không ra cảnh báo nào — đúng thứ người xem demo sẽ thử.
Mức `alert` chỉ hiện cho quản trị, không cản người dùng. Số lần sai một mình **không thể** phân biệt "quên mật khẩu 5–6 lần"
với "dò mật khẩu ngắn 5–12 lần"; phân biệt cần thêm ngữ cảnh (máy/vị trí quen — kiểu "smart lockout") → ứng viên MR27–MR30.

## 4. Kết quả trên bộ đánh giá (1.321 lần thử hợp lệ, 450 biến thể tấn công)

| | Trước (hành động thật MR24) | Sau MR25 |
|---|---|---|
| Lần thử hợp lệ bị cảnh báo trở lên — **chỉ luật** | 3,4% | **3,4%** (100% là họ "quên mật khẩu"; 9 họ hợp lệ còn lại: **0%**) |
| … trong đó bị xác thực thêm/khoá — chỉ luật | 1,5% | 1,5% |
| Lần thử hợp lệ bị cảnh báo trở lên — **mọi nguồn** | 33,5% | 33,5% |
| … bị xác thực thêm/khoá — mọi nguồn | 4,5% | **6,0%** ⚠️ |
| Tỉ lệ phát hiện trung bình 15 họ tấn công — chỉ luật | 58,4% | **71,8%** |
| Tỉ lệ phát hiện trung bình 15 họ tấn công — mọi nguồn | 89,3% | **95,1%** |

Họ tấn công tăng: dò danh sách tài khoản 70% → 100%, bot/công cụ tự động 43% → 100% (mọi nguồn); chỉ luật: rải mật khẩu chậm
3% → 60%, đăng nhập qua Tor/VPN 0% → 23%. Còn thấp: tài khoản ngủ đông 37% (mọi nguồn).

⚠️ **Điều kiện "xong" (≤ 1%) CHƯA đạt**:
- Lớp luật: 3,4%, toàn bộ là ca "quên mật khẩu" ở trên (cố ý: cảnh báo cho quản trị + OTP khi đăng nhập được).
- Mọi nguồn: 33,5% — gần như toàn bộ do `hybrid_cp2` → việc của **MR26** (giải quyết ở [`vn-recalibration.md`](vn-recalibration.md):
  còn 19,3%, OTP/khoá 1,7%). "AUC 0,23" ghi ở MR24 là nghịch lý Simpson, không phải mô hình ngược chiều — xem tài liệu MR26.
- Người dùng VPN hợp lệ bị xác thực thêm/khoá tăng 29 → 48/61 lần thử: trọng số datacenter (0,31) cộng lên nền 0,45–0,67 mà
  `hybrid_cp2` cho IP VPN. Một mình trọng số này không cảnh báo (họ `vpn_user` chỉ luật: 0%). Sau MR26: 1/61.

**20 kịch bản** (cùng bộ chạy CP4): 3 kịch bản hợp lệ không đổi; 4 kịch bản trước đây lọt giờ bị bắt (dò danh sách tài khoản,
bot UA, Tor, nhảy nhiều quốc gia), nhịp đều như máy bị bắt từ bước 2 (trước: bước 5); datacenter/VPN một mình vẫn `allow` (đúng
trần); 8 kịch bản tấn công lên `lock` (hai bằng chứng mạnh cùng lúc); E2E TC1 giữ 1 cảnh báo `step_up`. Tổng cảnh báo 40 → 44.

## 5. Giới hạn

- Trọng số mới đo trên **dữ liệu tự sinh** — các họ tấn công/hợp lệ do nhóm thiết kế; LR phụ thuộc thành phần đó. Vì vậy có
  hai trần ở mục 1 và mọi trọng số ghi nguồn. Không có ca hợp lệ dùng Tor hay công cụ tự động trong bộ MR24.
- Noisy-OR giữa các luật khác nhóm vẫn coi chúng độc lập (vd `scripted_client` và `bot_user_agent` cùng đọc chuỗi UA) — đo thử
  "max theo từng nhóm luật": báo nhầm không đổi, chỉ ít ca bị khoá hơn (lần thử độc hại bị khoá, chỉ luật: 28,9% → 23,8%); chưa
  đổi để giữ nguyên công thức và số đã công bố của MR11.

## 6. Hội đồng có thể hỏi

- **"Trọng số 0,57 cho 10 luật — vậy là đặt tay?"** Số đo là cột "LR → w" (0,75–0,99, có KTC). 0,57 là **trần chính sách**
  suy ra từ ngưỡng `step_up` (58): dữ liệu tự sinh chỉ đủ nói luật mạnh, không đủ để một luật một mình khoá người dùng thật.
  Bỏ trần: báo nhầm không đổi (không luật nào trong 10 luật đó khớp lần thử hợp lệ), chỉ nhiều ca tấn công bị khoá hơn.
- **"Sao không dùng độ chính xác như MR11?"** Tỉ lệ tấn công trong bộ MR24 do nhóm chọn; LR không phụ thuộc tỉ lệ đó, rồi quy về
  tỉ lệ tấn công của RBA để cùng thang với 5 trọng số giữ lại.
- **"Nhập sai 5 lần bị cảnh báo là báo nhầm?"** Cảnh báo cho quản trị, không cản người dùng; đăng nhập được sau ≥ 5 lần sai thì
  phải OTP. Đã đo phương án bỏ — đánh đổi ở mục 3.
- **"Sao VPN không bị cảnh báo?"** Trần nhóm IP: một mình VPN/datacenter không đủ (người dùng thật hay dùng VPN công ty); kèm
  tín hiệu khác thì đủ — họ "đăng nhập qua Tor/VPN" bị bắt 100% khi có cả mô hình. Riêng Tor một mình đã đủ cảnh báo (0,57).
- **"Báo nhầm 33%?"** Đúng, đo thật ở MR25; nguyên nhân là `hybrid_cp2` học trên RBA (gần như không có mạng Việt Nam) → sau MR26
  còn 19,3%, phần lớn là cảnh báo (không cản) của mô hình địa lý-thời gian ở các họ "khác thường nhưng hợp lệ".
