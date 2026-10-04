# MR29 — Luật kết hợp: đo bốn tổ hợp, giữ một

Mã: luật `anonymizer_new_device` trong [`rules_reputation.py`](../backend/app/detection/engine/rules_reputation.py), kho IP `datacenter_vn`
trong [`ml/corpus/ip_pools.py`](../backend/ml/corpus/ip_pools.py), họ dữ liệu trong [`ml/corpus/families.py`](../backend/ml/corpus/families.py),
trần trọng số `CONTEXT_ONLY` trong [`ml/corpus/calibrate_rules.py`](../backend/ml/corpus/calibrate_rules.py) · test: `test_rule_engine_rules.py`,
`test_hybrid_combine.py`, `test_calibration_corpus.py`. Dữ liệu: bộ MR24 mở rộng lần 3 (**tự sinh**, 39 họ, 1.170 biến thể mỗi phần) ở
`ml/artifacts/corpus/mr29/` (cửa `setup`) và `mr29_full/` (cửa `full`).

## 1. Vì sao cần luật kết hợp

Từ MR25, VPN và datacenter **một mình** không cảnh báo (trần 0,31) — người dùng thật hay dùng VPN công ty/đám mây. Nhưng noisy-OR coi các
bằng chứng là độc lập, nên một TƯƠNG TÁC kiểu "VPN **và** thiết bị chưa từng dùng" (mạnh hơn hẳn tổng hai phần) không được biểu diễn. Checklist
nêu bốn tổ hợp; cả bốn được đo trước trên **bộ hiệu chỉnh** (dữ liệu thiết kế), số dưới đây trên **bộ đánh giá**. Thêm 3 họ để đo công bằng
(như phòng máy đào tạo ở MR28): tấn công `vn_vps_takeover` — kẻ có mật khẩu thuê VPS ở Việt Nam để "ở cùng nước" (kho IP mới `datacenter_vn`:
dải datacenter của danh sách threat_intel mà GeoLite đặt ở Việt Nam, 89 dải); hợp lệ khó `vpn_typo` (người dùng VPN gõ sai mật khẩu bằng máy
của mình) và `vpn_new_device` (người dùng VPN đổi điện thoại mới).

| Tổ hợp | Khớp lần thử độc hại | Khớp lần thử hợp lệ | Quyết định |
|---|---|---|---|
| **Tor/VPN/datacenter + thiết bị lạ** | 987 / 4.589 | **29 / 3.846 (0,75%)** — toàn bộ "đổi điện thoại mới" | **Giữ** |
| Tor/VPN/datacenter + quốc gia mới | 1.005 | 156 (4,06%) — điểm thoát VPN đổi nước liên tục | Loại |
| Tor/VPN/datacenter + đăng nhập sai | 960 | 40 (1,04%) — người dùng VPN gõ sai | Loại |
| Bot/script UA + đăng nhập sai | 1.056 | 0 | Loại — cả 1.056 lần đã bị bot/script UA **một mình** cảnh báo (MR25): không bắt thêm gì, chỉ đếm trùng một bằng chứng |

## 2. Luật `anonymizer_new_device` — hành động thay vì cộng điểm

IP thuộc Tor/VPN/datacenter **và** User-Agent chưa từng đăng nhập thành công vào tài khoản (đã có lịch sử). Cùng nhóm "Danh tiếng hạ tầng" nên
gộp bằng max với `tor_exit`/`vpn_ip`/`datacenter_ip` (cùng một IP). Hai quyết định, đều do số đo:

- **Hành động tối thiểu `step_up`**: chủ tài khoản (vd người dùng VPN đổi điện thoại) qua được bằng OTP; kẻ chỉ có mật khẩu bị chặn — nếu
  đoán OTP thì `otp_guessing` (MR28) khoá.
- **Trọng số giữ ở mức của IP (trần 0,31)** dù số đo LR cho 0,66–0,81: phần "thiết bị mới" đã nằm trong nhóm mô hình (`ml_geo`, `hybrid_cp2`).
  Bản đầu dùng trọng số đo được (trần chung 0,57) thì cộng với mô hình thành **KHOÁ 29/44** lần đăng nhập của người dùng VPN hợp lệ đổi điện
  thoại; hạ còn 0,45–0,50 vẫn khoá 11 lần. Với `step_up` + 0,31: **0 lần khoá**, 29 lần OTP — cùng lý do "đếm trùng" như MR22 (hai mô hình
  gộp bằng max) và MR25 (nhóm danh tiếng gộp bằng max).

## 3. Kết quả

**Hành vi** (cửa `setup`): "Đăng nhập qua VPN/datacenter bằng thiết bị lạ" **83%** nhờ chính luật (phần còn lại: kẻ tấn công vô tình dùng đúng
trình duyệt của nạn nhân), báo nhầm 0,75% → **vững**; "Chiếm tài khoản qua VPS trong nước" **97%** → **vững**. VPN/datacenter một mình vẫn
không cảnh báo (cố ý). Tổng **18/23** hành vi đo được trên bộ dữ liệu vững (MR28: 16/21).

**Chỉ luật** (khi mô hình không chạy — hồ sơ dự phòng, hoặc để giải thích): đăng nhập qua VPN/datacenter **0/23 → 19/23** biến thể bị bắt, VPS
trong nước **0/30 → 29/30** — tất cả đều phải xác thực thêm; báo nhầm của lớp luật 1,20% → 1,95%, OTP/khoá 0,52% → 1,27% (đúng 29 lần OTP
của người dùng VPN đổi điện thoại).

**Cả hệ thống**: VPS trong nước 61/64 lần thử phải OTP, 3 cảnh báo; người dùng VPN đổi điện thoại 29 OTP + 15 cảnh báo, **0 khoá**. Các họ cũ
**không đổi**: 25 họ MR26 19,30% / 1,67% / 94,7%; 29 họ MR27 11,73% / 0,76%; 36 họ MR28 24,96% / 0,62%. 39 họ: 27,1% / 1,35%.
**20 kịch bản**: đổi đúng một — "tài khoản ngủ đông đăng nhập lại" (từ IP datacenter bằng thiết bị lạ) từ cảnh báo lên **xác thực thêm**;
cảnh báo 44 → 44.

## 4. Giới hạn

- Kẻ tấn công chép đúng User-Agent của nạn nhân thì né được (như mọi kiểm tra "thiết bị" dựa trên UA).
- Danh sách VPN/datacenter là bản chụp cộng đồng, không đầy đủ; dải VPS trong nước chỉ có 89 dải trong danh sách.
- Người dùng VPN đổi điện thoại phải OTP ở lần đầu — đánh đổi có chủ đích (không khoá).
- Noisy-OR giữa các nhóm vẫn coi chúng độc lập; MR29 chỉ xử lý đúng trường hợp đo được là đếm trùng.

## 5. Hội đồng có thể hỏi

- **"Sao chỉ thêm một luật kết hợp?"** Đã đo cả bốn: hai cái báo nhầm người dùng VPN thật (đổi nước, gõ sai), một cái không bắt thêm được lần
  thử nào. Thêm luật vô ích chỉ làm hệ thống khó giải thích hơn.
- **"Trọng số đo được 0,66–0,81 sao lại dùng 0,31?"** Vì phần vượt mức IP ("thiết bị mới") mô hình đã tính; cộng nữa là đếm trùng và đo được
  hậu quả (khoá người dùng thật). Hành động của luật đến từ mức tối thiểu "xác thực thêm", không từ điểm.
- **"Kẻ tấn công dùng VPS trong nước thì sao?"** Đó là ca luật này nhắm tới: 97% bị bắt nhờ chính nó, và 61/64 lần thử phải OTP.
- **"Người dùng VPN bị làm phiền?"** Chỉ khi đăng nhập qua VPN bằng thiết bị chưa từng dùng — một lần OTP; dùng máy quen qua VPN thì không.
