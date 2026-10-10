# MR28 — Mở rộng hành vi, đợt 2: đoán mã OTP, cố thử khi đang bị khoá, một IP vào nhiều tài khoản

> **Ghi chép theo thời điểm (MR28)** — mô tả và số đo lúc đó, giữ để truy vết; hệ thống đã thay đổi ở các MR sau (đến MR36). Bản hiện hành: [`architecture.md`](architecture.md) · mục lục tài liệu: [`README.md`](README.md).

Mã: [`app/detection/gate.py`](../backend/app/detection/gate.py) (cửa của `/login` và `/login/verify-otp`), ba luật cuối
[`rules_auth.py`](../backend/app/detection/engine/rules_auth.py), chỉ mục mới trong [`indexes.py`](../backend/app/detection/engine/indexes.py),
router [`auth.py`](../backend/app/routers/auth.py), bộ chạy [`ml/corpus/run.py`](../backend/ml/corpus/run.py) (cửa `/login`, bước OTP,
khoá dựng sẵn), [`ml/corpus/behaviors.py`](../backend/ml/corpus/behaviors.py) · test: `test_auth_mr28.py`, `test_rule_engine_rules.py`,
`test_calibration_corpus.py`, `test_behaviors_mr28.py`, `test_login_context.py`. Dữ liệu: bộ MR24 mở rộng lần 2 (**tự sinh**, 36 họ,
1.080 biến thể mỗi phần) ở `ml/artifacts/corpus/mr28/` (cửa `setup`) và `mr28_full/` (cửa `full`).

```
cd backend
venv\Scripts\python.exe -m ml.corpus.run --split both --with-model-inputs --out-dir ml/artifacts/corpus/mr28
venv\Scripts\python.exe -m ml.corpus.run --split evaluation --with-model-inputs --gate full --out-dir ml/artifacts/corpus/mr28_full
venv\Scripts\python.exe -m ml.corpus.behaviors --write
```

## 1. Vấn đề: hai loại lần thử không ai nhìn thấy

- **Lần thử vào tài khoản/IP đang bị khoá**: `POST /login` trả 423 ngay, trước cả bước kiểm tra mật khẩu (MR16) — chỉ ghi audit
  `reject_blocked_login`, không qua phát hiện. Kẻ tấn công cứ thử, hết 30 phút khoá lại được 5 lần thử mới như chưa có gì.
- **Lần nhập sai mã OTP**: `POST /login/verify-otp` chỉ tăng bộ đếm của TỪNG mã (tối đa 5 lần/mã). Kẻ đã có mật khẩu chỉ cần đăng nhập
  lại để lấy mã mới rồi đoán tiếp — không giới hạn, không ai biết.

`app/detection/gate.py` ghi hai loại này (kèm audit `reject_blocked_login` / `verify_otp_failed`) vào CHÍNH bộ đếm cửa sổ thời gian mà
rule engine đọc (`blk:u`, `blk:ip`, `otpf:u`); luật chấm ở lần đăng nhập KẾ TIẾP đi qua pipeline — giữ nguyên "một bộ luật" (MR21), không
có đường phát hiện thứ hai. Lỗi bộ đếm (Redis) không bao giờ chặn đăng nhập.

## 2. Ba luật mới (ngưỡng đặt trước khi đo)

| Luật | Điều kiện | Hành động tối thiểu | Vì sao |
|---|---|---|---|
| `otp_guessing` | ≥ 10 lần sai mã OTP / 24 giờ (= hết lượt 2 mã) | **lock** | Người có mật khẩu đúng mà không có mã: mật khẩu đã lộ. Mỗi mã 5 lần đoán, sau 2 mã khoá 30 phút → đoán 6 chữ số thành bất khả thi; một mã hết lượt có thể là chính chủ đọc nhầm mã cũ. |
| `blocked_retry` | ≥ 10 lần bị từ chối vì khoá / 1 giờ (theo tên đăng nhập, không phân biệt hoa/thường; hoặc theo IP) | **step_up** | Chấm ở lần thử đầu tiên sau khi khoá hết hạn. Không khoá lại: chủ tài khoản có OTP qua được, kẻ chỉ có mật khẩu thì không; khoá lại sẽ cho kẻ tấn công cách giữ chủ tài khoản bị khoá mãi. |
| `multi_account_success` | Một IP vào được ≥ 5 tài khoản / 1 giờ, mỗi tài khoản đều từ IP **và** thiết bị lạ với nó (cả lần thử này) | — (bằng chứng) | Kẻ đã có danh sách mật khẩu đúng vào từng tài khoản. NAT văn phòng (IP quen) và wifi hội nghị (máy của mình) không tính. |

`AccountHistory` có thêm `known_ips` (IP từng đăng nhập thành công) — dựng từ đúng nhóm thành công mà MR20 đã truy vấn, không thêm truy vấn.
Cả ba không đo được trên RBA (không có OTP, không có khoá; IP và UA của RBA là tổng hợp — 52% lần đăng nhập hợp lệ có UA mới).

## 3. Bộ dữ liệu: cửa `/login` và hai chế độ

Bộ chạy tái hiện cửa `/login` bằng CHÍNH các hàm của `gate.py`: bước `otp_fail` ghi như `verify-otp`; khoá dựng sẵn của kịch bản
(`Variant.locks`) chặn ở cửa. Thêm 7 họ: tấn công `otp_guessing` (1–4 lượt × 5 mã sai, rồi đăng nhập lại — giả định bị đòi OTP),
`locked_hammering` (5–40 lần thử trong lúc khoá, rồi thử tiếp sau khi hết khoá), `account_checker` (3–12 tài khoản từ một IP, một công
cụ); hợp lệ khó `otp_typo` (sai 1–5 mã, tối đa 7), `locked_owner` (chủ bị khoá nhầm thử lại 1–8 lần), `training_lab` (phòng máy đào tạo:
IP và máy đều lạ), `event_wifi` (wifi hội nghị, máy của mình).

**Phát hiện về phương pháp:** khi MỌI khoá chặn ở cửa (như chạy thật), hệ thống thường đã khoá kẻ tấn công bằng tín hiệu khác trước khi
tín hiệu riêng của hành vi đủ số lần để chấm — botnet phân tán 30/30 biến thể, nhịp đều như máy 25/30, đăng nhập dồn dập 22/30 bị "chặn
sớm". Đo "tín hiệu riêng có bắt được không" phải ở chế độ cửa **`setup`** (chỉ khoá dựng sẵn chặn ở cửa; khoá hệ thống tạo trong biến thể
chỉ là bằng chứng `blocklist_hit` — đúng ngữ nghĩa MR24–MR27); số của cả hệ thống báo thêm ở chế độ **`full`**.

## 4. Kết quả (bộ đánh giá, cửa `setup`)

| Hành vi | Phát hiện nhờ chính tín hiệu | Mọi nguồn | Báo nhầm của chính tín hiệu | Vững |
|---|---|---|---|---|
| **Đoán mã OTP liên tục** | **83%** (biến thể 1 lượt là dưới ngưỡng) | 100% | **0%** (gõ sai OTP: 0) | **✓** |
| **Cố đăng nhập khi đang bị khoá** | **83%** (biến thể < 10 lần là dưới ngưỡng) | 100% | **0%** (chủ bị khoá nhầm thử lại: 0) | **✓** |
| Một IP đăng nhập thành công vào nhiều tài khoản | 0% | 100% | 0% | ✗ |

Trọng số (phương pháp MR25 trên bộ hiệu chỉnh): `otp_guessing`, `blocked_retry` LR → 0,79–0,93, giữ trần **0,57**; `multi_account_success`
**0,056** (KTC 0,03–0,10) — phòng máy đào tạo khớp gần như mọi lần (luật một mình không bao giờ cảnh báo, chỉ góp bằng chứng). Đây là giới
hạn thật: một IP vào nhiều tài khoản bằng IP và máy lạ thì phòng máy đào tạo và kẻ tấn công trông giống hệt — cần quản trị viên khai báo
mạng nội bộ tin cậy (chưa làm). Kẻ tấn công trong họ này vẫn bị bắt 100% nhờ tín hiệu khác (vị trí/thiết bị lạ, công cụ tự động...).

Tổng **16/21** hành vi đo được trên bộ dữ liệu là vững (MR27: 14/18). **Không đổi** trên các họ cũ: 25 họ của MR26 — hợp lệ bị cảnh báo
19,3%, OTP/khoá 1,67%, phát hiện 94,7%; 29 họ của MR27 — 11,7% / 0,76%. Họ hợp lệ mới: gõ sai OTP 1/34 lần thử bị cảnh báo, chủ bị khoá
nhầm 2/30; wifi hội nghị 261/306 và phòng máy 310/317 — **toàn bộ do `ml_geo`** (vị trí mới, chỉ cảnh báo, không cản: OTP/khoá 0), giữ
theo quyết định CP5. 36 họ gộp: 25,0% / 0,62%.

**Như chạy thật (cửa `full`):** mọi họ tấn công trừ "ngủ đông" (37%) và "proxy cùng nước" (83%) bị bắt 100%; báo nhầm không đổi (cửa hầu
như không chặn người dùng hợp lệ). **20 kịch bản**: không kịch bản nào đổi (cảnh báo 44 → 44).

## 5. Giới hạn

- `otp_guessing` giả định kẻ tấn công được đòi OTP. Trên hệ thống này, kẻ có mật khẩu đúng đăng nhập từ một thành phố khác ở Việt Nam
  thường chỉ bị CẢNH BÁO (mô hình địa lý một mình, trần 0,382 — MR22), tức là vào được, không cần OTP. Đó là đánh đổi của MR22 (không làm
  phiền người đi công tác), không phải lỗi của luật này.
- `blocked_retry` khoá theo tên đăng nhập: kẻ tấn công có thể khiến chủ tài khoản phải OTP sau mỗi lần khoá hết hạn (không khoá được chủ).
- Bước OTP và khoá dựng sẵn do nhóm mô phỏng; ngưỡng đặt trước nhưng họ dữ liệu dựng quanh ngưỡng (có biến thể dưới ngưỡng).

## 6. Hội đồng có thể hỏi

- **"Sai OTP nhiều lần thì sao?"** Mỗi mã 5 lần; hai mã hết lượt trong 24 giờ thì lần đăng nhập kế tiếp bị khoá 30 phút và quản trị viên
  được báo "mật khẩu có thể đã lộ". Đoán 6 chữ số với ~20 lần/giờ mất hàng năm.
- **"Tài khoản bị khoá mà kẻ tấn công vẫn thử?"** Mỗi lần bị từ chối được đếm; hết khoá, lần thử đầu tiên phải OTP. Không khoá lại để kẻ
  tấn công không giữ được chủ tài khoản ngoài cửa mãi.
- **"Sao luật 'một IP vào nhiều tài khoản' không tự cảnh báo?"** Đo được: phòng máy đào tạo trông giống hệt (trọng số 0,056). Thà là bằng
  chứng yếu, giải thích được, còn hơn cảnh báo mỗi buổi đào tạo. Kẻ tấn công vẫn bị bắt nhờ tín hiệu khác.
- **"Sao phải đo hai chế độ?"** Chạy thật thì hệ thống thường đã khoá kẻ tấn công trước khi luật riêng đủ dữ kiện — tốt cho an ninh nhưng
  làm số "tín hiệu riêng" vô nghĩa. Mỗi chế độ trả lời một câu hỏi khác nhau; cả hai đều báo.
