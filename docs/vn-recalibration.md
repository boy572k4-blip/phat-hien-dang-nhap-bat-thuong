# MR26 — Hiệu chỉnh `hybrid_cp2` cho người dùng Việt Nam + sức khoẻ mô hình đọc được

Mã: [`ml/corpus/calibrate_ml.py`](../backend/ml/corpus/calibrate_ml.py) (độ lệch miền), `MlDomainShift` trong
[`hybrid/calibration.py`](../backend/app/detection/hybrid/calibration.py), [`ml/rba/drift.py`](../backend/ml/rba/drift.py) +
[`routers/model_health.py`](../backend/app/routers/model_health.py) (sức khoẻ) · test:
[`test_ml_domain_shift.py`](../backend/tests/test_ml_domain_shift.py) và các test MR26 trong `test_hybrid_calibration.py`,
`test_hybrid_runtime.py`, `test_rba_drift.py`, `test_model_health_router.py`. Dữ liệu: bộ MR24 (**tự sinh**) chạy lại với
`--with-model-inputs` (ghi thêm điểm thô, xác suất đuôi từng thành phần, 50 đặc trưng) vào `ml/artifacts/corpus/mr26/`.

```
cd backend
venv\Scripts\python.exe -m ml.corpus.run --split both --with-model-inputs --out-dir ml/artifacts/corpus/mr26
venv\Scripts\python.exe -m ml.corpus.calibrate_ml --write
```

## 1. Chẩn đoán: mô hình KHÔNG ngược chiều — nghịch lý Simpson + lệch miền

MR24 ghi "AUC `hybrid_cp2` 0,23, ngược chiều trên lưu lượng Việt Nam". Phân tích lại từng thành phần:

| | AUC trên bộ hiệu chỉnh |
|---|---|
| Mọi lần thử gộp chung | 0,24 |
| Chỉ lần đăng nhập **thành công** | **0,88** |
| Chỉ lần **thất bại** | **0,94** |
| Thành phần `ip_tan_cong` (chấm mọi lần thử) | 0,92 |
| Thành phần `chiem_tai_khoan` / `bat_thuong` (chỉ chấm lần thành công) | 0,96 / 0,86 |

Hai thành phần chỉ chấm lần thành công (đúng thiết kế MR6: chiếm tài khoản chỉ xảy ra khi đã qua mật khẩu). Lần thất bại — đa
số là tấn công — chỉ có 1/3 thành phần chấm nên điểm thấp; lần thành công — đa số hợp lệ — có cả 3 nên điểm cao. Gộp hai nhóm
lại thì thứ hạng đảo: nghịch lý Simpson.

Phần thật sự sai là **lệch miền** ở lần thành công: điểm thô là −log10 "xác suất đuôi" so với người dùng hợp lệ CỦA RBA. Người
dùng hợp lệ Việt Nam cao hơn RBA một khoảng gần như **không đổi** ở mọi phân vị:

| Phân vị (lần thành công hợp lệ) | 50% | 90% | 95% | 99% | 99,5% |
|---|---|---|---|---|---|
| RBA (val, trọng số dân số) | 0,59 | 1,37 | 1,67 | 2,39 | 2,70 |
| Việt Nam (bộ hiệu chỉnh MR24) | 2,25 | 2,97 | 3,60 | 4,17 | 4,35 |
| Chênh lệch | 1,65 | 1,61 | 1,93 | 1,78 | 1,66 |

Nguyên nhân: mạng/quốc gia Việt Nam cực hiếm trong RBA, và các đặc trưng độ hiếm toàn cục (`rare_*`, `llr_*`) tính theo số lượt
của CHÍNH hệ thống — hệ thống nhỏ cho giá trị mô hình chưa từng thấy. Lần thất bại hợp lệ thì KHÔNG lệch lên (99%: 0,60 so với 2,24).

## 2. Cách sửa: độ lệch miền, không train lại

Δ_thành_công = Q_VN(99%) − Q_RBA(99%) = 4,168 − 2,391 = **1,78** (KTC 95% bootstrap theo biến thể: **1,61–1,97**). Lúc chấm:
xác suất = đường hiệu chỉnh RBA (MR11) của (điểm thô − Δ). 99% = 1 − FPR mục tiêu của `alert` mà MR11 dùng để đặt ngưỡng.

- **Chỉ dùng lưu lượng hợp lệ.** Đã thử fit thẳng isotonic trên nhãn của bộ MR24 (tách thành công/thất bại, quy về tỉ lệ tấn
  công của RBA): mô hình học luôn thiết kế của bộ dữ liệu — lần thất bại có điểm ≥ 1 thành "chắc chắn tấn công" (vì 92% lần
  thất bại trong bộ là tấn công) — và **ATO trên RBA từ 31,6% còn 0%**. Loại.
- **Δ thất bại = 0** (đo ra âm, chặn ở 0): không làm mô hình nhạy hơn bản đã đo trên RBA. `MlDomainShift` từ chối Δ < 0.
- **Số đo trên RBA giữ nguyên theo cấu trúc**: RBA là miền tham chiếu, Δ = 0. Mô hình, đường hiệu chỉnh và ngưỡng không đổi.
  Kiểm lại trên RBA với hồ sơ đang dùng: tái tạo đúng số MR11 khi dùng trọng số MR11 (≥ alert: `attack_ip/test` 43,4%,
  `ato/future` 36,8%, `ato/all` 29,2%; báo nhầm val 0,71%); với trọng số MR25: 43,4% / 36,8% / 30,0%, báo nhầm 0,73%.
- **Kiểm chéo trên log thật** của DB dev (không dùng để đo Δ): trung vị lần thành công của 300 lần thử gần nhất trừ trung vị RBA
  = **1,93** (230 lần thành công) — nằm trong KTC của Δ đo trên bộ MR24. Trang Model Health hiện số này.

## 3. Kết quả (bộ đánh giá MR24, 1.321 lần thử hợp lệ, 450 biến thể tấn công)

| | Trước MR26 | Sau MR26 |
|---|---|---|
| Hợp lệ bị cảnh báo — riêng `hybrid_cp2` | 24,0% | **0,15%** |
| Hợp lệ bị cảnh báo — mọi nguồn | 33,5% | **19,3%** |
| Hợp lệ bị xác thực thêm/khoá — mọi nguồn | 6,0% | **1,7%** |
| Phát hiện trung bình 15 họ tấn công | 95,1% | 94,7% |

Theo họ hợp lệ (cảnh báo trở lên / xác thực thêm-khoá, trên số lần thử): theo thói quen 21 → **0**/146; tài khoản mới 0/150;
gõ sai 34 → 6/84 (OTP 8 → 0); đổi wifi/4G 29 → 9/94; NAT văn phòng 123 → 40/390; đăng nhập đêm 28 → 21/65; đi công tác
60 → 42/93; thiết bị mới 32 → 31/56; quên mật khẩu 55 → 45/182 (OTP 23 → 20 — luật `success_after_failures`, cố ý, MR25);
VPN 61 → 61/61 nhưng OTP/khoá **48 → 2**. Tấn công: chỉ "proxy cùng nước" giảm 90% → 83%; còn lại giữ nguyên (ngủ đông vẫn 37%).

**Báo nhầm còn lại (255 lần thử) đến từ đâu:** mô hình địa lý-thời gian `ml_geo` 205 (VPN 56, đi công tác 42, NAT văn phòng 40,
thiết bị mới 31, đêm 21…), `brute_force` 25 và `success_after_failures` 20 (quên mật khẩu — MR25), `hybrid_cp2` 2, datacenter 3.
`ml_geo` một mình chỉ ra **cảnh báo** cho quản trị (trần 0,382, MR22), không cản người dùng: đó là các họ "khác thường nhưng hợp
lệ" mà bộ MR24 cố tình dồn vào (8/10 họ hợp lệ là ca khó).

**Phương án đã đo, KHÔNG áp dụng — để duyệt ở CP5:** hạ `ml_geo` một mình xuống dưới `alert` (trần 0,31): báo nhầm 19,3% →
**7,9%** nhưng phát hiện trung bình 94,7% → **81,3%** — "mô phỏng tinh vi" và "proxy cùng nước" từ 100%/83% xuống **0%**
(`ml_geo` là tín hiệu duy nhất bắt hai kiểu chiếm tài khoản này).

**Kịch bản** (cùng bộ chạy CP4, 20 kịch bản): không kịch bản tấn công nào đổi bước phát hiện hay hành động; kịch bản hợp lệ "đăng
nhập theo thói quen" (bị `hybrid_cp2` báo nhầm từ MR22, ghi là việc của MR26) **không còn bị báo**; cảnh báo 44 → 43. Kịch bản đối
chứng âm `benign_control` của MR13: **không bị báo** — xem mục 4.

## 4. `benign_control` (MR13) — hai lỗi của chính kịch bản, sửa và ghi lại

1. `_seed_history` ghi lịch sử chỉ có IP/UA thô — thiếu GeoIP/ASN, dấu vân tay thiết bị và sổ sách thiết bị/vị trí quen/giờ quen
   (cùng thiếu sót MR18 đã ghi và MR22 đã sửa cho bộ chạy kịch bản, nhưng chưa sửa ở đây). Giờ ghi như một lần thành công thật.
2. Lịch sử "quen thuộc" là 10 lần đăng nhập trong 10 giờ liên tiếp (19h–4h giờ Việt Nam) rồi im 10 ngày — mô hình địa lý báo
   "khoảng cách lần trước ↑, lệch giờ ↑" là ĐÚNG với lịch sử đó. Giờ là mỗi ngày một lần cùng giờ, lần gần nhất hôm qua.

Sau hai sửa: không bị báo. Với cùng kịch bản đã sửa, `hybrid_cp2` cho **0,29** khi không có Δ (sát ngưỡng 0,32 — chỉ cần thêm chút
bằng chứng là thành cảnh báo, đúng hiện tượng MR22 đã gặp) và **0,006** khi có Δ.

## 5. Sức khoẻ mô hình đọc được (`GET /model-health`, trang Model Health)

- **Trôi của chính hệ thống**: 300 lần thử ĐẦU của log thật so với 300 GẦN NHẤT (chưa đủ 600 thì chia đôi theo thời gian) — cùng
  nguồn, cùng cách tính. Thêm PSI của **điểm** `hybrid_cp2` và tỉ lệ lần thử mà riêng mô hình đủ cảnh báo ở mỗi cửa sổ. Trên DB
  dev: cửa sổ đầu 14–20/9, gần nhất là 300 lần thử dồn trong 30 phút ngày 28/9 (đợt chạy demo/kịch bản) → PSI lớn, đúng.
- **Khoảng cách RBA → hệ thống** (bảng riêng, nhãn "khác xa/khác vừa/gần" chứ không gọi là "trôi"), kèm Δ đang dùng (KTC, nguồn)
  và Δ ước lượng lại từ log thật. Trước MR26 trang chỉ có số này nên mọi đặc trưng luôn "trôi đáng kể" — không đọc được gì.
- ~4,6 giây cho hai cửa sổ trên DB dev (trước: ~2 giây cho một cửa sổ), cache 10 phút như cũ.

## 6. CP5

| Chỉ số | CP4 (cấu hình sau MR23; bộ MR24 đo ở MR24) | CP5 (sau MR26) |
|---|---|---|
| Hành vi vững / 25 (tín hiệu của chính nó đủ cảnh báo, đo trên 20 kịch bản) | 10 | **18** |
| Hợp lệ bị cảnh báo, bộ đánh giá MR24 — mọi nguồn | 33,5% | **19,3%** |
| Hợp lệ bị xác thực thêm/khoá — mọi nguồn | 4,5% | **1,7%** |
| Phát hiện trung bình 15 họ tấn công | 89,3% | **94,7%** |
| Độ trễ pipeline trong tiến trình, trung vị / p95 (DB tạm, 2 lượt) | 103–120 / 119–141 ms | **83–104 / 98–114 ms** |

Tám hành vi mới thành vững nhờ trọng số MR25: dò danh sách tài khoản, bot UA, Tor, thử từ nhiều quốc gia, botnet phân tán, client
kịch bản, xoay UA, nhịp đều như máy. Còn phụ thuộc hoàn cảnh: rải mật khẩu chậm, nhiều quốc gia cùng lúc, proxy cùng nước. Không
cảnh báo: datacenter, VPN (cố ý — trần MR25), đăng nhập dồn dập. Mơ hồ có chủ đích: mô phỏng tinh vi.

**Báo nhầm theo từng luật** (lần thử hợp lệ của bộ đánh giá mà luật khớp): `datacenter_ip` 44, `vpn_ip` 52 (một mình không cảnh
báo — trần), `brute_force` 25, `success_after_failures` 20, mọi luật khác **0**. Theo nguồn của báo nhầm còn lại: `ml_geo` 205,
`brute_force` 25, `hybrid_cp2` 22 (trong đó 20 là lần thử mà `success_after_failures` đã ép OTP), datacenter 3.

Độ trễ: cùng script CP4 trên bản chép DB dev (`lad_bench`, đã xoá sau khi đo), mỗi tình huống 30 lần × 2 lượt. Không chậm hơn;
phần nhanh hơn nằm trong dao động giữa các lượt và khác dữ liệu (DB dev đã dọn dữ liệu benchmark sau CP4), không quy cho MR26.

## 7. Giới hạn

- Δ đo trên **dữ liệu tự sinh** (họ hợp lệ do nhóm thiết kế, nhiều ca khó); kiểm chéo duy nhất là log của DB dev (cũng là dữ liệu
  demo). Khi có log thật, đọc Δ ước lượng trên trang Model Health; lệch khỏi KTC thì chạy lại `calibrate_ml`.
- Một Δ cho mọi phân vị là xấp xỉ: ở 99,9% chênh lệch chỉ 1,01 (bộ MR24 không có đủ ca cực hiếm hợp lệ để đo đuôi).
- Đặc trưng độ hiếm phụ thuộc quy mô dữ liệu: Δ đúng cho quy mô hiện tại; hệ thống lớn lên thì Δ giảm dần — trang Model Health
  theo dõi được.
- Bộ MR24 chạy mỗi biến thể trên DB gần như rỗng — các đặc trưng toàn cục ở đó còn cực đoan hơn hệ thống thật; Δ trên log dev
  (1,93) gần Δ trên bộ MR24 (1,78) cho thấy ảnh hưởng không lớn.

## 8. Hội đồng có thể hỏi

- **"Sao không train lại mô hình trên dữ liệu Việt Nam?"** Không có dữ liệu Việt Nam thật có nhãn; train trên dữ liệu tự sinh thì
  mô hình học thiết kế của nhóm (đã đo: fit trên nhãn MR24 làm mất 100% ATO trên RBA). Độ lệch miền chỉ dùng lưu lượng hợp lệ,
  một tham số, có KTC, và giữ nguyên mọi số đo RBA.
- **"Trừ 1,78 là đặt tay?"** Là hiệu hai phân vị 99% đo được; 99% lấy từ FPR mục tiêu 1% của ngưỡng `alert` (MR11). KTC 1,61–1,97;
  log thật của hệ thống cho 1,93.
- **"Vậy AUC 0,23 ở MR24 là sai?"** Số đúng, diễn giải sai: gộp lần thành công và thất bại gây nghịch lý Simpson. Đã đính chính
  ở MR24 và MR25.
- **"Còn 19% báo nhầm?"** Gần như toàn bộ là cảnh báo (không cản người dùng) của mô hình địa lý ở các ca khác thường thật sự (VPN,
  đi công tác, thiết bị mới, đêm); ca theo thói quen 0%. Tắt thì mất khả năng bắt chiếm tài khoản tinh vi (đã đo: 100% → 0%).
- **"PSI trước đây toàn 'trôi đáng kể'?"** So hai nguồn khác hẳn nhau (RBA và hệ thống) thì luôn vậy — giờ là khoảng cách, tách
  riêng; trôi thật là so hệ thống với chính nó.
