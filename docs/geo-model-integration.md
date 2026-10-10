# Một lớp ML: mô hình địa lý-thời gian thành nguồn bằng chứng của hybrid (MR22)

> **Ghi chép theo thời điểm (MR22)** — mô tả và số đo lúc đó, giữ để truy vết; hệ thống đã thay đổi ở các MR sau (đến MR36). Bản hiện hành: [`architecture.md`](architecture.md) · mục lục tài liệu: [`README.md`](README.md).

> **Cập nhật MR23** ([`incident-unification.md`](incident-unification.md) mục 5): (1) trên luồng thật, đặc trưng
> `minutes_since_last_login` của mọi lần đăng nhập thành công là 0 từ Tuần 7 (truy vấn thấy chính lần thử vừa ghi) — đã sửa,
> có test so khớp với đặc trưng lúc train; số đo trên tập test ở dưới là offline nên không bị ảnh hưởng. (2) Tên họ tấn công
> "địa lý-thời gian" của MR22 dài 67 ký tự > cột 64 — Postgres từ chối ghi cảnh báo (lần đăng nhập thành công trả 500) — đã
> rút gọn. (3) Cột `login_events.ml_anomaly_score` đã xoá (MR23), mô hình không còn được gọi cho tài khoản dưới cổng.

Trước MR22, mô hình địa lý-thời gian (tầng 3, Isolation Forest trên 9 đặc trưng giờ/vị trí/thiết bị/khoảng cách — Tuần 7,
[`ml-evaluation.md`](ml-evaluation.md), [`model-b-geo-time.md`](model-b-geo-time.md)) chạy **song song** với hybrid risk
engine và tự tạo cảnh báo `ml_anomaly` riêng: một lần đăng nhập có thể ra hai cảnh báo với hai điểm khác nhau, và
**lần đăng nhập đầu tiên của mọi tài khoản mới đều bị báo** (đo ở MR18).

MR22 đưa mô hình đó vào hybrid làm nguồn bằng chứng thứ hai của nhóm ML, tên `ml_geo`, cạnh mô hình `hybrid_cp2`:

```
biên độ của Isolation Forest ──(cổng cold-start: ≥ 5 lần thành công trước đó)──> geo_probability ──> ml_geo
                                                                                                      │
hybrid_cp2 ──> ml ─────────────────────────────────────────────────────────────── max(ml, ml_geo) ───┤
luật (rule engine v2) ─────────────────────────────────────────────────────────── noisy-OR ──────────┤──> MỘT điểm, MỘT hành động
danh tiếng hạ tầng ───────────────────────────────────────────────────────────────────────────────────┘
```

Mã: [`hybrid/calibration.py`](../backend/app/detection/hybrid/calibration.py) (`geo_probability`, `geo_cap`),
[`hybrid/combine.py`](../backend/app/detection/hybrid/combine.py), [`ml_model.py`](../backend/app/detection/ml_model.py),
[`pipeline.py`](../backend/app/detection/pipeline.py), [`ml/train.py`](../backend/ml/train.py),
[`ml/evaluate.py`](../backend/ml/evaluate.py). Không còn cảnh báo `ml_anomaly` mới; `login_events.ml_anomaly_score` vẫn được
ghi cho mọi lần thử vào tài khoản có thật (kể cả khi bị cổng chặn) để tra cứu — MR23 quyết định giữ hay bỏ cột này.

## 1. Dữ liệu tái lập được (seed cố định)

`ml/generate_dataset.py` giờ cố định `random.seed` (`--seed`, mặc định 42) **và** mốc thời gian (`--reference-time`, mặc
định 01/09/2026 — trước đây lấy giờ hiện tại nên `day_of_week` đổi theo ngày chạy). Chạy lại hai lần cho ra
`features.csv` và `labels.csv` giống hệt (đã kiểm). Dữ liệu sinh lại theo seed: **1.815 lần đăng nhập, 304 bất thường (16,7%),
7 kiểu** (9 nhãn nếu tính riêng 3 tổ hợp); mọi số đo dưới đây và ở [`ml-evaluation.md`](ml-evaluation.md) là của bộ này. Vẫn
là **dữ liệu tự sinh**, không phải đăng nhập thật.

## 2. Cổng cold-start: không chấm tài khoản có dưới 5 lần thành công

Với một tài khoản mới, "thiết bị mới" và "vị trí mới" đúng theo định nghĩa — mô hình không thể phân biệt người dùng thật với
kẻ tấn công. Đo trên toàn bộ dữ liệu (`ml/train.py`, ghi vào `meta.json`): tỉ lệ đăng nhập **bình thường** bị mô hình gắn cờ,
theo số lần thành công trước đó của tài khoản:

| Lần thành công trước đó | 0 | 1 | 2 | 3–4 | 5–9 | 10–19 | 20+ |
|---|---|---|---|---|---|---|---|
| Đăng nhập bình thường | 38 | 33 | 34 | 67 | 169 | 342 | 828 |
| Bị gắn cờ | **100%** | 24,2% | 2,9% | 4,5% | 2,4% | 0,6% | 0,9% |

Chọn **N = 5**: từ mức đó báo nhầm về gần mức nền. Cái giá, đo trên cùng dữ liệu: 28/304 ca bất thường (9,2%) nằm trong 5 lần
đầu của tài khoản. Ở vùng đó mô hình bắt 18/28 ca nhưng gắn cờ nhầm 50/172 lần đăng nhập bình thường (**độ chính xác 26,5%**);
qua cổng: bắt 193/276, nhầm 13/1.339 (**93,7%**). Tức là trong vùng cold-start, cờ của mô hình chủ yếu là nhiễu. Tài khoản mới
vẫn được các nguồn khác chấm (`hybrid_cp2`, luật, danh tiếng) — vd kịch bản "tài khoản ngủ đông" (chỉ 1 lần thành công trước
đó) vẫn cảnh báo nhờ luật `dormant_account_login`.

Số lần thành công trước đó lấy từ chính lịch sử của ngữ cảnh đăng nhập (`LoginContext.account.n_success`, MR20) — cùng định
nghĩa với cột `successful_login_count_so_far` lúc train.

## 3. Điểm → xác suất: neo ở ngưỡng của mô hình, độ dốc học từ dữ liệu

`margin` = điểm bất thường − ngưỡng quyết định của chính mô hình (`offset_`; > 0 là bị gắn cờ).

```
ml_geo = min( σ(slope · margin + logit(alert_at/100)),  geo_cap )
```

- **Độ dốc** (`slope` = 48,22): hồi quy logistic một biến trên biên độ **ngoài mẫu** (5-fold) của 1.054 dòng train đã qua cổng.
  Nhãn chỉ dùng ở đây và khi đánh giá; Isolation Forest vẫn học không giám sát.
- **Mốc**: biên độ 0 cho đúng `alert_at/100` (0,32 với hồ sơ RBA). Một mình tầng 3 cảnh báo **đúng khi** mô hình gắn cờ, như
  `ml_anomaly` trước đây — giữ nguyên điểm làm việc đã đo. Mốc dùng ngưỡng của **nhóm**, không dùng ngưỡng đã nới riêng của một
  tài khoản (MR15), để nới ngưỡng vẫn giảm được cảnh báo do nguồn này gây ra.
- **Trần** `geo_cap = 1 − (1 − step_up)/(1 − alert)` = **0,382**: mức mà cộng noisy-OR với **một** tín hiệu khác tự nó đủ cảnh
  báo thì vừa chạm `step_up`. Một mình tầng 3 chỉ cảnh báo; thêm một tín hiệu độc lập đáng cảnh báo mới yêu cầu xác thực thêm.

**Vì sao không dùng thẳng xác suất hiệu chỉnh isotonic** (cách "chuẩn"), đo trên cùng tập test đã qua cổng: tỉ lệ bất thường
của dữ liệu tự sinh (~14%) cao hơn thực tế nhiều, nên xác suất bị thổi phồng — ở ngưỡng `alert` báo nhầm **4,8%** (gấp 3 lần
1,6% của ngưỡng mô hình), **47,6%** số ca bất thường lên xác suất 1,0, và 3,0% đăng nhập bình thường vượt ngưỡng `lock`. Một mô
hình học trên dữ liệu tự sinh không được tự khoá tài khoản.

## 4. Gộp hai mô hình bằng max, và vì sao trần không đặt sát `step_up`

Bản đầu của MR22 đặt trần ngay dưới `step_up` (0,57) và gộp `ml_geo` với mọi bằng chứng khác bằng noisy-OR. Đo qua pipeline
thật thì hai vấn đề lộ ra:

1. **Đếm một tín hiệu hai lần.** `hybrid_cp2` và mô hình địa lý-thời gian cùng thấy "thiết bị mới", "vị trí/quốc gia mới";
   noisy-OR coi chúng độc lập. Ví dụ hợp lệ "khó": tài khoản 20 ngày lịch sử ở Hà Nội đăng nhập bằng **điện thoại mới ở
   TP.HCM** — `hybrid_cp2` = 0,561, tầng 3 gắn cờ. Bản đầu: 1 − 0,439 × 0,43 = 0,811 → **khoá tài khoản**. Bản cuối: max(0,561;
   0,382) = 0,561 → **cảnh báo** (như trước MR22).
2. **Bằng chứng dưới ngưỡng chồng lên nền của `hybrid_cp2`.** Mô hình RBA cho mọi IP Việt Nam xác suất nền ~0,20–0,29 (lệch
   phân phối đã biết, sửa ở MR26). Với noisy-OR, tầng 3 chỉ cần 4–15% là đẩy một lần đăng nhập bình thường qua ngưỡng cảnh báo.
   Đo trên đăng nhập bình thường của tập test:

   | Nền của `hybrid_cp2` | 0 | 0,10 | 0,20 | 0,29 |
   |---|---|---|---|---|
   | Vượt `alert` nếu gộp noisy-OR | 1,6% | 3,0% | 4,4% | **8,0%** |
   | Vượt `alert` nếu gộp max | 1,6% | 1,6% | 1,6% | 1,6% |

Vì vậy **nhóm ML lấy max** của hai mô hình (coi như phụ thuộc hoàn toàn — cận dưới của "ít nhất một đúng"), rồi mới noisy-OR
với luật và danh tiếng. Mô hình thua vẫn được liệt kê trong phần giải thích của cảnh báo (cùng chiều, dễ hiểu hơn), nhưng không
đổi điểm. Hệ quả có thể kiểm chứng: so với MR21, **không lần đăng nhập nào bị hạ hành động** (max ≥ `hybrid_cp2`), và một lần
đăng nhập chỉ bị nâng thêm khi tầng 3 thấy điều mà `hybrid_cp2` không thấy.

## 5. Kết quả đo

**Trên tập test của dữ liệu tự sinh** (561 lần đăng nhập, 126 bất thường; `python -m ml.evaluate` →
`ml/artifacts/evaluation_geo_by_type.csv`). Mọi dòng test đều đã qua cổng (30% cuối lịch sử của mỗi tài khoản), nên quyết định
cảnh báo của `ml_geo` **trùng hoàn toàn** với ngưỡng mô hình mà `ml_anomaly` dùng trước MR22:

| Kiểu bất thường | Số ca | Điểm đã công bố (top 14,2%) | Ngưỡng mô hình (`ml_anomaly` cũ) | `ml_geo` ≥ alert, qua cổng (MR22) |
|---|---|---|---|---|
| `dormant_reactivation` | 13 | 100% | 100% | 100% |
| `impossible_travel_geo` | 18 | 55,6% | 66,7% | 66,7% |
| `unusual_hour` | 18 | 72,2% | 94,4% | 94,4% |
| `unusual_location` | 18 | 72,2% | 77,8% | 77,8% |
| `unusual_device` | 28 | 46,4% | 57,1% | 57,1% |
| `rapid_fire` | 13 | 0% | 0% | 0% |
| `unusual_hour+unusual_location` | 9 | 100% | 100% | 100% |
| `unusual_device+unusual_hour` | 5 | 100% | 100% | 100% |
| `unusual_device+unusual_location` | 4 | 75% | 75% | 75% |
| **Tổng (recall)** | 126 | 62,7% | 70,6% | **70,6%** |
| Báo nhầm (435 bình thường) | | 0,2% | 1,6% | **1,6%** |

→ Recall của hai kiểu địa lý-thời gian (`dormant_reactivation`, `impossible_travel_geo`) và mọi kiểu khác **giữ nguyên** so với
cách tầng 3 chạy trên luồng thật trước MR22. Cổng chỉ ảnh hưởng 5 lần đầu của tài khoản (mục 2). Cột "điểm đã công bố" là cách
đếm của tài liệu từ Tuần 7 (gắn cờ đúng 14,2% điểm cao nhất của tập test) — chặt hơn ngưỡng mô hình mà luồng thật dùng; hai con
số khác nhau từ trước MR22, giờ ghi rõ cả hai.

**Qua pipeline thật** — 17 kịch bản của MR21 + 3 kịch bản hợp lệ mới, chạy trên commit MR21 và trên MR22 với **cùng** mô hình đã
train và cùng bộ chạy kịch bản (đã sửa, mục 6). "Bước" là lần thử đầu tiên có cảnh báo, kèm hành động cao nhất:

| Kịch bản | MR21: cảnh báo | MR21: bước · hành động | MR22: cảnh báo | MR22: bước · hành động |
|---|---|---|---|---|
| Rải mật khẩu chậm | ml_anomaly ×17 | 1/18 · allow | hybrid_risk ×17 | 1/18 · **alert** |
| Botnet phân tán vào một tài khoản | hybrid_risk ×2; ml_anomaly ×8 | 1/8 · alert | hybrid_risk ×3 | 1/8 · alert |
| Proxy cùng quốc gia, khác nhà mạng | ml_anomaly ×1 | 1/1 · allow | hybrid_risk ×1 | 1/1 · **alert** |
| Xoay User-Agent | hybrid_risk ×1; ml_anomaly ×9 | 1/9 · alert | hybrid_risk ×2 | 1/9 · alert |
| Tài khoản ngủ đông đăng nhập lại | hybrid_risk ×1; ml_anomaly ×1 | 1/1 · alert | hybrid_risk ×1 | 1/1 · alert |
| Mô phỏng tinh vi (Targeted mimic) | hybrid_risk ×1; ml_anomaly ×1 | 1/1 · alert | hybrid_risk ×1 | 1/1 · alert |
| Dò danh sách tài khoản | — | — · allow | — | — · allow |
| Nhồi thông tin đăng nhập quy mô lớn | hybrid_risk ×6; ml_anomaly ×16 | 1/16 · alert | hybrid_risk ×13 | 1/16 · **step_up** |
| Di chuyển bất khả thi | hybrid_risk ×1; ml_anomaly ×1 | 2/2 · step_up | hybrid_risk ×1 | 2/2 · step_up |
| User-Agent là bot | — | — · allow | — | — · allow |
| Nhịp thử đều như máy | hybrid_risk ×1 | 5/10 · alert | hybrid_risk ×1 | 5/10 · alert |
| Tor exit node | — | — · allow | — | — · allow |
| IP datacenter | — | — · allow | — | — · allow |
| IP VPN thương mại | — | — · allow | — | — · allow |
| Cùng lúc nhiều quốc gia | hybrid_risk ×1; ml_anomaly ×1 | 2/2 · step_up | hybrid_risk ×1 | 2/2 · step_up |
| Thử từ nhiều quốc gia | — | — · allow | — | — · allow |
| E2E TC1: 5 lần sai + 1 lần đúng | hybrid_risk ×1 | 5/6 · step_up | hybrid_risk ×1 | 5/6 · step_up |
| *Hợp lệ:* tài khoản mới, 6 ngày | ml_anomaly ×1 | 1/6 · allow | **—** | — · allow |
| *Hợp lệ:* tài khoản cũ, theo thói quen, 5 ngày | hybrid_risk ×1 | 1/5 · alert | hybrid_risk ×1 | 1/5 · alert |
| *Hợp lệ:* tài khoản cũ, điện thoại mới ở thành phố khác | hybrid_risk ×1; ml_anomaly ×1 | 1/3 · alert | hybrid_risk ×1 | 1/3 · alert |

- **Không kịch bản nào mất phát hiện hay phát hiện muộn hơn.** Tổng số hàng cảnh báo **74 → 44** (mỗi lần thử còn tối đa một
  cảnh báo, chống trùng lặp MR13 giờ áp dụng cả cho bằng chứng của tầng 3).
- **Tài khoản mới hợp lệ không còn bị báo** — điều kiện "xong" của MR22.
- Hai kịch bản trước chỉ có `ml_anomaly` trong khi hybrid nói "cho qua" (rải mật khẩu chậm, proxy cùng quốc gia) giờ có hành
  động `alert` thật — cùng loại mâu thuẫn MR21 đã gỡ cho tầng 1. Nhồi thông tin lên `step_up` nhờ tầng 3 cộng với các luật.
- Đăng nhập theo thói quen: `ml_geo` chỉ 0,01–0,07 cả 5 ngày. Cảnh báo ở ngày đầu của kịch bản này là của `hybrid_cp2` (0,50),
  **có sẵn từ MR21**, không do MR22 — thuộc phạm vi hiệu chỉnh `hybrid_cp2` cho người dùng Việt Nam (MR26).
- Rải mật khẩu chậm ra 17 cảnh báo vì 17 tài khoản khác nhau bị nhắm cách nhau 25 phút (ngoài cửa sổ gộp 15 phút); tương quan
  chiến dịch (MR14) đã gom chúng; "một sự cố = một cảnh báo" là việc của MR23.

## 6. Lỗi tìm ra khi đo

- **Bộ chạy kịch bản dựng lịch sử sai** (`scripts/attack_scenario_runner.py::_insert_baseline`, dùng chung cho MR18, MR21 và
  `measure_untested_behaviors.py`): lịch sử "quen thuộc" chèn thẳng vào `login_events`, nhưng mô hình địa lý-thời gian đọc
  thiết bị/vị trí quen từ bảng `known_devices`/`known_locations` (từ Tuần 4) và giờ quen từ `user_baseline` — ba bảng này chỉ
  được ghi khi một lần đăng nhập thành công đi qua pipeline. Hệ quả: với tầng 3, **mọi tài khoản có lịch sử trong kịch bản đều
  là "thiết bị mới + vị trí mới"**. Ghi chú của MR18 "`ml_anomaly` gần như luôn kêu, kể cả khi đăng nhập khớp hệt thói quen" một
  phần là do chính lỗi này. Đã sửa: mỗi dòng lịch sử thành công được ghi sổ y như pipeline làm. Bảng ở mục 5 chạy lại **cả hai
  phía** (MR21, MR22) với bộ chạy đã sửa; số trong [`rule-unification.md`](rule-unification.md) (MR21) đo bằng bộ chạy cũ —
  phần luật/hybrid của bảng đó (số cảnh báo, bước, hành động) đo lại bằng bộ chạy mới vẫn giống hệt ở cả 17 kịch bản, chỉ số
  `ml_anomaly` là không đáng tin.
- Cùng lỗi trong test `test_pipeline_mr13.py` ("đăng nhập bình thường không tạo cảnh báo"): lịch sử chèn thẳng, dồn trong một
  ngày, 30 ngày trước. Trước MR22 test chỉ đếm `hybrid_risk` nên không thấy `ml_anomaly`; giờ test dựng lịch sử như thật và đếm
  **mọi** loại cảnh báo.
- **Khối khoá tự động (MR16)** so `expires_at` đọc từ SQLite (không múi giờ) với mốc có múi giờ → `TypeError`, cả khối hybrid
  bị bỏ. Chỉ lộ ra khi một kịch bản mô phỏng đi tới nhánh gia hạn khoá; đã sửa bằng `ensure_utc`.

## 7. Giới hạn

- **Dữ liệu tự sinh.** Độ dốc, bảng cold-start và mọi recall ở trên đo trên dữ liệu do nhóm sinh ra; ranh giới "bất thường" do
  chính bộ sinh định nghĩa. Mốc và trần là **lựa chọn thiết kế có lý do** (giữ điểm làm việc cũ; một mình chỉ cảnh báo), không
  phải xác suất đo trên tấn công thật.
- Mô hình học trên **lần đăng nhập thành công**; trên luồng thật nó chấm mọi lần thử của tài khoản đã qua cổng (kể cả lần sai)
  — giống hệt phạm vi của `ml_anomaly` trước MR22, chưa đo riêng độ chính xác trên lần thử sai.
- 9,2% ca bất thường của dữ liệu nằm trong vùng cold-start, tầng 3 không còn chấm (mục 2).
- Gộp max bỏ qua trường hợp hai mô hình thật sự độc lập cùng thấy bất thường (khi đó noisy-OR mới đúng) — chọn phía an toàn vì
  hai mô hình dùng chung tín hiệu và nền của `hybrid_cp2` đang lệch.
- `rapid_fire` vẫn 0%: đặc trưng `logins_last_24h` không đủ — MR27 thay bằng luật tốc độ.

## 8. Kiểm thử

- `test_pipeline_mr22.py` (qua pipeline thật, mô hình tầng 3 giả luôn gắn cờ, không phụ thuộc artifacts): 5 lần đầu của tài
  khoản mới không bị chấm (điểm tầng 3 vẫn được ghi); lần thứ 6 thành **một** cảnh báo hybrid có nguồn `ml_geo` kèm diễn giải,
  họ tấn công "địa lý-thời gian", không còn `ml_anomaly`; một mình chỉ `alert` dù biên độ cực lớn; mô hình train trước MR22
  (không có độ dốc) bị bỏ qua; lần không bị gắn cờ chỉ góp bằng chứng yếu.
- `test_hybrid_calibration.py` (mốc, đơn điệu, trần, công thức trần, trần không dưới ngưỡng alert), `test_hybrid_combine.py`
  (max giữa hai mô hình, noisy-OR với luật, nhãn), `test_hybrid_runtime.py` (neo theo ngưỡng nhóm), `test_alert_intelligence.py`
  (họ tấn công khi `ml_geo` dẫn đầu), `test_ml_model.py` (`margin`, độ dốc, cổng), `test_ml_geo_mr22.py` (độ dốc, bảng cold-start,
  "qua cổng thì quyết định trùng ngưỡng mô hình", seed của bộ sinh dữ liệu).
