# Đánh giá ML tầng 3 (nhiệm vụ 7.1) — điểm nhấn chính của đồ án

> **Ghi chép theo thời điểm (Tuần 7–MR22)** — mô tả và số đo lúc đó, giữ để truy vết; hệ thống đã thay đổi ở các MR sau (đến MR36). Bản hiện hành: [`architecture.md`](architecture.md) · mục lục tài liệu: [`README.md`](README.md).

> **MR22:** bộ sinh dữ liệu đã cố định random seed và mốc thời gian — mọi con số dưới đây là của bộ dữ liệu sinh với seed
> 42 (gồm cả 2 kiểu bất thường MR18 thêm: `dormant_reactivation`, `impossible_travel_geo`, xem
> [`model-b-geo-time.md`](model-b-geo-time.md)) và **chạy lại ra đúng như vậy** (mục 6). Số của Tuần 7 (78,3% recall trên
> 5 kiểu, dữ liệu không cố định seed) là lịch sử, không tái lập được nên đã thay.
>
> Trên luồng đăng nhập thật, từ MR22 Isolation Forest này không còn tạo cảnh báo `ml_anomaly` riêng mà là nguồn bằng chứng
> `ml_geo` của hybrid risk engine, có cổng cold-start — cách đổi điểm sang xác suất, cổng và số đo trước/sau:
> [`geo-model-integration.md`](geo-model-integration.md).

## Vì sao làm sâu phần này

Ban đầu checklist coi ML là "tuỳ chọn, không bắt buộc thành công". Nhóm quyết
định đầu tư sâu hơn để ML thực sự là điểm khác biệt của đồ án — nhưng **trung
thực với giới hạn của dữ liệu tự sinh** là nguyên tắc xuyên suốt: mọi con số
dưới đây đo trên dữ liệu do chính nhóm tạo ra (`backend/ml/generate_dataset.py`),
không phải dữ liệu tấn công thật. Đây là **proof-of-concept có phương pháp
luận chuẩn** (train/test tách theo thời gian, không rò rỉ dữ liệu tương lai,
so sánh trên hàm sản xuất thật), không phải bằng chứng "AI phát hiện được
tấn công thật ngoài đời" — nếu hội đồng hỏi, đây là câu trả lời đúng mực.

## 1. Dữ liệu

- **40 user** (`user101`-`user140`), tách biệt hoàn toàn khỏi 30 user dùng
  cho demo dashboard (Tuần 2-3) để không xáo trộn số liệu đã ghi ở các tuần
  trước.
- **1815 lần đăng nhập thành công**, trải trong 90 ngày trước mốc 01/09/2026.
- **7 kiểu bất thường** (5 kiểu của Tuần 7 + 2 kiểu địa lý-thời gian của MR18), kể cả tổ hợp:

  | Kiểu | Mô tả | Số lượng (toàn tập) |
  |---|---|---|
  | `unusual_hour` | Giờ đăng nhập đối lập hoàn toàn thói quen | 58 |
  | `unusual_location` | Vị trí cách xa nơi ở quen thuộc | 55 |
  | `unusual_device` | Thiết bị (User-Agent) chưa từng thấy | 61 |
  | `rapid_fire` | Nhiều lần đăng nhập dồn dập bất thường (vài chục giây/lần) | 47 |
  | kết hợp (`unusual_device+unusual_hour`, `unusual_hour+unusual_location`, `unusual_device+unusual_location`) | 2 tín hiệu cùng lúc — ca khó nhất | 52 |
  | `dormant_reactivation` (MR18) | Im lặng lâu ngày rồi đăng nhập từ vị trí mới | 13 |
  | `impossible_travel_geo` (MR18) | Thời gian cực ngắn và khoảng cách cực xa so với lần trước | 18 |

- Tỷ lệ **83,3% bình thường / 16,7% bất thường** (304 ca) — trong khoảng 80-90% khuyến
  nghị (mục 11 checklist gốc).
- Mỗi user có 1-2 "thiết bị quen thuộc" (User-Agent thật của trình duyệt/di
  động phổ biến) thay vì 1 chuỗi cố định như bản Tuần 2-3 — cần thiết để đặc
  trưng "thiết bị lạ" có ý nghĩa.

## 2. Đặc trưng (feature engineering)

9 đặc trưng, tính từ [`backend/ml/features.py`](../backend/ml/features.py) —
**chống rò rỉ dữ liệu tương lai** bằng cách xử lý tuần tự theo thời gian,
chỉ dùng lịch sử TRƯỚC thời điểm đăng nhập hiện tại (kiểm tra bằng unit test
`test_ml_features.py`):

| Đặc trưng | Ý nghĩa |
|---|---|
| `hour_sin`, `hour_cos` | Giờ đăng nhập (mã hoá vòng tròn — 23h và 1h gần nhau) |
| `day_of_week` | Thứ trong tuần |
| `hour_deviation_from_avg` | Lệch bao nhiêu giờ so với giờ trung bình của user (khoảng cách vòng tròn) |
| `is_new_location` | Vị trí chưa từng thấy |
| `is_new_device` | Thiết bị chưa từng thấy |
| `minutes_since_last_login` | Bao lâu kể từ lần đăng nhập trước |
| `logins_last_24h` | Số lần đăng nhập trong 24h qua (bắt `rapid_fire`) |
| `distance_km_from_home` | Khoảng cách tới vị trí quen thuộc nhất |

Phần lớn đặc trưng **tái sử dụng tín hiệu đã có ở tầng 2**
([`app/detection/baseline.py`](../backend/app/detection/baseline.py),
[`app/utils/geo.py`](../backend/app/utils/geo.py) — khoảng cách, trước MR21 ở `app/detection/rules.py`) — khác biệt
cốt lõi không phải là "ML thấy nhiều thứ hơn" mà là **tầng 2 gán trọng số
THỦ CÔNG cố định** (mục 4.2: lệch giờ +20, vị trí lạ +30...), còn **tầng 3
để mô hình TỰ HỌC cách kết hợp** (kể cả quan hệ phi tuyến) từ dữ liệu.

## 3. Phương pháp đánh giá

- **Train/test split theo THỜI GIAN, riêng từng user** (70% đầu → train, 30%
  cuối → test) — **không** xáo trộn ngẫu nhiên như `train_test_split()` mặc
  định, vì sẽ làm lẫn thông tin tương lai vào tập train.
- **3 mô hình ML** (scikit-learn, không cần TensorFlow/PyTorch):
  - **Isolation Forest** — học trên toàn bộ tập train (kể cả lẫn ít bất
    thường, đúng bản chất unsupervised).
  - **Local Outlier Factor** (novelty detection) — chỉ học trên phần được
    xác nhận bình thường của tập train.
  - **Autoencoder** (mạng MLP thắt cổ chai 9→6→3→6→9) — chỉ học tái tạo dữ
    liệu bình thường, đo lỗi tái tạo (MSE) làm điểm bất thường.
- **So sánh với tầng 2 THẬT** — không viết lại song song, gọi thẳng
  `compute_risk_score()` (đã chạy trên luồng thật từ Tuần 4 tới MR20; từ MR21
  chuyển nguyên văn sang [`ml/tier2_baseline.py`](../backend/ml/tier2_baseline.py)
  làm phương pháp đối chứng), dựng `UserBaseline` giả từ đúng ngữ cảnh lịch sử
  tại thời điểm đó. Đảm bảo so sánh công bằng trên đúng công thức đã chạy thật.

## 4. Kết quả

Tập test: 561 lần đăng nhập (30% cuối của từng user), 126 bất thường. Ngưỡng của 3 mô hình ML: gắn cờ đúng tỉ lệ
`contamination` (14,2%, ước từ tập train) điểm cao nhất — "điểm làm việc đã công bố" từ Tuần 7.

| Phương pháp | Precision | Recall | F1 | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Tầng 2 (behavioral, ngưỡng 40) | **1.000** | 0.063 | 0.119 | 0.758 | 8 | 0 | 118 | 435 |
| Isolation Forest | 0.988 | 0.627 | **0.767** | **0.942** | 79 | 1 | 47 | 434 |
| Local Outlier Factor | 0.975 | 0.619 | 0.757 | 0.940 | 78 | 2 | 48 | 433 |
| Autoencoder | 0.607 | **0.881** | 0.718 | 0.929 | 111 | 72 | 15 | 363 |

Biểu đồ: [`ml-confusion-matrices.png`](figures/ml-confusion-matrices.png),
[`ml-roc-curves.png`](figures/ml-roc-curves.png),
[`ml-feature-importance.png`](figures/ml-feature-importance.png).

Trên luồng thật, Isolation Forest dùng **ngưỡng của chính mô hình** (`offset_`) chứ không phải điểm làm việc trên: recall
70,6%, báo nhầm 1,6% trên cùng tập test — theo từng kiểu ở [`geo-model-integration.md`](geo-model-integration.md) mục 5.

### Phát hiện quan trọng nhất: tầng 2 gần như "im lặng"

Tầng 2 chỉ bắt được **8/126 ca bất thường** trong tập test (recall 6,3%),
dù không báo động giả nào (precision 100%). Soi theo từng kiểu bất thường:

| Kiểu bất thường | Số ca (test) | Recall tầng 2 | Recall Isolation Forest |
|---|---|---|---|
| `unusual_hour` | 18 | **0%** | 72% |
| `unusual_location` | 18 | **0%** | 72% |
| `unusual_device` | 28 | **0%** (không có trọng số cho loại này) | 46% |
| `rapid_fire` | 13 | **0%** (không có trọng số cho loại này) | 0% |
| `unusual_hour+unusual_location` | 9 | 67% | 100% |
| kết hợp có `unusual_device` | 9 | **0%** | 89% |
| `dormant_reactivation` (MR18) | 13 | 15% | 100% |
| `impossible_travel_geo` (MR18) | 18 | **0%** | 56% |

**Nguyên nhân gốc rễ, không phải lỗi đánh giá:**

1. **Tầng 2 KHÔNG có trọng số cho `unusual_device` và `rapid_fire`** —
   `compute_risk_score()` (mục 4.2 checklist gốc) chỉ tính 4 yếu tố: lệch
   giờ, vị trí lạ, fail liên tiếp, thành công sau chuỗi fail. Hai kiểu bất
   thường mới (thiết bị lạ, tốc độ bất thường) **về mặt thiết kế không thể
   bị tầng 2 bắt được** — đây là lý do chính đáng để có tầng 3.
2. **Baseline giờ bị "pha loãng" theo thời gian** — `avg_login_hour`/
   `stddev_login_hour` được tính lại từ **MỌI** lần đăng nhập thành công
   (xem `update_baseline_after_successful_login()`), **kể cả những lần đã
   là bất thường trước đó**. Khi có nhiều ca `unusual_hour` liên tiếp,
   `stddev_login_hour` bị kéo giãn ra, khiến ngưỡng `2.5 × stddev` ngày
   càng khó vượt qua — hạn chế THẬT của tầng 2 trong production, không chỉ
   trong đánh giá này. **Đây là điểm cần cải thiện nếu có thời gian** (VD
   dùng median/IQR thay vì mean/stddev, hoặc loại các lần đã gắn cờ rủi ro
   cao khỏi việc cập nhật baseline).
3. **Ngưỡng cố định (40 điểm) không thích ứng** — đường ROC của tầng 2 vẫn
   đạt AUC 0.758 (cao hơn ngẫu nhiên đáng kể), nghĩa là điểm số **về hướng
   là đúng** (anomaly có xu hướng điểm cao hơn normal), nhưng ngưỡng 40 đặt
   quá cao so với phân bố điểm thực tế nên hầu hết không vượt qua. ML không
   dùng ngưỡng cố định — chọn ngưỡng theo **percentile của chính phân bố dữ
   liệu** (tham số `contamination`), thích ứng tốt hơn.

### Feature importance (Isolation Forest, permutation importance)

Xếp hạng theo mức giảm ROC-AUC khi xáo trộn từng đặc trưng:
`distance_km_from_home` (0,079) > `is_new_device` (0,067) >
`hour_deviation_from_avg` (0,032) > `is_new_location` (0,024) >
`logins_last_24h` ≈ `minutes_since_last_login` (0,015–0,016) > (3 đặc trưng
còn lại gần như không đóng góp, `day_of_week` gần như nhiễu).

**`is_new_device` đứng thứ 2** dù đây là đặc trưng **hoàn toàn không tồn tại
ở tầng 2**. Đây là bằng chứng định lượng cho việc mở rộng đặc trưng (không chỉ
đổi thuật toán) mới là yếu tố quyết định khiến tầng 3 "thông minh hơn", không
phải bản thân Isolation Forest có phép màu gì. (Tuần 7, dữ liệu chưa có 2 kiểu
địa lý-thời gian, lệch giờ đứng đầu; thêm `dormant_reactivation`/
`impossible_travel_geo` đưa khoảng cách tới nhà lên đầu.)

## 5. Giới hạn thật, nói thẳng khi bị hỏi

- **Dữ liệu tự sinh, không phải tấn công thật.** Ranh giới "bất thường" do
  chính script sinh dữ liệu định nghĩa — mô hình về bản chất học lại đúng
  logic đó. Số liệu đẹp không chứng minh hệ thống phát hiện được tấn công
  thật ngoài đời, chỉ chứng minh **pipeline đúng phương pháp luận** (không
  rò rỉ dữ liệu, so sánh công bằng, tái lập được).
- **Isolation Forest yếu nhất ở `rapid_fire` (0%) và `unusual_device` đơn lẻ**
  (46%). `rapid_fire` chỉ được thấy qua `logins_last_24h` — một lần đăng nhập
  dồn dập vẫn rất giống bình thường ở 8 đặc trưng còn lại; việc này giao cho
  luật tốc độ (MR27) thay vì cố ép mô hình.
- **Precision của Autoencoder thấp (60,7%)** — báo động giả nhiều nhất
  trong 3 mô hình (72 ca) dù recall cao nhất. Kiến trúc mạng nhỏ (phù hợp dữ
  liệu ít), có thể cải thiện bằng nhiều dữ liệu train "sạch" hơn.
- **Lần đăng nhập đầu của tài khoản mới**: "thiết bị mới + vị trí mới" theo
  định nghĩa — mô hình gắn cờ 100% đăng nhập bình thường của tài khoản chưa
  có lần thành công nào. Luồng thật không chấm tài khoản dưới 5 lần thành
  công (cổng cold-start, MR22).
- Baseline tầng 2 (mục 3, phát hiện #2) là hạn chế **có thật trong hệ thống
  đang chạy**, không riêng gì bài đánh giá này — nên ghi vào phần "hướng
  phát triển" của báo cáo cuối.

## 6. Tái tạo kết quả

```bash
cd backend
venv\Scripts\python.exe -m ml.generate_dataset --reset   # sinh dữ liệu (40 user, seed 42, mốc 01/09/2026)
venv\Scripts\python.exe -m ml.extract_features            # trích đặc trưng, chống rò rỉ dữ liệu
venv\Scripts\python.exe -m ml.train                        # huấn luyện 3 mô hình + độ dốc ml_geo + bảng cold-start (MR22)
venv\Scripts\python.exe -m ml.evaluate                     # so sánh + xuất biểu đồ + recall theo kiểu (MR22)
```

Từ MR22 bước sinh dữ liệu cố định random seed và mốc thời gian (`--seed`,
`--reference-time`): chạy lại ra đúng `features.csv`/`labels.csv` và đúng các
con số ở trên. Đổi seed để kiểm độ ổn định của kết luận (tầng 2 gần như im
lặng, ML vượt trội rõ rệt). `--reset` xoá và sinh lại user101-140 trong DB.
