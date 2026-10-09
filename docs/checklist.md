# Checklist tổng hợp toàn dự án

Chép từ phụ lục checklist gốc (`Ke_hoach_trien_khai_chi_tiet_va_checklist.docx`, mục 11).
Tick `[x]` khi nhiệm vụ đã qua đủ các mục kiểm tra — không tick khi chỉ mới viết code xong.

## Tuần 1 — Kiến trúc & khung project

- [x] 1.1 Thống nhất kiến trúc & API contract — Cả hai — xem [`docs/api-contract.md`](api-contract.md)
- [x] 1.2 Thiết kế schema cơ sở dữ liệu — A — xem [`docs/db-schema.md`](db-schema.md)
- [x] 1.3 Khởi tạo khung backend (FastAPI) — A
- [x] 1.4 Khởi tạo khung frontend (React) — B

## Tuần 2 — Đăng nhập & log cơ bản

- [x] 2.1 API đăng nhập cơ bản + ghi log — A — `POST /login`, xem [`backend/app/routers/auth.py`](../backend/app/routers/auth.py)
- [x] 2.2 Giao diện đăng nhập web app mẫu — B — [`frontend/src/pages/LoginPage.jsx`](../frontend/src/pages/LoginPage.jsx)
- [x] 2.3 Sinh dữ liệu đăng nhập lịch sử giả lập ban đầu — Cả hai — [`backend/scripts/generate_historical_data.py`](../backend/scripts/generate_historical_data.py)

## Tuần 3 — Rule-based tầng 1

- [x] 3.1 Tích hợp MaxMind GeoLite2 — A — [`backend/app/detection/geoip.py`](../backend/app/detection/geoip.py), dùng dữ liệu GeoLite2-City thật (xem [`docs/geoip-setup.md`](geoip-setup.md))
- [x] 3.2 Đếm login fail bằng Redis (sliding window) — A — [`backend/app/detection/rate_counter.py`](../backend/app/detection/rate_counter.py)
- [x] 3.3 Viết rule-based detection tầng 1 — A — [`backend/app/detection/rules.py`](../backend/app/detection/rules.py)
- [x] 3.4 Dựng khung dashboard 4 khu vực — B — [`frontend/src/pages/DashboardPage.jsx`](../frontend/src/pages/DashboardPage.jsx)
- [x] 3.5 Mở rộng dữ liệu lịch sử giả lập cho baseline — B — [`backend/scripts/generate_labeled_anomalies.py`](../backend/scripts/generate_labeled_anomalies.py)

## Tuần 4 — Behavioral scoring tầng 2

- [x] 4.1 Xây baseline hành vi user — A — [`backend/app/detection/baseline.py`](../backend/app/detection/baseline.py)
- [x] 4.2 Cài đặt chấm điểm risk score tầng 2 — A — [`backend/app/detection/scoring.py`](../backend/app/detection/scoring.py)
- [x] 4.3 Bảng log & biểu đồ tĩnh trên dashboard — B — `GET /login-events`, `GET /alerts` + [`frontend/src/components/LogTablePanel.jsx`](../frontend/src/components/LogTablePanel.jsx), [`RiskChartPanel.jsx`](../frontend/src/components/RiskChartPanel.jsx)

## Tuần 5 — Bảo mật & real-time

- [x] 5.1 Xác thực JWT cho admin & WebSocket — A — [`backend/app/dependencies.py`](../backend/app/dependencies.py), [`backend/app/routers/admin.py`](../backend/app/routers/admin.py)
- [x] 5.2 Tối ưu tốc độ detection engine — A — [`backend/app/detection/pipeline.py`](../backend/app/detection/pipeline.py) (BackgroundTasks), xem [`docs/performance.md`](performance.md)
- [x] 5.3 Kết nối WebSocket thật & bản đồ real-time — B — [`frontend/src/services/useAlertsSocket.js`](../frontend/src/services/useAlertsSocket.js)

## Tuần 6 — Kịch bản tấn công & kiểm thử end-to-end

- [x] 6.1 Viết 4 script giả lập tấn công — B — [`attack-sim/`](../attack-sim/)
- [x] 6.2 Kiểm thử end-to-end toàn luồng — Cả hai — [`docs/e2e-test-report.md`](e2e-test-report.md)

## Tuần 7 — ML mở rộng & đánh giá hệ thống

- [x] 7.1 Thử nghiệm mô hình ML tầng 3 — A — **đầu tư sâu, không chỉ "tuỳ chọn"**: 3 thuật toán (Isolation Forest, LOF, Autoencoder), 5 kiểu bất thường, so sánh với tầng 2 thật — xem [`docs/ml-evaluation.md`](ml-evaluation.md)
- [x] 7.2 Hoàn thiện giao diện & đo precision/recall — B — hệ thống thiết kế (CSS variables), nav/form/dashboard viết lại, responsive mobile/tablet đã test; precision/recall đo xong ở 7.1

## Tuần 8 — Báo cáo, slide & diễn tập demo

- [ ] 8.1 Viết báo cáo, chuẩn bị slide, diễn tập demo — Cả hai

---

# Giai đoạn mở rộng — nâng cấp AI, rule engine, cảnh báo (sau Tuần 7)

Kế hoạch **MR1–MR19** đã được duyệt ngày 20/09/2026, làm tuần tự theo thứ tự dưới đây. Nhãn: **[Lõi]** bắt buộc, **[Nên]** nên có, **[Thêm]** bổ sung. Cỡ: S ≈ 1 phiên làm việc, M ≈ 2–3, L ≥ 4. Mỗi MR có test, commit riêng và cập nhật docs; chỉ tick khi đạt điều kiện "Xong khi".

⚠️ **Đính chính quan trọng về dữ liệu:** bộ RBA là dữ liệu **tổng hợp** (README ghi "hoàn toàn nhân tạo"), không phải log thật — xem [`rba-data-card.md`](rba-data-card.md). Không được nói "huấn luyện trên dữ liệu thật" khi báo cáo.

Ba nguồn bằng chứng: (1) **RBA** — mô hình tần suất/mới lạ, so baseline Freeman, kiểm tra tổng quát hoá; (2) **simulator của dự án** — địa lý, giờ, impossible travel, kịch bản tấn công có nhãn tự kiểm soát; (3) **tấn công sống** vào hệ thống đang chạy — kiểm thử end-to-end, thời gian phát hiện.

**Điểm kiểm soát:** CP1 sau MR5 (đo tín hiệu thật, báo trước khi làm tiếp) · CP2 sau MR8 (chốt mô hình) · CP3 sau MR12 (hồi quy toàn hệ thống).

## Giai đoạn A — Nền móng dữ liệu

- [x] **MR1 [Lõi, S] Chốt chiến lược dữ liệu và môi trường** — Xong khi: một lệnh kiểm tra môi trường báo đủ (`python -m ml.check_env`)
  - [x] Data card: nguồn, CC BY 4.0, trích dẫn, ghi rõ "tổng hợp" — [`rba-data-card.md`](rba-data-card.md)
  - [x] Dữ liệu RBA ngoài git (`backend/ml/data/rba/` trong `.gitignore`), đọc thẳng từ zip, không giải nén — [`backend/ml/rba/paths.py`](../backend/ml/rba/paths.py)
  - [x] Cài lightgbm, shap, pyarrow, duckdb, user-agents; cập nhật [`requirements.txt`](../backend/requirements.txt)
  - [x] `lookup_asn()` ([`geoip.py`](../backend/app/detection/geoip.py)) và `parse_user_agent()` ([`device.py`](../backend/app/utils/device.py)) cho luồng realtime; file `GeoLite2-ASN.mmdb` chưa tải (chỉ cần từ MR12), xem [`geoip-setup.md`](geoip-setup.md)
  - [x] Danh sách Tor / datacenter / VPN công khai — [`backend/scripts/update_threat_feeds.py`](../backend/scripts/update_threat_feeds.py)
- [x] **MR2 [Lõi, M] Pipeline dữ liệu RBA** — Xong khi: test chứng minh không IP tấn công nào trùng giữa train và test (`tests/test_rba_real_data.py` trên mẫu thật + `tests/test_rba_splits.py`, `test_rba_sample.py`). Chi tiết: [`rba-data-card.md`](rba-data-card.md) mục 8
  - [x] ETL theo chunk từ zip sang Parquet ([`etl.py`](../backend/ml/rba/etl.py)); đối chiếu cột `index`: 31.269.264 dòng, liên tục, không mất dòng (README ghi >33M, nguyên nhân chênh chưa rõ)
  - [x] Đánh dấu artifact (IP 10.x, ASN ≥ 500000, 1.526 UA lỗi); loại 2 "user" khổng lồ (thùng chứa tài khoản không tồn tại 14 triệu sự kiện; client tự thử lại 70 nghìn sự kiện)
  - [x] Lấy mẫu theo user giữ nguyên lịch sử ([`sample.py`](../backend/ml/rba/sample.py)): đủ 138 user ATO + mẫu phân tầng 5%/10%/25% → 2.707.021 dòng, 401.092 user
  - [x] Chia theo thời gian + nhóm IP ([`splits.py`](../backend/ml/rba/splits.py)): train 02–07/2020, val 08/2020, test 09–11/2020, **late 12/2020–02/2021 (kiểm tra trôi phân phối)**; nhãn Attack IP chia theo **IP**; ATO (141) chỉ để đánh giá, 38 ca ở giai đoạn tương lai
  - ⚠️ Điều chỉnh so với kế hoạch: cả 141 ATO nằm trong 02–11/2020 (không có ca nào từ 12/2020) nên test phải phủ hết 11/2020; thêm cột `weight` để phục hồi tỉ lệ tấn công tự nhiên (val/test chỉ giữ 15% IP tấn công); bỏ "CV theo user cho ATO" vì ATO không bao giờ vào huấn luyện

## Giai đoạn B — AI lõi

- [x] **MR3 [Lõi, L] Đặc trưng v2, dùng chung train và realtime** — Xong khi: test rò rỉ và test tương đương offline/online đều pass (29 test: `test_rba_features*.py`, `test_rba_model_table.py`). Chi tiết: [`rba-features.md`](rba-features.md)
  - [x] Mới lạ theo user: country/ASN/IP/UA/browser/OS/device + họ trình duyệt/OS (9 cờ, so với lịch sử đăng nhập thành công)
  - [x] Kiểu Freeman: log-tỉ-số p_user/p_global cho 7 thuộc tính (làm mịn α = 1), đưa từng thành phần + tổng vào model
  - [x] Độ hiếm toàn cục (−ln p_global) cho 7 thuộc tính
  - [x] Nhịp/tần suất theo tài khoản: số lần thử 1h/24h, chuỗi fail, thời gian từ lần thử/thành công gần nhất, số IP 24h và quốc gia 7d
  - [x] Cấp hạ tầng: 7 đặc trưng theo IP và 6 theo ASN (số lần thử, tỉ lệ thất bại, số user/UA/IP khác nhau, số lần thử vào tài khoản không tồn tại)
  - [x] Cold-start: nhóm `history` (số lần thử/thành công, tuổi tài khoản) + độ hiếm toàn cục; 39,7% user RBA chỉ có 1 lần đăng nhập
  - [x] Tính cấp IP/ASN bằng DuckDB trên toàn bộ 31,27 triệu dòng ([`features_sql.py`](../backend/ml/rba/features_sql.py)), đặc tả Python ([`features.py`](../backend/ml/rba/features.py)) dùng cho luồng realtime; test tương đương trên ~1.270 sự kiện ngẫu nhiên có cố ý trùng micro-giây và sát biên cửa sổ, đã kiểm tra test bắt được lỗi cố ý
  - [x] Test không rò rỉ: thêm sự kiện tương lai không đổi đặc trưng cũ (dữ liệu ngẫu nhiên và dữ liệu RBA thật)
  - ⚠️ Điều chỉnh so với kế hoạch: cửa sổ và "trước đó" định nghĩa theo micro-giây strictly trước; thêm cờ `in_warmup` (14 ngày đầu); giai đoạn hạ tầng chia khối thời gian vì tính một lượt chạy siêu tuyến tính (30+ phút, treo do thiếu RAM); tránh `COUNT(*) FILTER` trong window DuckDB (chậm ~30 lần trên partition lớn)
- [x] **MR4 [Lõi, M] Khung đánh giá nghiêm ngặt** — Xong khi: một lệnh sinh bảng kết quả chuẩn cho mọi model (`python -m ml.rba.report <mô hình|all>`). Chi tiết: [`rba-evaluation.md`](rba-evaluation.md)
  - [x] Chỉ số có trọng số: ROC-AUC, PR-AUC, recall tại FPR 1% và 0,1%, tỉ lệ xác thực lại tại TPR 90%/99%, cảnh báo/1.000 đăng nhập và cảnh báo/ngày ở recall 90%/99% (quy về toàn dân số) — khớp `scikit-learn` (18 test)
  - [x] Mô phỏng kẻ tấn công Naive / VPN / Targeted thay thế đăng nhập thật của user hợp lệ, tính đặc trưng bằng đúng pipeline MR3 ([`attackers.py`](../backend/ml/rba/attackers.py)). ⚠️ **Đính chính ở MR6:** bản MR4 (5.966 đăng nhập giả) để lại "dấu vân tay" nên số liệu kẻ tấn công của CP1 sai; bản hiện tại (5.911 test + 16.162 train/val) sau bảy lần sửa và có công cụ kiểm định `ml/rba/audit.py` — [`rba-evaluation.md`](rba-evaluation.md) mục 5
  - [x] Khoảng tin cậy bootstrap theo cụm dương tính (IP cho bài IP tấn công, user cho ATO)
  - [x] Báo cáo tách riêng user chưa có lịch sử / mỏng (1–4) / dày (≥5) tại một ngưỡng chung cho FPR 1%
  - [x] (MR6) Trọng số dân số `pop_weight` cho mọi chỉ số: mẫu user phân tầng nghiêng về user hoạt động nhiều nên tỉ lệ báo nhầm đo trên mẫu thô chưa đúng cho toàn dân số
  - ⚠️ Điều chỉnh: bootstrap chỉ lấy mẫu lại phía dương tính (tập âm tính hàng trăm nghìn dòng giữ cố định) để mỗi lần lấy mẫu O(P log P); nhóm "chưa có lịch sử" không có ở bài `attacker/*` vì nạn nhân luôn có ≥ 1 lần thành công; hồ sơ nạn nhân chọn tất định (hoà thì lấy giá trị nhỏ nhất) vì `mode()` của DuckDB không xác định khi đồng tần
- [x] **MR5 [Lõi, M] Baseline (CP1)** — Xong khi: có bảng baseline và kết luận dữ liệu thật sự chứa tín hiệu gì. Kết quả và phân tích: [`ml-evaluation-v2.md`](ml-evaluation-v2.md), bảng đầy đủ [`rba-baseline-comparison.md`](rba-baseline-comparison.md)
  - [x] Cài lại mô hình Freeman et al. 2016 làm baseline học thuật (`freeman_all`, `freeman_no_ip`)
  - [x] Rule Tier 2 hiện tại (`tier2_current`, xấp xỉ bằng đặc trưng RBA) và luật đã tinh chỉnh ngưỡng trên train (`rules_tuned`: 18 luật, hồi quy logistic)
  - [x] Isolation Forest chạy trên đặc trưng mới, không dùng nhãn (`isolation_forest`)
  - **Kết luận CP1:** dữ liệu chứa tín hiệu vượt xa Freeman và Tier 2 (ATO thật tương lai: Isolation Forest 0,95, Freeman 0,77, Tier 2 hiện tại 0,53 ≈ ngẫu nhiên); kẻ tấn công Targeted đánh bại mọi baseline (⚠️ số kẻ tấn công mô phỏng đã đính chính ở MR6: Freeman 0,67, còn lại ≤ 0,54); 35% ATO nhắm vào tài khoản chưa có lịch sử nhưng độ hiếm quốc gia/ASN phân biệt được chúng (AUC 0,95–0,97)
- [x] **MR6 [Lõi, L] Mô hình và hybrid** — Xong khi: model card và bảng so với baseline MR5. Model card: [`model-card-rba.md`](model-card-rba.md); kết quả và phân tích: [`ml-evaluation-v2.md`](ml-evaluation-v2.md); bảng đầy đủ 13 mô hình × 11 bài: [`rba-baseline-comparison.md`](rba-baseline-comparison.md)
  - [x] Unsupervised chỉ học từ đăng nhập hợp lệ: Isolation Forest (MR5), kNN-distance (thay LOF: cùng họ nhưng chạy được trên hàng triệu dòng bằng phép nhân ma trận), Autoencoder 32-12-32 ([`models.py`](../backend/ml/rba/models.py))
  - [x] Supervised LightGBM trên nhãn Attack IP (chia theo nhóm IP, trọng số dân số) và trên kẻ tấn công mô phỏng; mô hình gộp hai nguồn với tỉ trọng ρ chọn trên val
  - [x] Đánh giá trên ATO thật: recall ở FPR 1% / 0,1%, khoảng tin cậy bootstrap. **Kết quả âm tính:** mô hình có giám sát không chuyển sang ATO thật (0% ở FPR 1%); Isolation Forest không nhãn bắt 42,1% [26–55%]
  - [x] Hybrid "bất kỳ bộ phát hiện nào báo động" (3 thành phần có cổng, [`ensemble.py`](../backend/ml/rba/ensemble.py)), hiệu chỉnh isotonic, ngưỡng chọn trên val rồi chuyển sang test/late (FPR thực tế 0,92% / 0,85% cho mục tiêu 1%) — [`analysis.py`](../backend/ml/rba/analysis.py)
  - [x] Cá nhân hoá và cold-start: `gbm_combined_global` (chỉ đặc trưng toàn cục) + bảng theo mức lịch sử. Cá nhân hoá quyết định chống chiếm tài khoản (AUC 0,94 → 0,51); hybrid không báo nhầm tài khoản mới nhiều hơn mức chung nhưng ATO ở đó (35%) chưa bắt được — khoảng trống còn lại
  - ➡️ Mô hình B (địa lý-thời gian) **chuyển sang MR18**: cần thư viện kịch bản tấn công của MR18 và simulator hiện tại (`ml/generate_dataset.py`) dựa trên DB
  - ⚠️ Điều chỉnh/bài học: (1) chọn nạn nhân, IP và hồ sơ của kẻ tấn công mô phỏng sai bảy lần (mô hình học cách mô phỏng, recall 100% giả tạo) — mỗi lỗi do `ml/rba/audit.py` chỉ ra; số kẻ tấn công của CP1 đã đính chính; (2) trọng số dân số; (3) bộ mô phỏng không thay thế được ATO thật: kết quả trên kẻ tấn công mô phỏng chỉ dùng để so sánh mô hình
- [x] **MR7 [Lõi, M] Kiểm chứng "kiểu tấn công mới" và ablation** — Xong khi: bảng ablation và kết luận trung thực. Kết quả: [`ml-holdout-ablation.md`](ml-holdout-ablation.md)
  - [x] Giấu từng họ tấn công khỏi tập train (8 họ IP tấn công theo hành vi/nhà mạng/quốc gia/thiết bị; 4 cách giấu kiểu kẻ tấn công mô phỏng; ATO thật là họ chưa thấy theo thiết kế), đo phần bắt được ([`holdout.py`](../backend/ml/rba/holdout.py)). ⚠️ RBA gần như không có thiết bị bot (2 dòng) nên "bot/device" thay bằng loại thiết bị. **Kết quả:** LightGBM chưa thấy họ IP tấn công bắt 0,0–1,1% ở 5/6 họ (15–56% khi đã thấy); bộ phát hiện không nhãn tối đa 10,1%; kẻ tấn công mô phỏng tổng quát một phần (giữ 30–91%)
  - [x] Ablation theo nhóm đặc trưng cho LightGBM IP tấn công, LightGBM kẻ tấn công mô phỏng và Isolation Forest trên ATO ([`ablation.py`](../backend/ml/rba/ablation.py)): mô hình học từ kẻ tấn công mô phỏng không có nhóm "đường tắt" nào tự mang tín hiệu (0,0–1,7%); Isolation Forest bắt ATO nhờ mới lạ/độ hiếm nhà mạng, bỏ nhóm hạ tầng IP tăng gần gấp đôi recall ATO
  - [x] Phân tích lỗi ([`errors.py`](../backend/ml/rba/errors.py)): 103/130 ATO bị bỏ sót (0/46 tài khoản chưa có lịch sử) nhưng một luật `rare_asn` không học bắt 65,8% ATO tương lai; báo nhầm dồn vào đăng nhập từ quốc gia/nhà mạng mới (gấp 3,5 lần mức chung)
  - [x] Ghi thẳng giới hạn với Targeted: bắt 58,9% khi đăng nhập trong 1 phút sau lần trước, 6,5% khi cách > 30 ngày; sàn lý thuyết khi kẻ tấn công dùng cả IP của nạn nhân
  - ⚠️ Phát hiện cần quyết ở CP2: chọn lại nhóm đặc trưng cho từng thành phần trên val hoặc trên 92 ca ATO quá khứ (cần đồng ý vì trái quy tắc "ATO không dùng để chọn"); thêm rule "nhà mạng cực hiếm" ở MR9
- [x] **MR8 [Lõi, M] Giải thích và model card (CP2)** — Xong khi: mỗi cảnh báo có giải thích ngắn kèm "thường … nay …" và đo được độ trung thực của nó. Kết quả: [`ml-explanations.md`](ml-explanations.md); model card cuối: [`model-card-rba.md`](model-card-rba.md)
  - [x] SHAP cho LightGBM (TreeSHAP có sẵn của LightGBM, trùng thư viện `shap` từng chữ số); z-score fallback cho unsupervised ([`explain.py`](../backend/ml/rba/explain.py)). Đo độ trung thực bằng phép thử xoá/giữ yếu tố ([`explain_eval.py`](../backend/ml/rba/explain_eval.py)): xoá các yếu tố nêu ra làm mất 99–100% cảnh báo (xoá ngẫu nhiên 49–90%). ⚠️ Ba yếu tố chỉ là phần **chủ đạo**: chỉ giữ chúng thì bộ không giám sát còn khoảng 68% điểm, `ip_tan_cong` 66%
  - [x] Câu tiếng Việt ngắn từ top-3 yếu tố (50 đặc trưng gộp thành 9 yếu tố), kèm "thường … → nay …" từ lịch sử thành công của tài khoản (`build_context`): trung vị 57–118 ký tự, dài nhất 151; số thập phân giữ dấu chấm như chuỗi cảnh báo hiện có. ⚠️ Chưa nối vào cảnh báo thật — việc của MR12 (nạp mô hình, ngữ cảnh từ `login_events`) và MR13 (định dạng trong `alerts`)
  - [x] Model card: dữ liệu, chỉ số, giới hạn, phiên bản đặc trưng (`v2`, chữ ký `2e54756a441c`), ngưỡng vận hành (hybrid 2,410 và 3,365: ~102 và ~10 cảnh báo nhầm trên 10 nghìn đăng nhập hợp lệ thành công; độ chính xác của cảnh báo theo tỉ lệ tấn công: 0,26% nếu 1 trên 10.000)
  - ⚠️ Phát hiện MR8: kiểm định dấu vân tay **có điều kiện** (thêm `python -m ml.rba.audit conditional`: chỉ so với đăng nhập hợp lệ cũng dùng IP mới) cho thấy kẻ tấn công mô phỏng còn tách được ở nhóm IP (AUC 0,67–0,72) và độ hiếm (0,67–0,71) mà kiểm định tổng thể ở MR6 bỏ sót → recall trên kẻ tấn công mô phỏng là **cận trên** (tối đa khoảng 6–12 điểm); ATO thật không bị ảnh hưởng

- [x] **MR8b [Lõi, S] Chốt mô hình ở CP2 (thực hiện D1, D2)** — Xong khi: hybrid chốt được dựng lại, so trước/sau và có ngưỡng vận hành mới. Kết quả: [`ml-model-selection.md`](ml-model-selection.md); mã: [`selection.py`](../backend/ml/rba/selection.py)
  - [x] D1: `gbm_attacker_sim_cp2` chỉ dùng 28 đặc trưng quan hệ với lịch sử tài khoản; recall kẻ tấn công mô phỏng của hybrid 47,1 / 37,2 / 17,8% → 36,4 / 27,0 / 8,4% (số trung thực hơn, vẫn là cận trên)
  - [x] D2a: Isolation Forest chọn nhóm đặc trưng bằng loại trừ lùi có kiểm định ghép cặp trên 92 ATO quá khứ → bỏ `infra_ip`
  - [x] D2b: `gbm_attack_ip` chọn trên val → đề xuất bỏ `infra_asn` (PR-AUC +0,007) → **phủ quyết theo `late`** (recall 11,1% → 6,5%) nên giữ bản MR6. ⚠️ Quy tắc phủ quyết được thêm sau khi thấy kết quả; ứng viên vẫn lưu để đảo lại
  - [x] Hybrid chốt `hybrid_cp2` (ngưỡng 2,391 / 3,345): ATO tương lai 26,3% [13–39] → 36,8% [21–51], ATO cả 130 ca 23,8% → 31,5%, IP tấn công 12,3% → 12,4%; độ chính xác cảnh báo ở mức 0,1% tăng 0,25% → 0,74% (tấn công 1/10.000). ⚠️ 38 ATO tương lai đã bị nhìn ở MR7 nên chỉ xác nhận; ATO của RBA có đặc điểm nhân tạo

### CP2 — quyết định của chủ dự án (D1–D3 đã duyệt 26/09/2026; D4 còn mở)

Các mục dưới đây đổi mô hình hoặc quy tắc nên cần đồng ý. Mỗi mục ghi đề xuất của tôi và kết quả.

- [x] **D1. Xử lý dấu vân tay có điều kiện của kẻ tấn công mô phỏng.** (a) *Đề xuất, rẻ:* huấn luyện lại `gbm_attacker_sim` chỉ với đặc trưng quan hệ với lịch sử tài khoản (`novelty`, `freeman`, `rhythm`, `history`), chọn trên val, rồi đo lại hybrid; chi phí ~1 phiên. Lý do có sẵn ở MR7 (ablation: 47,7 / 37,7 / 16,2%) và MR8 (kiểm định có điều kiện), không dùng ATO để chọn. (b) *Triệt để, sau:* sinh lại kẻ tấn công với IP mượn chỉ từ đăng nhập mà chính chủ cũng dùng IP mới, huấn luyện và đo lại MR6–MR7 (~2–3 phiên) — gộp vào MR18 (thư viện tấn công v2). (c) Không làm gì, ghi "cận trên" (đã ghi). ✅ **Đã duyệt (a) ngày 26/09/2026 và làm ở MR8b** ([`ml-model-selection.md`](ml-model-selection.md) mục 2); (b) gộp vào MR18.
- [x] **D2. Dùng 92 ca ATO quá khứ (`ato/all` trừ `ato/future`) làm tập chọn ngoài** để chọn nhóm đặc trưng cho từng thành phần, giữ 38 ca tương lai để báo cáo cuối. Trái quy tắc hiện tại "ATO không bao giờ dùng để chọn", nên cần đồng ý. Cần vì ablation MR7 cho Isolation Forest bỏ nhóm `infra_ip` (recall ATO 31,6% → 60,5%) đo ngay trên 38 ca tương lai — không thể dùng làm căn cứ chọn; lưu ý 38 ca đó đã bị nhìn ở MR7 nên vẫn cần ghi rõ khi báo cáo. Đề xuất: đồng ý, chỉ để chọn nhóm đặc trưng của Isolation Forest (mô hình không nhãn, không có tập chọn nào tốt hơn vì kẻ tấn công mô phỏng còn dấu vân tay, D1); `gbm_attack_ip` chọn trên val bằng nhãn IP tấn công, không cần ATO. ✅ **Đã duyệt và làm ở MR8b** ([`ml-model-selection.md`](ml-model-selection.md) mục 3–4): Isolation Forest bỏ `infra_ip` (35,9% → 51,1% trên 92 ca quá khứ; 42,1% → 57,9% trên 38 ca tương lai); `gbm_attack_ip` đề xuất bỏ `infra_asn` trên val nhưng bị phủ quyết theo `late` (quy tắc thêm sau khi thấy kết quả).
- [x] **D3. Thêm luật "nhà mạng cực hiếm" ở MR9** (đăng nhập thành công từ ASN gần như chưa từng thấy). Luật một đặc trưng `rare_asn` bắt 65,8% ATO tương lai ở MR7; ⚠️ đánh giá trên ATO của RBA là **vòng tròn** (bộ dữ liệu tổng hợp cho ATO dùng nhà mạng hiếm), nên số đó không được dùng để tuyên bố luật hay hơn AI; giá trị thật của luật đo bằng kịch bản mô phỏng ở MR18. Đề xuất: thêm. ✅ **Đã duyệt ngày 26/09/2026**: luật `rare_network_login` làm ở MR9 (chế độ shadow mặc định).
- [ ] **D4. Độ dài giải thích trong danh sách cảnh báo** (MR13): giữ top-3 (tối đa 151 ký tự) hay rút còn top-2 kèm chi tiết mở rộng. Có thể quyết sau.

## Giai đoạn C — Rule engine v2

- [x] **MR9 [Lõi, L] Rule engine v2** — Xong khi: ≥ 12 rule có test, danh mục rule tự sinh vào docs. Danh mục (tự sinh từ mã, có test chống lỗi thời): [`rule-catalog.md`](rule-catalog.md); kết quả replay trên RBA: [`rule-replay.md`](rule-replay.md); mã: [`backend/app/detection/engine/`](../backend/app/detection/engine/)
  - [x] Registry ([`registry.py`](../backend/app/detection/engine/registry.py)): mã, mô tả, mức nghiêm trọng, ánh xạ MITRE ATT&CK (T1110, T1110.001/.003/.004, T1078, T1090/.002/.003, T1589), tham số có kiểu/đơn vị/khoảng hợp lệ (tham số sai bị từ chối ngay khi nạp), ghi đè bằng JSON (`RuleConfig`), ba chế độ enforce / shadow / off. ⚠️ Ánh xạ MITRE là gần đúng: ATT&CK mô tả kỹ thuật của kẻ tấn công, luật nhận dấu hiệu của chúng trong log đăng nhập
  - [x] 19 luật trong 4 nhóm, 14 mặc định enforce và 5 shadow (`regular_rhythm`, `country_hop`, `rare_network_login`, `datacenter_ip`, `vpn_ip`: chưa kiểm chứng hoặc dễ báo nhầm): đoán/dò mật khẩu (brute force, nhồi thông tin, rải mật khẩu chậm, dò phân tán vào một tài khoản, dò danh sách tài khoản, thành công sau chuỗi sai), tự động hoá (UA bot, client kịch bản, xoay UA, nhịp đều), ngữ cảnh tài khoản (di chuyển bất khả thi, nhiều quốc gia cùng lúc, nhảy quốc gia, tài khoản ngủ đông, nhà mạng cực hiếm — D3), danh tiếng hạ tầng (Tor, datacenter, VPN, blocklist của quản trị viên). Danh sách công khai nạp từ `backend/threat_intel/` (MR1); thiếu danh sách thì luật bị bỏ qua kèm lý do rõ ràng thay vì báo động sai
  - [x] Nâng luật cũ: `credential_stuffing` thêm phạm vi ASN, nới ngưỡng một nửa khi thấy xoay User-Agent, bỏ qua khi tỉ lệ thành công cao (nhiều người dùng thật sau một cổng NAT); ba luật gốc giữ nguyên ngưỡng và chuỗi thông điệp của tầng 1 cũ (5 lần/5 phút; 10 lần và 5 tên/5 phút; 900 km/h)
  - [x] Thiết kế để dùng chung cho luồng thật (MR12), replay và test: một đầu vào duy nhất `LoginAttempt`; thời gian là thời gian SỰ KIỆN nên replay log 2020 cho đúng kết quả của 2020; trạng thái cửa sổ ở `WindowStore` với hai cài đặt (`MemoryStore`, `RedisStore`) chạy chung một bộ test hợp đồng và cho kết quả giống hệt trên lưu lượng ngẫu nhiên; chi phí mỗi sự kiện bị chặn bởi ngưỡng (không bậc hai theo độ dài cửa sổ); luật không bao giờ thấy nhãn (đổi nhãn không đổi kết quả); luật lỗi hoặc thiếu dữ liệu bị cô lập và ghi lại, không chặn luật khác
  - [x] Test: 144 test riêng cho engine (50 test dương/âm cho từng luật, 27 cho kho cửa sổ, 12 cho bộ máy chấm, 12 cho registry/cấu hình, 11 cho nguồn danh tiếng, 4 cho danh mục, 14 cho replay và 14 cho bộ chuyển đổi RBA). Test bắt được 1 lỗi thật của cơ chế dọn khoá (điều kiện kích hoạt không bao giờ đạt khi mọi lần ghi tạo khoá mới)
  - [x] Bộ replay ([`replay.py`](../backend/app/detection/engine/replay.py), bộ chuyển đổi [`rule_replay.py`](../backend/ml/rba/rule_replay.py); lệnh `python -m app.detection.engine.replay rba|db`): phát lại log theo thời gian qua đúng `RuleEngine.evaluate`, đo từng luật (khớp, khớp trên dòng không nhãn, chia theo nhãn, theo phạm vi IP/ASN, số IP bị khớp, luật bị bỏ qua và lý do), độ trễ và bộ nhớ; nguồn RBA và bảng `login_events`. Giai đoạn train RBA (12.957.314 lần thử, 179,5 ngày) chạy trong 1.799 giây (~7.200 lần thử/giây trên một tiến trình Python khi chạy song song với hai lần chạy khác, ~8.200 khi chạy riêng; độ trễ engine trung bình 0,12 ms, p99 0,30 ms, lớn nhất 1,4 giây — một lần, chưa rõ nguyên nhân, nghi bộ gom rác khi giữ 2.492.848 tài khoản) với 1.539 MB bộ nhớ
  - ⚠️ **Kết quả trung thực (tham số mặc định đặt trước, CHƯA tinh chỉnh):** trên giai đoạn train RBA, các luật `enforce` gộp lại báo **5.421 lần khớp trên dòng không nhãn cho mỗi 10.000 đăng nhập hợp lệ thành công** (mô hình hybrid ở FPR 1%: ~93 cảnh báo nhầm/10.000 — không so ngang được vì luật báo cả lần thất bại và chưa gộp cảnh báo trùng; tính riêng lần THÀNH CÔNG không nhãn: 215/10.000; gộp theo IP: 567.619 IP không nhãn bị khớp trong 179 ngày), nhưng chỉ bắt 43,7% dòng và 37,8% IP tấn công và **8/86 ATO** (thêm các luật shadow, chủ yếu `rare_network_login` — vòng tròn với cách RBA sinh ATO — mới lên 61/86). Thủ phạm chính là luật theo nhà mạng/IP: `password_spray_slow` 3.521 và `credential_stuffing` 1.652 lần/10.000, trong đó phạm vi ASN chiếm 1.437.908 và 1.250.524 lần khớp (90,7% và 71,6% rơi vào dòng không nhãn). Đây là số ĐO của giá trị đặt trước, đúng việc cần làm ở MR10 (tinh chỉnh ngưỡng trên train, báo cáo trên test), không phải kết luận về khả năng của rule engine
  - ⚠️ Giới hạn của phép đo trên RBA (in trong báo cáo): (1) dòng không nhãn coi là hợp lệ nhưng nhà mạng có phần lớn dòng mang nhãn tấn công thì phần còn lại chưa chắc hợp lệ, nên số báo nhầm của luật phạm vi ASN là **cận trên**; (2) RBA gộp mọi lần thử vào tên không tồn tại (45% số dòng) thành một `user_id` nên adapter phải đặt tên giả; độ nhạy đo trên 30 ngày cuối của train (2.138.879 lần thử, hai cách đặt tên giả là hai cận của sự thật): `credential_stuffing` gần như không đổi (2.247 → 2.197 lần/10.000), `password_spray_slow` giảm 3.558 → 1.995 nhưng vẫn rất ồn, `username_enumeration` (574 → 0 lần/10.000) và `brute_force` (15,6 → 707) phụ thuộc hoàn toàn vào cách đặt tên nên KHÔNG kiểm chứng được trên RBA — kết luận "luật mặc định ồn" không phụ thuộc vào giả định này; (3) không có toạ độ (`impossible_travel` không chạy), IP tổng hợp (Tor/datacenter/VPN/blocklist không đánh giá được), timestamp có thành phần ngẫu nhiên (cửa sổ vài phút chỉ gần đúng), quốc gia gán ngẫu nhiên, User-Agent tổng hợp đổi liên tục (khiến `dormant_account_login` và `rare_network_login` báo nhiều). Các luật địa lý, danh tiếng IP và những luật dựa vào User-Agent hoặc quốc gia chỉ kiểm chứng được bằng kịch bản mô phỏng (MR18) hoặc log thật
  - ➡️ Chưa làm ở MR9 (đúng phân công): nối engine vào pipeline `/login` và nạp `LoginAttempt` từ DB (MR12), gộp cảnh báo trùng và cột `alerts` mới (MR13), tinh chỉnh ngưỡng và bảng chồng lấn rule/ML (MR10), hành động chặn của blocklist (MR16)
- [x] **MR10 [Nên, M] Tinh chỉnh theo dữ liệu và bù trừ rule/ML** — Xong khi: bảng chồng lấn làm bằng chứng cho hybrid. Kết quả: [`rule-tuning.md`](rule-tuning.md) (tinh chỉnh) và [`rule-ml-overlap.md`](rule-ml-overlap.md) (chồng lấn), cả hai tự sinh; hồ sơ cấu hình luật: [`profiles/rba_train_tuned.json`](../backend/app/detection/engine/profiles/rba_train_tuned.json); mã: [`rule_tuning.py`](../backend/ml/rba/rule_tuning.py), [`rule_tuning_report.py`](../backend/ml/rba/rule_tuning_report.py), [`rule_overlap.py`](../backend/ml/rba/rule_overlap.py)
  - [x] Phương pháp: mỗi luật có một "bậc thang" tham số từ lỏng đến chặt (lần khớp lồng nhau và bậc mặc định trùng đúng quyết định của engine — test trên lưu lượng tổng hợp và trên một ngày RBA thật). MỘT lượt replay toàn bộ 31.269.264 sự kiện RBA (~30 phút) chấm ĐÚNG các dòng, trọng số và định nghĩa dương/âm của khung đánh giá ML (2.707.021 dòng mẫu) ở 14 bậc thang của 12 luật, nên số của luật và của mô hình so được; engine có thêm `observe` (chỉ cập nhật trạng thái) và `probe` (chấm với tham số tuỳ ý). Bảy luật không đánh giá được trên RBA (`username_enumeration`, `regular_rhythm`, `impossible_travel`, Tor/datacenter/VPN, blocklist; lý do trong tài liệu). Chọn bậc chỉ trên train: bậc lỏng nhất có ≤ 5 lần khớp trên dòng bình thường cho mỗi 10.000 đăng nhập hợp lệ thành công (ngân sách đặt trước); nhãn không tham gia chọn
  - [x] Tinh chỉnh có chuyển giao được không (quy trình đặt trước, chỉ train): **10/12** bậc thang giữ được ngoài train (khớp/10.000 trên test ≤ 15); **2 không giữ được**: `credential_stuffing/asn` (0,4 → 0,3 → 29,4 → 345,9 qua train → val → test → late: số lần sai/số tên tuyệt đối của một nhà mạng đi theo lưu lượng của nó) và `dormant_account_login` (0,0 → 89,1 → 288,4 → 493,7; ở bậc mặc định 228,9 → 827,2 → 973,3 → 1.243,9: tỉ lệ khớp tăng theo tuổi của log vì ngày càng nhiều tài khoản có ≥ N ngày lịch sử). ⚠️ Quy trình sửa (chọn trên train VÀ val) và việc loại hai bậc thang này khỏi hồ sơ được thêm SAU khi thấy điều trên nên test không còn "sạch" về mặt thiết kế quy trình; tài liệu ghi cả hai quy trình để đối chiếu
  - [x] Bộ luật trong hồ sơ (9 bậc thang enforce): khớp/10.000 trên test **19,9 [17,1–23,5]** so với 2.387 ở tham số mặc định (giảm ~120 lần), NHƯNG recall dòng tấn công **0,3% [0,1–0,4%]** so với 38,0% (late: 29,1/10.000, 1,6%); ATO tương lai 1/38 và tất cả 5/130 (mặc định 5/38 và 17/130). Recall của bộ mặc định được mua bằng báo nhầm gấp ~120 lần, gần hết từ phạm vi ASN. 2 bậc thang không chọn được bậc nào ở ngân sách này (`password_spray_slow/asn`, `rare_network_login`): riêng ngưỡng không đủ, cần thêm điều kiện (chuẩn hoá theo lưu lượng nhà mạng)
  - [x] Bảng chồng lấn với `hybrid_cp2` (ngưỡng chọn trên val cho FPR 1% = 2,391 và 0,1% = 3,345): trên `attack_ip/test` ở FPR 1% — chỉ mô hình 12,0%, cả hai 0,0%, chỉ luật 0,2%, **cả hai bỏ sót 87,7%**. So công bằng (bộ gộp so với CHỈ mô hình nới ngưỡng đến cùng tổng báo nhầm): **-0,0 điểm [-0,2; +0,2]** ở FPR 1%, -3,4 điểm [-4,7; -2,3] ở 0,1%; `late` +1,4 điểm [-0,0; +4,0]; ATO tương lai -5,3 điểm [-13,2; +0,0]. Bộ luật MẶC ĐỊNH thua rõ (-13,0 điểm [-15,3; -10,5] ở `attack_ip/test`, -47,4 điểm [-63,2; -34,2] ở ATO tương lai)
  - ⚠️ **Kết luận trung thực cho hybrid:** trên khung đánh giá ML của RBA, luật — kể cả đã tinh chỉnh — KHÔNG cộng thêm recall so với chỉ nới ngưỡng mô hình ở cùng tổng báo nhầm (chênh lệch của bộ đã tinh chỉnh nằm giữa -5,3 và +1,4 điểm, không khoảng tin cậy nào nằm hẳn về phía dương và có chỗ âm rõ ở FPR 0,1% của `attack_ip/test`). Không thể dùng bảng này để nói "kết hợp luật giúp phát hiện nhiều hơn". Lý do giữ luật phải dựa vào thứ nằm NGOÀI khung này: (a) lưu lượng vào tên không tồn tại (45% số dòng RBA, mô hình không chấm được; mới đo ở tham số mặc định ở MR9, chưa tinh chỉnh), (b) danh tiếng IP, blocklist, toạ độ mà RBA không có, (c) phản ứng tức thời và giải thích được. Gợi ý cho MR11: dùng lần khớp luật làm bằng chứng cộng vào điểm rủi ro/quyết định hành động, không cộng gộp cảnh báo kiểu "luật HOẶC mô hình" vì làm tăng báo nhầm mà không tăng recall
  - ⚠️ Giới hạn: quét một chiều mỗi luật; hai bậc thang (`distributed_bruteforce`, `ua_rotation`) chọn ở bậc lỏng nhất (bậc thang chưa đủ lỏng, nhưng chúng chỉ bắt 13 và 2 dòng mà mô hình bỏ sót nên không đổi kết luận); số tên khác nhau tối đa 200 (`indexes.CAP`); dòng không nhãn coi là bình thường (khớp/10.000 là cận trên); ngưỡng chỉ tinh chỉnh cho RBA (tổng hợp), không tự nhiên áp cho hệ thống thật; 38 ATO tương lai đã bị nhìn ở MR7 và `rare_network_login` vòng tròn với cách RBA sinh ATO

## Giai đoạn D — Hợp nhất và tích hợp

- [x] **MR11 [Lõi, M] Hybrid risk engine** — Xong khi: điểm 0-100 giải thích được, chính sách hành động, kiểm tra chuyển miền. Kết quả: [`hybrid-risk-engine.md`](hybrid-risk-engine.md) (tự sinh); hồ sơ hiệu chỉnh: [`profiles/rba_calibrated.json`](../backend/app/detection/hybrid/profiles/rba_calibrated.json); mã: [`app/detection/hybrid/`](../backend/app/detection/hybrid/) (bộ gộp, dùng ở luồng thật MR12), [`ml/rba/hybrid_calibrate.py`](../backend/ml/rba/hybrid_calibrate.py) (hiệu chỉnh trên RBA)
  - [x] Điểm = noisy-OR có trọng số của BA nguồn: xác suất `hybrid_cp2` đã hiệu chỉnh (hồi quy isotonic trên `attack_ip/val`, Brier 0,0607 so với 0,0769 nếu đoán theo tỉ lệ trung bình), xác suất gộp của các luật KHÔNG thuộc nhóm danh tiếng, xác suất gộp nhóm "Danh tiếng hạ tầng". `blocklist_hit` GHI ĐÈ (điểm 100, khoá tạm) vì là quyết định của quản trị viên, không phải bằng chứng xác suất — đường này chưa kiểm được trên RBA (blocklist rỗng khi replay), chỉ có unit test tổng hợp
  - [x] Trọng số MỘT luật = độ chính xác đo trên `val` khi luật khớp ở bậc MẶC ĐỊNH của sổ đăng ký (dùng lại `levels.parquet` của MR10, không replay lại RBA lần nữa): `credential_stuffing` cao nhất (34,6%, n=7.111), phần lớn luật khác 0–10%. 7/19 luật không thể đánh giá trên RBA (thiếu IP thật/toạ độ/tên đăng nhập phân biệt được — như MR10 mục 6) và 3 luật có bậc thang nhưng không khớp lần nào trên `val` vì quá hiếm (`bot_user_agent`, `scripted_client`, `ua_rotation`) — cả hai nhóm dùng trọng số đặt trước 5%, đánh dấu rõ `calibrated: false`. Luật `shadow` (MR9) vẫn là bằng chứng đầy đủ ở đây — shadow chỉ quyết định rule engine có TỰ tạo cảnh báo hay không
  - [x] Ba ngưỡng hành động (0–100, chọn trên đăng nhập hợp lệ THÀNH CÔNG của val cho FPR 1%/0,1%/0,01% — hai mức đầu trùng hai ngưỡng vận hành đã công bố của `hybrid_cp2`): `alert_at`=32, `step_up_at`=58, `lock_at`=70
  - [x] **Kiểm tra chuyển miền (val → test/late trong RBA):** so sánh CÔNG BẰNG (bộ gộp ở ngưỡng triển khai so với CHỈ mô hình được hiệu chỉnh RIÊNG ở cùng ba FPR mục tiêu — tránh lỗi đã tự phát hiện: điểm gộp luôn ≥ điểm ML nên so ở cùng ngưỡng tuyệt đối luôn có lợi giả tạo cho bộ gộp). Ở mức `alert` (ngân sách lỏng nhất), bộ gộp bắt được NHIỀU HƠN RÕ RỆT: `attack_ip/test` 43,4% [41,0–45,9%] so với 11,7% [8,1–15,5%] chỉ ML; `attack_ip/late` 46,1% [44,0–48,2%] so với 6,7% [4,8–9,1%]; `ato/future` 36,8% so với 31,6%. Ở mức `step_up`/`lock` (ngân sách chặt) phần thêm gần như biến mất — khớp kết luận của MR10 ở vùng đó
  - ⚠️ **Vì sao không mâu thuẫn với MR10** ("gộp không tăng recall ở cùng ngân sách"): MR10 so hai bộ CỰC ĐOAN (union thô ngân sách khổng lồ ~18,6%, hoặc luật đã tinh chỉnh riêng lẻ nên gần như không còn recall một mình — 0,3%). MR11 dùng NGUYÊN luật mặc định (còn nhiều recall khi đứng riêng) nhưng trọng số theo ĐÚNG độ chính xác đo được rồi hiệu chỉnh ngưỡng của điểm GỘP (không phải từng luật) để tự đạt đúng FPR mục tiêu — nhờ vậy phần recall thêm ở mức `alert` là thật, không phải giả tạo do đốt ngân sách
  - [x] Kẻ tấn công mô phỏng (CẬN DƯỚI, chỉ thành phần ML vì rule engine chưa từng chạy trên dòng chèn — bằng chứng luật thật chỉ làm TĂNG, không giảm): `naive` 31,9% đạt ít nhất `alert`, `targeted` (mạnh nhất) 6,6% — thấp hơn hẳn do đã bắt chước gần như toàn bộ hồ sơ nạn nhân (đúng giới hạn đã biết từ MR4)
  - ➡️ Chưa làm ở MR11 (đúng phân công): chuyển miền sang "live" (log thật của web app mẫu) — cần pipeline tính đặc trưng RBA và chạy rule engine trên `login_events`, thuộc MR12; nối bộ gộp vào `app/detection/pipeline.py` và nạp model theo phiên bản cũng là việc của MR12

- [x] **MR12 [Lõi, L] Tích hợp realtime (CP3)** — Xong khi: migration chạy thật, parse UA/tra ASN không chặn `/login`, model theo phiên bản có fallback, đo được độ trễ/tải, có công cụ theo dõi drift. Kết quả và giới hạn: [`realtime-integration.md`](realtime-integration.md) (viết tay, số liệu dẫn nguồn cụ thể); schema: [`db-schema.md`](db-schema.md)
  - [x] Migration Alembic (`e1318f3ac8e5`, ĐÃ CHẠY THẬT lên Postgres dev — xác nhận qua `information_schema`, không chỉ đọc file): cột mới `login_events` (asn có index, os_name, browser_name, device_type, hybrid_risk_score, hybrid_action) và `alerts` (rule_id, attack_family, explanation JSON, campaign_id, status, feedback — giữ nguyên `resolved`/`resolved_at` cũ để tương thích ngược); 5 bảng mới `campaigns`, `blocklist`, `response_actions`, `audit_log`, `model_registry`
  - [x] Parse UA (`app/utils/device.parse_user_agent`, có sẵn từ MR1) + tra ASN (`geoip.lookup_asn`) ngay khi dựng `LoginEvent`, trong pipeline NỀN — không thêm gì vào đường phản hồi `/login`. Đã cài **GeoLite2-ASN thật** vào `backend/geoip/` (người dùng xác nhận cài, không dùng lại key MaxMind — file đã tải sẵn); xác nhận qua ASN thật của Google (15169) trên IP `8.8.8.8`, không phải chế độ mock
  - [x] Rule engine v2 (MR9-10) nối vào pipeline: trạng thái cửa sổ trong REDIS THẬT (dùng chung kết nối với `rate_counter.py`); lịch sử tài khoản + thống kê ASN toàn cục dựng lại từ DB mỗi lần chấm (đúng dù nhiều worker/vừa restart); blocklist DB-backed (bảng mới) cache 15 giây. Đặc trưng RBA (`ml/rba/features.py`, có sẵn từ MR3) tính từ DB thật qua 4 truy vấn nhắm chỉ mục — CÙNG hàm `features_from_summary` dùng để train, không phải bản sao công thức riêng
  - [x] Hybrid risk engine (MR11) chấm mỗi lần đăng nhập: điểm/hành động ghi vào `login_events`; hành động khác `allow` tạo `Alert` (`rule_id`, `explanation` JSON là danh sách đóng góp); `step_up`/`lock` thêm một hàng `response_actions` (**status luôn `"recommended"` — CHƯA thực thi thật, việc của MR16**) và một hàng `audit_log`. Toàn khối cô lập trong try/except riêng — lỗi ở đây không được làm mất alert tầng 1-2-3 (kiểm bằng test)
  - [x] Nạp model theo phiên bản (bảng `model_registry`, tự đăng ký lúc khởi động) + fallback an toàn: thiếu hàng active/thiếu file/`feature_signature` lệch đều bị nuốt lỗi, dùng hồ sơ dự phòng cứng (chỉ luật, không ML) — không bao giờ tắt hẳn phát hiện
  - [x] **Đo độ trễ và tải:** trong tiến trình (`app/detection/perf.py`), pipeline nền trung bình 12-28 ms (cache nóng), một lần nguội tới 134 ms. Qua HTTP thật (server + Postgres + Redis thật): tuần tự trung vị 280 ms (tương đương ~250-260 ms của Tuần 5, vì MR12 chạy NỀN không cộng vào phản hồi); 20 đồng thời trung vị 3,6 giây, p99 6,0 giây
  - ⚠️ **Phát hiện và đã sửa ngay trong MR12:** `run_detection_pipeline` là `async def` nhưng gọi TOÀN BỘ I/O ĐỒNG BỘ bên trong — chặn vòng lặp sự kiện dùng chung, đo tải 20 đồng thời TRƯỚC khi sửa ra `httpx.ReadTimeout` thật sự (không chỉ chậm). Đã tách lõi đồng bộ chạy trong `asyncio.to_thread` + tăng pool kết nối DB (5+10 → 20+20). Sau khi sửa: hết timeout nhưng độ trễ dưới tải vẫn cao (nghi bcrypt giữ GIL + nhiều round-trip DB mỗi lần chấm, chưa cô lập rạch ròi — đã thử nới thêm executor mặc định nhưng đo lại không thấy lợi nên bỏ, chỉ giữ hai thay đổi đã CHỨNG MINH được ích lợi bằng số đo)
  - [x] Theo dõi trôi đặc trưng (PSI, `ml/rba/drift.py`, có test toán học riêng): so đặc trưng RBA (train, 1,14 triệu dòng) với đặc trưng tính lại từ CHÍNH `login_events` thật. **Kết quả trung thực: phần lớn đặc trưng trôi đáng kể (PSI > 1, có đặc trưng > 8)** — quy mô web app mẫu (66 user) khác RBA hàng nghìn lần nên các đặc trưng "độ hiếm" luôn trôi mạnh, không phải lỗi mô hình; điểm hybrid trên dữ liệu thật CHƯA được hiệu chỉnh đúng quy mô này, chỉ nên đọc như tín hiệu tham khảo thêm (như `ml_anomaly_score` tầng 3 cũ)
  - [x] Giữ toàn bộ test cũ (không sửa test nào để "cho qua") và thêm test mới: 63 test mới (perf, đặc trưng RBA từ DB, rule engine runtime, model registry, hybrid runtime, pipeline tích hợp qua HTTP thật bao gồm kịch bản blocklist ghi đè xác định, PSI) — toàn bộ 600 test của backend đều qua
  - ➡️ Chưa làm ở MR12 (đúng phân công, để lại cho sau): thực thi thật hành động `step_up`/`lock` (MR16); gán `campaign_id`/`attack_family` và router duyệt cảnh báo/blocklist (MR13+); hiệu chỉnh lại `hybrid_cp2` cho đúng quy mô dữ liệu thật (cần đủ dữ liệu tích luỹ)

## Giai đoạn E — Cảnh báo thông minh và vận hành

- [x] **MR13 [Lõi, M] Cảnh báo thông minh v2** — Xong khi: đo được mức giảm số cảnh báo và độ chính xác gán họ trên simulator. Kết quả: [`alert-intelligence-v2.md`](alert-intelligence-v2.md); mã: [`alert_intelligence.py`](../backend/app/detection/alert_intelligence.py), kịch bản đo: [`alert_intelligence_sim.py`](../backend/scripts/alert_intelligence_sim.py)
  - [x] Novelty alert ("lần đầu quốc gia/ASN/thiết bị này, trước đó dùng X N lần") — so với lịch sử THÀNH CÔNG của tài khoản (`compute_novelty`), nhiều nhất 1 khía cạnh/message (giữ ngắn gọn)
  - [x] So sánh với bình thường ngay trong message: D4 đã quyết định cùng người dùng — GIỮ top-3 lý do (không rút xuống top-2, khớp quy ước `explain.py` MR8/message `hybrid_risk` MR12)
  - [x] Gán "họ tấn công" gợi ý kèm độ tin cậy, luôn ghi rõ "gợi ý" (`suggest_attack_family`): 1 trong 4 nhóm luật (`registry.CATEGORIES`) nếu có luật/danh tiếng khớp — ƯU TIÊN luật hơn ML dù trọng số ai cao hơn (lý do: đo thật thấy ML một mình có thể vượt trọng số một luật rõ ràng chỉ vì ASN/quốc gia Việt Nam hiếm so với RBA — xem giới hạn); chỉ dùng 1 trong 3 nhãn thành phần `HybridMinTail` khi không luật nào khớp
  - [x] Chống trùng lặp: cùng (tài khoản, hoặc IP nếu tài khoản không tồn tại) + họ tấn công trong 15 phút (`DEDUP_WINDOW`) và còn "open" thì GỘP (`occurrence_count`, `last_seen_at`) thay vì tạo `Alert` mới; không lặp lại đúng đề xuất cũ mỗi lần trùng (`response_actions`/`audit_log` chỉ ghi thêm khi mức đề xuất TĂNG)
  - [x] Xếp hạng ưu tiên = novelty_level (1 + số khía cạnh mới) × độ tin cậy × `users.importance` (cột mới, mặc định 1.0 mọi tài khoản — demo không có khái niệm "tài khoản quan trọng" thật, placeholder có chủ đích); `GET /alerts` mặc định sắp theo ưu tiên (NULLS LAST cho alert cũ trước MR13), `?sort=recent` giữ hành vi cũ
  - [x] Migration (`222f3d1610a6`, ĐÃ CHẠY THẬT lên Postgres dev, xác nhận qua `information_schema`): `alerts.attack_family_confidence/occurrence_count/last_seen_at/priority_score`, `users.importance`, chỉ mục `(user_id, attack_family, status)`
  - [x] **Đo trên simulator kịch bản có nhãn tự tạo** (RBA không có nhãn "họ tấn công" nên không dùng RBA được, xem `alert_intelligence_sim.py`, 6 kịch bản, DB SQLite cô lập mỗi kịch bản, model `hybrid_cp2` thật): giảm **57,1%** số cảnh báo nhờ chống trùng lặp (7 lần đề xuất khác allow → còn 3 hàng `Alert`, chủ yếu từ kịch bản blocklist 5 lần → 1); trong số kịch bản THỰC SỰ có alert, đúng họ **100%** (2/2) — 3/5 kịch bản không tự vượt ngưỡng "alert" một mình (đúng hiệu chỉnh MR11 đã đo, không phải lỗi, tách riêng thành tỉ lệ vượt ngưỡng 40%, không gộp vào độ chính xác gán họ)
  - ⚠️ **Phát hiện qua chính simulator (không phải giả thuyết)**: kịch bản đối chứng âm (đăng nhập bình thường, khớp lịch sử) VẪN bị báo nhầm — mô hình ML một mình vượt ngưỡng vì ASN/quốc gia Việt Nam của IP dùng trong kịch bản cực hiếm so với phân bố huấn luyện RBA, đúng hệ quả của PSI drift đã công bố ở MR12, lần này đo được CỤ THỂ bằng một ca báo nhầm thật. Đã sửa `suggest_attack_family` để ưu tiên luật hơn ML (tránh gán sai family khi luật rõ ràng cùng tồn tại với ML) nhưng KHÔNG che giấu ca báo nhầm gốc — giữ nguyên IP thật, báo cáo trung thực trong `alert-intelligence-v2.md`
  - ⚠️ **2 bug thật tự phát hiện và sửa (không phải MR13 gây ra, có từ trước)**: `is_impossible_travel` (`app/detection/rules.py`, tầng 1 gốc) và một chỗ tính `elapsed_minutes` riêng trong `pipeline.py` trừ trực tiếp hai datetime mà không chuẩn hoá múi giờ — lộ ra khi test MR13 lần đầu làm 2 lần đăng nhập thành công thật liên tiếp qua SQLite (đọc lại mất tzinfo) — cùng lớp lỗi đã vá ở MR9/MR12 (`ensure_utc`), lần này áp dụng tận gốc tại 2 nơi cụ thể còn sót, không phải lỗi Postgres thật (TIMESTAMP WITH TIME ZONE luôn trả aware)
  - ➡️ Chưa làm ở MR13 (đúng phân công, để lại cho sau): gán `campaign_id`/tương quan chiến dịch NHIỀU tài khoản (MR14); hiển thị `attack_family`/ưu tiên thành badge/bộ lọc trên dashboard (MR17 đã liệt kê "bộ lọc mở rộng theo họ tấn công" là việc của nó); hiệu chỉnh lại `hybrid_cp2` cho đúng phân bố traffic Việt Nam (nguyên nhân gốc của ca báo nhầm ở trên, cần đủ dữ liệu thật tích luỹ, đã ghi từ MR12)
- [x] **MR14 [Nên, M] Tương quan chiến dịch** — Kết quả: [`campaign-correlation.md`](campaign-correlation.md); mã: [`campaign_correlation.py`](../backend/app/detection/campaign_correlation.py), kiểm chứng RBA: [`campaign_correlation_eval.py`](../backend/ml/rba/campaign_correlation_eval.py)
  - [x] Gom alert theo ASN (tín hiệu chính) hoặc IP CÙNG chia sẻ, NHẮM VÀO NHIỀU TÀI KHOẢN khác nhau, nối theo đồ thị (thành phần liên thông qua Union-Find — chuỗi bắc cầu, không chỉ cặp trực tiếp). **Kiểm chứng trên 141 ATO THẬT của RBA**: 83,0% dòng ATO chia sẻ ASN với ≥1 dòng ATO khác (117/141, 22 ASN tái sử dụng) — phần lớn ATO KHÔNG phải tấn công đơn lẻ. Quét cửa sổ 1/7/30/90 ngày (khớp nhịp độ 141 dòng rải gần 1 năm): ở 30 ngày, 26 chiến dịch nhiều nạn nhân bao phủ 60,3% dòng ATO, chiến dịch lớn nhất 10 dòng/10 tài khoản/76,6 ngày qua ASN 197175 — khớp trực giác hạ tầng bị lạm dụng lâu dài, không phải trùng hợp ngẫu nhiên
  - [x] Luồng thật (`app/detection/pipeline.py`) dùng cửa sổ **24 giờ RIÊNG** (không phải cửa sổ tốt nhất đo trên RBA — hai câu hỏi khác nhau: RBA đo "hạ tầng có tái dùng qua nhiều tháng", luồng thật cần "có nên gộp NGAY hôm nay"). Gán GIA TĂNG: alert mới khớp hạ tầng (khác tài khoản) với alert cũ trong 24h thì MỞ RỘNG chiến dịch đang có (hoặc tạo mới), KHÔNG gộp lại hai chiến dịch đã tách nếu có alert bắc cầu đến sau — giới hạn đã biết, chấp nhận có chủ đích
  - [x] API `GET /campaigns` (phân trang, lọc `status`) và `GET /campaigns/{id}` (timeline, số tài khoản bị nhắm tính lúc truy vấn — không lưu cột riêng để tránh lệch trạng thái, đồ thị liên kết); trang "Chiến dịch" trên dashboard (danh sách + chi tiết), route `/dashboard/campaigns`
  - [x] Đồ thị liên kết user–IP–ASN–thiết bị: SVG tự vẽ (bố cục vòng tròn, không thêm thư viện mô phỏng vật lý — số node của một chiến dịch trên demo nhỏ, không cần cytoscape/d3-force), API trả `{nodes, edges}` để MR17 tái dùng nếu cần trực quan hoá khác
  - ⚠️ **2 bug thật tự phát hiện và sửa ngay trong MR14** (không phải giả thuyết — lộ ra qua chính test MR14 dùng timestamp giả để mô phỏng "ngoài cửa sổ 24h"): (1) lọc cửa sổ chiến dịch ban đầu so `Alert.created_at` (giờ HÀNG được ghi, `server_default=func.now()`) với `event.created_at` (giờ ĐĂNG NHẬP, có thể là giờ giả lập/backfill) — hai "đồng hồ" khác nhau khiến lọc theo cửa sổ vô hiệu hoàn toàn; sửa bằng cách lọc theo `LoginEvent.created_at` (giờ đăng nhập thật) nhất quán, thêm `ensure_utc()` ở mọi phép so sánh (cùng lớp lỗi đã sửa ở MR9/MR12/MR13). (2) CSS: quy tắc `.campaign-detail__panel--graph { max-height: none }` khai TRƯỚC `.campaign-detail__panel { max-height: 420px }` trong file nên bị quy tắc sau (cùng độ ưu tiên, khai sau thắng) đè mất — đồ thị bị cuộn bên trong thay vì hiển thị trọn vẹn; xác nhận bằng cách đọc computed style thật qua trình duyệt (không đoán), sửa bằng cách đổi thứ tự khai báo
  - [x] Đã dựng backend + frontend thật (Docker `lad_postgres`/`lad_redis` đang chạy sẵn), tạo admin/tài khoản/campaign tạm để chụp màn hình xác nhận trang danh sách + chi tiết (timeline, tài khoản bị nhắm, đồ thị) render đúng với dữ liệu thật qua API thật — đã xoá sạch dữ liệu tạm sau khi xác nhận, không để lại trong DB dev
  - ➡️ Chưa làm ở MR14 (để lại cho sau): đóng/gộp chiến dịch thủ công qua router quản trị; hiệu năng cho hàng nghìn alert (quét toàn bảng `alerts` mỗi lần chấm — chấp nhận được ở quy mô demo, cùng tinh thần `GlobalCountsCache` MR12); trang chiến dịch đầy đủ bộ lọc/responsive (MR17 "Dashboard v2" đã liệt kê việc này)
- [x] **MR15 [Nên, M] Vòng phản hồi** — Kết quả: [`feedback-loop.md`](feedback-loop.md); mã: [`adaptive_threshold.py`](../backend/app/detection/adaptive_threshold.py), [`retrain_from_feedback.py`](../backend/scripts/retrain_from_feedback.py), mô phỏng K vòng: [`feedback_loop_sim.py`](../backend/scripts/feedback_loop_sim.py)
  - [x] Nút "Đúng"/"Báo nhầm" (kèm ghi chú) — `POST /alerts/{id}/feedback`: ghi `alerts.status` (`resolved`\|`false_positive`) + `feedback`, và MỘT hàng `audit_log` MỖI LẦN gửi (`actor`=username admin, có thể gửi lại/đổi ý — nhật ký giữ cả lịch sử, không chỉ trạng thái cuối). Nút hiển thị trên dashboard (`AlertListPanel.jsx`), ẩn đi khi alert đã có phản hồi, thay bằng nhãn đã xác nhận
  - [x] Ngưỡng thích nghi theo **user/nhóm**: đủ phản hồi (≥3, `MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD`) → `user_risk_profiles.threshold_delta` riêng cho tài khoản; chưa đủ → dùng thẳng ngưỡng NHÓM (mặc định toàn hệ thống). Công thức CHỈ NỚI LỎNG (không bao giờ tự thắt chặt xuống dưới mặc định nhóm): `delta = min(4 điểm × (số báo nhầm − số đúng ròng), 20 điểm)` — thắt chặt hơn cần con người quyết định, tự động chỉ nới lỏng theo bằng chứng là hướng an toàn. `scripts/retrain_from_feedback.py` (script ĐỊNH KỲ, không chạy ngay mỗi lần bấm) đọc lại TOÀN BỘ phản hồi tích luỹ và TÍNH LẠI TỪ ĐẦU mỗi lần (không cộng dồn theo số lần chạy)
  - [x] **Đo bằng phản hồi mô phỏng trên CHÍNH pipeline thật** (`feedback_loop_sim.py`, tái dùng đúng kịch bản báo nhầm THẬT đã phát hiện ở MR13): 8 vòng — bị báo ở vòng **1, 2, 3** (chưa đủ mẫu để điều chỉnh), **ngừng báo nhầm hẳn kể từ vòng 4** trở đi; tài khoản bị tấn công thật (blocklist) vẫn bị phát hiện ở **cả 8/8 vòng** — ngưỡng thích nghi của một tài khoản không làm mất phát hiện tài khoản khác, đo trực tiếp chứ không chỉ tin thiết kế
  - ⚠️ **3 bug thật tự phát hiện và sửa khi dựng MR15 (không phải giả thuyết)**: (1) Chống trùng lặp của MR13 (`pipeline.py`) so `Alert.created_at` (giờ hàng được GHI, `server_default=func.now()`) với giờ ĐĂNG NHẬP của sự kiện — hai đồng hồ khác nhau khiến bộ lọc cửa sổ 15 phút VÔ HIỆU HOÀN TOÀN khi giờ đăng nhập là giờ giả lập (script mới lộ ra ngay); sửa bằng `LoginEvent.created_at` (JOIN) + `ensure_utc()`, thêm test hồi quy. (2) Điểm rủi ro của MỘT tài khoản tự giảm mạnh (32→22/100) chỉ sau ĐÚNG một lần đăng nhập thành công bổ sung — đặc trưng RBA nhạy với độ dày lịch sử TỔNG THỂ, không chỉ độ quen với IP/ASN cụ thể; phải xoá lại lịch sử về baseline mỗi vòng mô phỏng để đo đúng tác dụng riêng của ngưỡng thích nghi. (3) Dù đã xoá lịch sử, điểm vẫn tự trôi nhẹ nếu các vòng cách nhau NHIỀU NGÀY (đặc trưng "tuổi tài khoản" tự tăng theo lịch dù số dòng không đổi) — phải cho các vòng cách nhau vài giây, không phải vài ngày, để cô lập đúng biến đang đo. Cả ba đều được ghi lại đầy đủ trong `docs/feedback-loop.md`
  - [x] 34 test mới (adaptive_threshold, retrain_from_feedback, alerts feedback endpoint, pipeline wiring qua spy — không cố dựng điểm số chính xác qua toàn bộ mô hình thật, mong manh theo hiệu chỉnh; simulator, regression cho bug (1) ở trên); toàn bộ test backend đều qua
  - ➡️ Chưa làm ở MR15 (để lại cho sau): lên lịch chạy `retrain_from_feedback.py` tự động định kỳ thật (cron/scheduler — hiện chạy tay); chỉnh riêng từng mốc `alert_at`/`step_up_at`/`lock_at` thay vì đều cả ba; ngưỡng thích nghi theo NHÓM thật sự (vd theo phòng ban) — hiện "nhóm" chỉ là ngưỡng mặc định toàn hệ thống dùng chung cho mọi tài khoản chưa đủ phản hồi
- [x] **MR16 [Thêm, M] Phản ứng tự động (mô phỏng)** — Kết quả: [`automated-response.md`](automated-response.md); mã: [`response_execution.py`](../backend/app/detection/response_execution.py), [`auth.py`](../backend/app/routers/auth.py), [`blocklist.py`](../backend/app/routers/blocklist.py); mô phỏng toàn luồng: [`automated_response_sim.py`](../backend/scripts/automated_response_sim.py)
  - [x] Web app mẫu có bước xác thực thêm (OTP giả lập) khi rủi ro trung bình: mật khẩu đúng nhưng hành động chấm được là `step_up` → tạo `otp_challenges` (mã 6 số, `secrets.randbelow`, băm bcrypt), trả THẲNG trong response `POST /login` (`demo_otp_code`, luôn ghi rõ "GIẢ LẬP" — hệ thống thật sẽ gửi SMS/email). `POST /login/verify-otp` xác thực — cùng thông báo lỗi chung cho MỌI lý do thất bại (không tồn tại/hết hạn/quá 5 lần/sai mã/đã dùng), giống triết lý "sai mật khẩu = tài khoản không tồn tại" đã có. Frontend: `LoginPage.jsx` chuyển sang form OTP khi `step_up_required=true`
  - [x] Khoá tạm tài khoản, chặn IP có hạn dùng, admin có nút mở khoá: `lock` giờ THỰC THI thật (trước đó `response_actions.status` luôn `"recommended"`, MR12) — tạo/gia hạn một `BlocklistEntry` có hạn 30 phút (`LOCK_TTL`), khoá TÀI KHOẢN nếu tồn tại (nặng tay hơn nhưng đúng — bảo vệ ngay cả khi đổi IP) hoặc chặn IP nếu tên đăng nhập không tồn tại. `POST /login` chặn NGAY (HTTP 423) một tài khoản/IP đã trong blocklist TRƯỚC KHI xác thực mật khẩu (không tra ASN ở bước này — đắt; vẫn bị bắt SAU nếu lọt, xem diễn giải trong báo cáo). Admin: `GET /blocklist` (danh sách, mặc định chỉ mục còn hiệu lực) + `DELETE /blocklist/{id}` (mở khoá, ghi audit log rồi xoá hàng, vô hiệu cache 15s ngay) — nút "🔓 Mở khoá" trên dashboard (`BlocklistPanel.jsx`)
  - [x] **Test toàn bộ luồng**: script `automated_response_sim.py` (qua HTTP thật, `TestClient` — KHÔNG bỏ qua router như các script MR13-15, vì logic mới của MR16 nằm CHÍNH ở đó) chạy 2 kịch bản đầu-cuối: (1) nạn nhân đăng nhập bình thường → kẻ tấn công dò trúng mật khẩu từ ASN đã chặn → khoá tài khoản → **nạn nhân cũng bị khoá theo** → admin mở khoá → nạn nhân đăng nhập lại được; (2) đăng nhập đúng mật khẩu với hành động ép `step_up` → nhận OTP → mã sai bị từ chối → mã đúng thành công. Cả 2 kịch bản đều đúng như kỳ vọng. Đo độ trễ riêng qua HTTP thật (Postgres dev): đường ĐÚNG mật khẩu (mới, chờ đồng bộ) chậm hơn đường SAI mật khẩu (nền, không đổi) **~140ms ở median** — khớp cùng bậc với chi phí pipeline trong tiến trình đã đo ở MR12 (p99 134ms)
  - ⚠️ **Phát hiện đáng chú ý (không phải bug — đánh đổi có chủ đích, xem `automated-response.md`)**: khoá tự động khoá theo TÀI KHOẢN (không phải IP kẻ tấn công) khi tài khoản có thật, nên sau MỘT lần bị dò trúng mật khẩu, chính CHỦ tài khoản cũng không đăng nhập được (từ bất kỳ IP nào) cho tới khi admin mở khoá hoặc hết 30 phút. An toàn hơn (chặn toàn bộ khi mật khẩu đã lộ) nhưng là chi phí thật cho người dùng hợp lệ, không phải tác dụng phụ nên bỏ qua
  - [x] 21 test mới (`response_execution.py` thuần: sinh/so khớp OTP, chọn khoá tài khoản hay IP; router `auth.py`: precheck, khoá sau khi chấm điểm — kể cả trường hợp ASN "lọt" precheck, step_up, toàn bộ nhánh lỗi của verify-otp; router `blocklist.py`: danh sách, mở khoá, xác thực admin) + 3 test cũ cập nhật đúng hành vi mới (status `"executed"` thay `"recommended"`, `POST /login` chặn trước khi tới bước chấm điểm nên kịch bản "blocklist_hit" phải gọi thẳng pipeline để kiểm phần THỰC THI); 709/709 test backend đều qua
  - ➡️ Chưa làm ở MR16 (để lại cho sau, ngoài phạm vi `[Thêm, M]`): revert thủ công một `response_action` đã thực thi nhầm (`status="reverted"` đã có cột nhưng chưa có endpoint nào ghi); khoá theo ASN/CIDR tự động (hiện chỉ khoá theo tài khoản hoặc IP, xem `lock_kind_and_value`); giao diện quản trị cho phép THÊM mục blocklist thủ công qua web (hiện chỉ xem + xoá, thêm vẫn phải qua DB/script như MR9)

## Giai đoạn F — Dashboard, tấn công mô phỏng, nghiệm thu

- [x] **MR17 [Nên, M] Dashboard v2** — Kết quả: [`dashboard-v2.md`](dashboard-v2.md); mã: [`rules.py`](../backend/app/routers/rules.py), [`model_health.py`](../backend/app/routers/model_health.py), [`users.py`](../backend/app/routers/users.py)
  - [x] Hồ sơ rủi ro theo user (timeline, alert, thiết bị/quốc gia quen): `GET /users/{id}/profile` gộp `login_events`
    (50 gần nhất), `alerts` (20 gần nhất), `known_devices`, `known_locations`, `user_risk_profiles` (MR15, ngưỡng riêng
    nếu đã đủ phản hồi) thành một trang xem nhanh — `UserProfilePage.jsx`, liên kết từ username trong bảng log và alert
  - [x] Trang chiến dịch (MR14), hiệu năng rule/ML, sức khoẻ model (drift, phiên bản): `CampaignsPage.jsx` thêm bộ lọc
    trạng thái + phân trang (backend đã hỗ trợ `?status=` từ MR14, frontend trước đó chưa dùng). `GET /model-health`
    (`ModelHealthPage.jsx`) ghép `model_registry` (MR12) + PSI drift (MR12, `ml/rba/drift.py` — trước đó chỉ chạy tay
    qua CLI) — **phát hiện hiệu năng thật**: tính PSI trên toàn bộ log thật (1.576 dòng) khiến request treo **>30
    giây**; giới hạn 300 dòng GẦN NHẤT đưa xuống còn **~2 giây** (chi tiết `docs/dashboard-v2.md`)
  - [x] Chỉnh ngưỡng và bật/tắt rule từ giao diện admin: **phát hiện quan trọng** — trước MR17, `/login` thật LUÔN
    chấm bằng MẶC ĐỊNH của sổ đăng ký luật (`build_rule_engine` không truyền `config`), `RuleConfig` (JSON, MR9-10)
    chỉ dùng cho hiệu chỉnh/replay ngoại tuyến, KHÔNG có đường nào ghi đè luồng thật. Bảng `rule_overrides` (DB, nhất
    quán với `blocklist`/`user_risk_profiles`) + `GET/PUT/DELETE /rules` (`RulesPage.jsx`) là đường ĐẦU TIÊN làm được
    việc đó — cache 15 giây cùng cơ chế `blocklist`
  - [x] Bộ lọc mở rộng (họ tấn công, rule, chiến dịch, phản hồi): `GET /alerts` thêm `attack_family`/`rule_id`/
    `campaign_id`/`status`, UI lọc trên `AlertListPanel.jsx` (tạm ngừng tự chèn alert mới qua WebSocket khi đang lọc
    — alert mới chưa chắc khớp bộ lọc đang xem); kiểm thử responsive: `RulesPage`/`ModelHealthPage`/`UserProfilePage`/
    Dashboard đều không tràn ngang ở 375px (`document.documentElement.scrollWidth === clientWidth`, kiểm trực tiếp
    trên trình duyệt thật, không chỉ đọc CSS)
  - ⚠️ **Bug thật tự phát hiện khi viết test cho MR17**: `ml/rba/drift.py::current_frame()` (từ MR12, vốn chỉ chạy
    CLI) tự mở `app.database.SessionLocal` bên trong hàm — gọi từ một router/test đã inject session RIÊNG (SQLite
    test hoặc session theo request) vẫn ÂM THẦM đọc Postgres dev THẬT thay vì session được truyền vào. Sửa bằng tham
    số `db=None` (dùng thẳng nếu có, chỉ tự mở khi không truyền — giữ nguyên hành vi CLI cũ), thêm test hồi quy chặn
    hẳn `SessionLocal` thật để không tái diễn im lặng
  - [x] 30 test mới (`rules.py`: danh sách/cập nhật/khôi phục mặc định, dây nối `build_rule_engine` giờ ĐỌC ĐƯỢC
    override; `model_health.py`: danh sách phiên bản + drift; `users.py`: hồ sơ đầy đủ/thiếu dữ liệu/giới hạn
    timeline; `alerts.py`: 4 bộ lọc mới; `current_frame()`: session được inject, `limit` giữ dòng gần nhất) — 730/730
    test backend đều qua
  - ➡️ Chưa làm ở MR17 (để lại cho sau, ngoài phạm vi `[Nên, M]`): UI thêm mục blocklist thủ công qua web (kế thừa
    giới hạn MR16); `PUT /rules/{id}` merge từng tham số với override cũ thay vì ghi đè nguyên bộ; bộ lọc theo
    khoảng thời gian trên trang chiến dịch; PSI xu hướng theo thời gian (hiện chỉ một lát cắt hiện tại)
- [x] **MR18 [Lõi, M] Thư viện tấn công mô phỏng v2 và scorecard** — Kết quả: [`attack-scenarios-v2.md`](attack-scenarios-v2.md), [`model-b-geo-time.md`](model-b-geo-time.md); mã: [`ml/attack_scenarios.py`](../backend/ml/attack_scenarios.py), [`scripts/attack_scenario_runner.py`](../backend/scripts/attack_scenario_runner.py)
  - [x] 9 kịch bản (spray chậm, botnet phân tán, proxy cùng quốc gia, UA rotation, TK ngủ đông, Targeted mimic,
    enumeration, stuffing quy mô lớn, impossible travel) — MỖI kịch bản hiệu chỉnh có chủ đích vượt HẲN ngưỡng THẬT
    của một luật cụ thể (`docs/rule-catalog.md`), dùng IP CÔNG KHAI THẬT đã xác nhận GeoIP/ASN (không phải IP bịa)
  - [x] Runner (`attack_scenario_runner.py`) chạy qua CHÍNH pipeline thật, ghi phát hiện/bước phát hiện/cơ chế/số alert
  - [x] Scorecard [`attack-scenarios-v2.md`](attack-scenarios-v2.md): 7/8 kịch bản kỳ vọng phát hiện được đã có alert
    (kịch bản thứ 9, `targeted_mimic`, cố ý khó — kết quả mơ hồ TỰ NÓ là phát hiện trung thực). **Bỏ sót thật đáng
    chú ý**: `username_enumeration` (trọng số mặc định 0,05 chưa hiệu chỉnh, không có luật tầng 1 dự phòng) không tạo
    alert nào dù vượt hẳn ngưỡng riêng. Trả lời câu hỏi để ngỏ ở `rule-catalog.md`: `rare_network_login` MỘT MÌNH
    không đủ vượt ngưỡng alert (trọng số 2,6%). `distributed_bruteforce` hiệu chỉnh trọng số **0,0** (mẫu val chỉ 2
    dòng) — kịch bản botnet chỉ được bắt "tình cờ" qua `impossible_travel` (IP chọn cách xa nhau), một botnet cùng
    khu vực địa lý nhiều khả năng lọt qua (chưa kiểm chứng trực tiếp)
  - [x] Dùng lại làm dữ liệu cho mô hình B (chuyển từ MR6): chỉ 2/9 kịch bản có tín hiệu ĐÚNG phạm vi geo/time của
    tầng 3 (`ml/features.py` không có đặc trưng IP/ASN/tốc độ) — thêm 2 kiểu bất thường mới
    (`dormant_reactivation`, `impossible_travel_geo`) vào `ml/generate_dataset.py`, huấn luyện/đánh giá lại: recall
    Isolation Forest **100%** và **63,2%** — chi tiết, kể cả giới hạn không so sánh trước/sau chính xác được (thiếu
    random seed cố định trong `generate_dataset.py`): [`model-b-geo-time.md`](model-b-geo-time.md)
  - ⚠️ **2 bug thật tự phát hiện khi dựng MR18 (không phải giả thuyết)**: (1) `app/detection/rules.py` (tầng 1,
    brute_force/credential_stuffing) đếm cửa sổ Redis theo `time.time()` THẬT thay vì timestamp SỰ KIỆN — MỌI script
    mô phỏng có timestamp không phải giờ hiện tại (MR13 trở đi) đều vô tình cho tầng 1 đếm sai tốc độ tấn công. Sửa
    bằng cách thêm tham số `now=` xuyên suốt (`register_login_failure`/`is_brute_force`/`is_credential_stuffing`),
    `pipeline.py` truyền `ensure_utc(timestamp).timestamp()`. (2) `ml/features.py::compute_realtime_features` — CÙNG
    lớp bug naive-vs-aware datetime đã gặp nhiều lần (`ensure_utc()`), lần này ở tầng 3, chỉ lộ ra khi kịch bản có
    lịch sử baseline TRƯỚC đó (không ai chạm code này với lịch sử thật trước MR18)
  - ⚠️ **Phát hiện phụ (không phải bug, đặc tính CÓ THẬT của tầng 3)**: `ml_anomaly` gần như LUÔN báo động cho tài
    khoản MỚI bất kể có tấn công hay không (mô hình toàn cục, không huấn luyện lại theo từng tài khoản) — làm giảm
    giá trị của tín hiệu này khi đọc scorecard cho tài khoản mới tạo trong mô phỏng
  - [x] 18 test mới (`ml/attack_scenarios.py`: 10 test đối chiếu trực tiếp với REGISTRY xác nhận mỗi đặc tả vượt đúng
    ngưỡng luật nhắm tới; `attack_scenario_runner.py`: 3 test phần render/tổng hợp thuần; `test_rules.py`: 4 test cho
    tham số `now=` mới; `test_ml_features.py`: 1 test hồi quy cho bug naive-datetime) — 750/750 test backend đều qua
  - ➡️ Chưa làm ở MR18 (để lại cho sau, ngoài phạm vi `[Lõi, M]`): kiểm chứng trực tiếp biến thể "botnet cùng khu
    vực địa lý"; cố định random seed cho `ml/generate_dataset.py` (cần để so sánh trước/sau chính xác); sửa
    `alert_intelligence_sim.py` (MR13) có cùng thiếu sót baseline thiếu device_fingerprint/GeoIP như bug đã sửa ở
    runner MR18; hiệu chỉnh lại trọng số `distributed_bruteforce`/`username_enumeration` (cần thêm dữ liệu val thật)
- [x] **MR19 [Lõi, M] Tài liệu và nghiệm thu** — Kết quả: [`behavior-coverage-matrix.md`](behavior-coverage-matrix.md), [`commercial-comparison.md`](commercial-comparison.md), [`reproduction-guide.md`](reproduction-guide.md), [`e2e-test-report-v2.md`](e2e-test-report-v2.md), [`soak-test.md`](soak-test.md); mã: [`scripts/soak_test.py`](../backend/scripts/soak_test.py)
  - [x] [`ml-evaluation-v2.md`](ml-evaluation-v2.md): banner CP2 GIẢI QUYẾT THẬT (không chỉ dời tiếp) — thêm dòng
    `hybrid_cp2` vào MỌI bảng lớn (ROC-AUC/recall@1%/recall@0,1%/xác thực lại, ATO có khoảng tin cậy, theo mức lịch
    sử tài khoản, chuyển ngưỡng, gán công từng thành phần), lấy thẳng từ artifact đã sinh
    (`ml/artifacts/rba_reports/hybrid_cp2.md`) và chạy lại `ml.rba.analysis hybrid_cp2` — không suy diễn số nào.
    Model card + data card: kiểm tra lại toàn bộ, data card ĐÃ đúng không cần sửa; model card có **2 chỗ sai thật**
    (mục dưới). Ma trận phủ hành vi mới: 27 hành vi × 4 tầng phát hiện, liệt kê 7 khoảng trống đã biết trong một chỗ
  - [x] [`commercial-comparison.md`](commercial-comparison.md): so 11 khả năng với Okta/Microsoft Entra ID
    Protection/Auth0 (tài liệu công khai, có nguồn dẫn — không đo được recall/FPR thật của họ, chỉ so "có/không có
    tính năng"); so với baseline học thuật Freeman et al. 2016 đo TRỰC TIẾP trên cùng bộ RBA (không phải đọc tài
    liệu): `hybrid_cp2` hơn rõ ở ATO thật (36,8% so với 15,8%) và IP tấn công (12,4% so với 0,3%), ngang nhau ở kẻ
    tấn công mô phỏng Naive/VPN, cả hai đều yếu ở Targeted — xác nhận giới hạn là của CÁCH TIẾP CẬN, không phải một
    mô hình cụ thể
  - [x] README (mục mới tóm tắt MR1-19, không viết đè lịch sử Tuần 1-7), `getting-started.md` (nạp `hybrid_cp2`,
    admin pages mới, attack scenario runner v2, các sim script MR13-16), `reproduction-guide.md` mới (9 giai đoạn
    theo đúng thứ tự phụ thuộc, gom lệnh từ 10 tài liệu rời rạc). `api-contract.md`/`db-schema.md`: đối chiếu từng
    route/bảng với mã nguồn thật — **cả hai đã đúng 100%, không cần sửa** (mọi endpoint/bảng MR9-18 đã được cập nhật
    kịp thời qua từng MR, khác với model card)
  - [x] Regression: **756/756** test backend qua (750 kế thừa + 6 mới cho `soak_test.py`). E2E:
    [`e2e-test-report-v2.md`](e2e-test-report-v2.md), 10 kịch bản qua trình duyệt thật (không phải `TestClient`) —
    khoá tự động → dashboard → admin mở khoá → đăng nhập lại, cả 4 trang quản trị mới, giải thích cảnh báo, phản hồi
    — toàn bộ pass, không lỗi backend. Performance: đo lại `benchmark_login.py`, **chậm đi rõ rệt** so với Tuần 5
    (median 614ms so với 260ms tuần tự; 3 request đồng thời → median 1062ms, `--concurrency 10` timeout thật) — xem
    mục dưới. Soak test MỚI (chưa từng có trong dự án): script [`soak_test.py`](../backend/scripts/soak_test.py),
    12 phút tải nhẹ (1 req/s, luân phiên 30 tài khoản), **760 mẫu, chỉ 1 lỗi kết nối (0,14%), không khoá nhầm, độ trễ
    dao động quanh mức nền chứ không tăng dần đơn điệu — hệ thống ổn định dưới tải thấp, dù chậm**
  - ⚠️ **2 lỗi thật tự phát hiện ở `model-card-rba.md` khi đối chiếu với mã nguồn (tài liệu viết ở CP2/MR8b, chưa
    từng cập nhật lại dù MR12/MR16 đổi đúng những gì nó mô tả)**: (1) mục "Trạng thái" vẫn ghi "dùng offline để đánh
    giá; chưa nối vào luồng `/login`" — SAI từ MR12, `hybrid_cp2` đã chạy live thật (xác nhận trực tiếp qua
    `/dashboard/model-health` ở E2E: `feature_signature` khớp, `is_active=true`). (2) mục "Không dùng để" ghi "không
    tự động khoá tài khoản mà không có bước xác thực lại" — bị MR16 GHI ĐÈ có chủ đích (điểm hybrid vượt `lock_at`
    hoặc `blocklist_hit` → khoá tạm ngay, không chờ xác thực thêm ở lần đó); tài liệu chưa từng ghi nhận thay đổi
    này. Cả hai đã sửa, kèm lý do đánh đổi (khoá **có hạn, admin mở khoá được** — không phải khoá vĩnh viễn)
  - ⚠️ **Nguyên nhân hiệu năng chậm đi xác nhận qua đọc mã nguồn** (`app/detection/rba_live_features.py`):
    `_user_events()` lấy TOÀN BỘ lịch sử tài khoản không giới hạn dòng (tài khoản benchmark `alice` đã có 1.422 dòng
    sau 8 tuần bị dùng lại liên tục — độ trễ không có trần theo số lần đăng nhập của MỘT tài khoản); truy vấn đếm
    toàn cục (`GlobalCountsCache`) quét TOÀN BẢNG mỗi 30 giây hết cache, KHÔNG có khoá chống nhiều request cùng lúc
    cùng làm mới (thundering herd) — khớp với việc độ trễ tệ đi không tuyến tính khi có tải đồng thời. Kiến trúc
    async (`asyncio.to_thread` từ MR12) đúng đắn, KHÔNG chặn event loop — chậm là chi phí DB/CPU thật, không phải
    lỗi async. Chi tiết đầy đủ, khuyến nghị chưa làm: [`performance.md`](performance.md)
  - ⚠️ **Phát hiện phụ ở Model Health (không phải bug)**: PSI drift so sánh train RBA (1,1 triệu dòng) với log demo
    của chính dự án (300 dòng) — hai quần thể khác bản chất nên PSI luôn cực lớn (8-10, ngưỡng "đáng kể" chuẩn chỉ
    0,25) bất kể mô hình có cũ hay không; tính đúng công thức nhưng số không mang tính hành động trong bối cảnh này
  - ➡️ Chưa làm ở MR19 (ngoài phạm vi, để lại cho sau): sửa 2 nguyên nhân hiệu năng vừa tìm được (giới hạn
    `_user_events`, khoá cho `GlobalCountsCache`); đổi "hiện tại" của model-health drift sang nguồn cùng bản chất
    với train; viết lại `scripts/create_admin.py` để không crash cosmetic khi thiếu `PYTHONIOENCODING` (đã có sẵn
    ở nhiều script khác, không mới nhưng lần đầu thấy nó có thể che giấu thao tác ĐÃ thành công); mọi mục "Bổ sung
    tuỳ chọn" (MR-S1-S4) bên dưới — không được duyệt trong kế hoạch MR1-19

## Bổ sung tuỳ chọn (làm sau CP2 nếu còn thời gian)

- [ ] **MR-S1** Nhật ký truy cập sau đăng nhập và phát hiện IDOR/enumeration (module riêng, dữ liệu mô phỏng, ghi rõ ngoài phạm vi "đăng nhập")
- [ ] **MR-S2** Mô hình chuỗi (GRU) hoặc đồ thị — chỉ làm nếu MR6 cho thấy còn dư địa
- [ ] **MR-S3** Trợ lý điều tra dùng LLM tóm tắt chiến dịch từ bằng chứng có cấu trúc (cần API key, có chế độ tắt, không thay giải thích tất định)
- [ ] **MR-S4** Clustering tìm "mẫu lạ mới" tự động

# Giai đoạn hoàn thiện — hợp nhất kiến trúc, độ tin cậy, chuẩn bị bảo vệ (MR20–MR39)

> **Kế hoạch đã được chủ dự án duyệt ngày 01/10/2026.** Bối cảnh: còn khoảng 6 tuần tới bảo vệ (≈ 12/11/2026), đề cương chưa nộp,
> mục tiêu "hoàn chỉnh, ít bị bắt bẻ, điểm cao", **được phép phá kiến trúc cũ** (khác MR1–MR19: xây mới song song, không
> đụng cái cũ).

**Nguyên tắc**
- Việc rủi ro (đụng lõi) làm trước, tuần 1–2. Đóng băng code cuối tuần 5. Tuần 6 chỉ báo cáo, slide, luyện bảo vệ.
- Mọi con số trình bày phải có phép đo kèm báo nhầm. Không nâng số phát hiện bằng cách hạ ngưỡng hay nâng trọng số bằng tay.
- Mỗi giai đoạn làm trên nhánh riêng, gộp vào `main` ở điểm kiểm soát. Mỗi task một commit (không ghi tên công cụ AI), không
  push khi chưa được yêu cầu.
- Điểm kiểm soát CP4/CP5/CP6: dừng, báo số đo thật, chờ duyệt. **Đường lùi:** nếu CP4 cho thấy mất hành vi vững mà không gỡ
  được trong tuần 2, quay về kiến trúc hiện tại và chỉ làm "phương án giữa" (gộp cảnh báo, một điểm hiển thị, sửa hiệu năng).
- Tuần 1–2 có thể trượt sang đầu tuần 3; MR30 và MR31 là phần đệm, cắt được nếu thiếu thời gian.

**Chỉ số mục tiêu** (đo lại ở CP6)

| Chỉ số | Hiện tại | Mục tiêu |
|---|---|---|
| Hành vi vững / tổng | 10/25 | ≥ 20/28 |
| Cảnh báo sinh ra cho 1 cuộc tấn công (E2E `user020`) | 4 | 1 |
| Điểm rủi ro hiển thị cho 1 lần đăng nhập | 3 (tầng 2, tầng 3, hybrid) | 1 |
| Độ trễ đăng nhập tuần tự (median) | 614 ms | ≤ 350 ms (bcrypt chiếm ~230 ms) |
| 10 request đồng thời | timeout | không timeout, p95 ghi rõ |
| Báo nhầm trên lưu lượng hợp lệ "khó" | chưa đo | ≤ 1% đăng nhập hợp lệ, đo theo từng luật |
| Đăng nhập hợp lệ từ IP Việt Nam bị báo (MR13) | có | không |
| Kiểm chứng trên log thật | không (RBA là dữ liệu tổng hợp) | có (LANL) |

**Câu hỏi hội đồng dễ gặp → task giải quyết**

| Có thể bị hỏi | Ở đâu |
|---|---|
| "Sao có 5 cơ chế phát hiện chồng nhau, 3 điểm rủi ro, tin cái nào?" | MR21–MR23 |
| "Một cuộc tấn công mà ra 4 cảnh báo?" | MR23 |
| "Đăng nhập sao chậm, tải cao thì sao?" | MR20 |
| "Nhiều luật trọng số 0–5% thì có tác dụng gì?" | MR24–MR25 |
| "Đăng nhập bình thường mà cũng bị báo?" (lúc demo) | MR26 |
| "Chỉ bắt được 10 hành vi?" | MR27–MR30 |
| "Dữ liệu tổng hợp, có dữ liệu thật không?" | MR31 |
| "Hệ thống phát hiện đăng nhập bất thường mà trang admin không được bảo vệ?" | MR32 |
| "Lưu IP, thiết bị, vị trí người dùng có vi phạm dữ liệu cá nhân không?" | MR32 |
| "Code có tự viết không, giải thích phần X?" | H1–H5, MR39 |
| "Demo lỗi thì sao?" | MR36 |

## Giai đoạn G — Hợp nhất kiến trúc (tuần 1 – đầu tuần 2)

- [x] **MR20 [Lõi, M] Ngữ cảnh đăng nhập dùng chung + sửa hiệu năng** (tuần 1) — chi tiết và số đo:
  [`performance.md`](performance.md) mục "MR20"
  - [x] `LoginContext` ([`login_context.py`](../backend/app/detection/login_context.py)) dựng MỘT lần cho mỗi lần đăng nhập:
    lịch sử tài khoản, thống kê IP/ASN 24h, đếm toàn cục, lần thử đã chuẩn hoá cho luật và cho đặc trưng (GeoIP, ASN, phân
    tích UA tra một lần trước khi ghi `LoginEvent`, ngữ cảnh đọc lại từ dòng đó). Thay `DbAccountHistory` và `_user_events`
    (rule engine, đặc trưng RBA, novelty MR13 đọc chung). ⚠️ **Chưa thay baseline tầng 2** (vẫn đọc mọi lần thành công để
    tính giờ trung bình, ~21 ms với `alice`): tầng 2 bị thay bằng luật v2 ở MR21, tối ưu nó lúc này là làm hai lần
  - [x] Đặc trưng `u_*` (và cả `ip_*`/`asn_*`) do **DB tự đếm** (`count ... FILTER`, `GROUP BY` theo 7 thuộc tính), Python chỉ
    nhận vài con số — số dòng chuyển sang Python không còn phụ thuộc độ dài lịch sử hay lượng tấn công dồn dập từ một IP.
    Khác kế hoạch: KHÔNG lưu bảng "hồ sơ cập nhật dần" riêng — truy vấn gộp qua chỉ mục đã đủ nhanh (lịch sử tài khoản ~2–5
    ms) và tránh rủi ro hồ sơ lệch với log; đặc tả `ml/rba/features.py` đổi sang dạng tổng hợp (`UserHistory`, `InfraStats`)
  - [x] Gộp `GlobalCountsCache` và `DbGlobalStats` thành một bộ đếm có khoá (một request tính lại, request khác chờ dùng
    chung); DB gom nhóm sẵn nên mỗi lần tính lại ~4–16 ms thay vì ~67 ms. Sửa kèm: bộ cũ của luật nhà mạng hiếm dựng mới
    mỗi lần chấm (quét toàn bảng ở MỌI lần đăng nhập có ASN) và đếm cả chính lần thử đang chấm
  - [x] `scripts/benchmark_login.py`: tài khoản mới mỗi lần chạy (`--username/--password` để đo tài khoản có sẵn), gọi
    `127.0.0.1`, UA trình duyệt thật, `--ip`, đếm kết quả từng loại (thành công/OTP/bị khoá)
  - [x] Ngoài danh sách, tìm ra khi profiling: tương quan chiến dịch nạp toàn bộ bảng `alerts` mỗi lần có cảnh báo (~140 ms,
    nguyên nhân lớn nhất) → lọc trong SQL; mô hình `hybrid_cp2` chạy 2 lần/lần đăng nhập → 1 lần; Isolation Forest chấm 1
    dòng chậm → bộ chấm nhanh chỉ dùng khi trùng từng bit với sklearn ([`fast_iforest.py`](../backend/ml/fast_iforest.py));
    **bcrypt chạy thẳng trong hàm `async` `/login` chặn vòng lặp sự kiện** (lý do chính khiến request đồng thời xếp hàng)
    → threadpool; sau đó lộ ra **2 lỗi tranh chấp thật** (10 lần đăng nhập đầu tiên đồng thời của tài khoản mới: 9/10 lỗi
    500 do trùng khoá `user_baseline`; cùng lớp lỗi ở mục khoá tự động MR16) → SAVEPOINT + đọc lại. Phép đo MR19 cũng lẫn
    nhiễu của máy đo: "localhost" trên Windows mất ~2 s mỗi kết nối mới (thử IPv6 trước)
  - **Kết quả** (HTTP thật, so cùng điều kiện với bản trước MR20): tuần tự tài khoản mới median **319 ms** (trước 395),
    IP Việt Nam **323 ms** (trước 395), `alice` 349 ms (trước 689); **10 request đồng thời không timeout** — tài khoản mới
    median 542 ms / **p95 855 ms** (trước 2.659 / 4.992 ms), `alice` median 839 ms / p95 2.888 ms / max 4.235 ms (trước
    5.312 / 6.553 / 6.780 ms). Trong tiến trình: pipeline tài khoản mới 356 → 79 ms, `alice` 394 → 104 ms
  - **Đặc trưng không đổi**: 41 test tương đương MR3 (đặc tả vs DuckDB) vẫn qua; test mới `test_login_context.py` so 50 đặc
    trưng + lịch sử luật + novelty với mã cũ trên dữ liệu ngẫu nhiên — bằng tuyệt đối; trên Postgres thật 50/50 lần đăng
    nhập tính lại bằng mã cũ và mới cho đặc trưng và xác suất ML giống hệt. Regression: **780/780** test backend qua (có
    test mới cho bộ chấm Isolation Forest, bcrypt ngoài vòng lặp sự kiện, tranh chấp tạo baseline)
  - ⚠️ Còn lại, chuyển cho task sau: đuôi dài khi nhiều request đồng thời vào CÙNG một tài khoản lịch sử dài (`alice` p95
    ~2,2–2,9 s; không do khoá DB — đo 0 lần chờ khoá; nghi GIL, chưa xác minh); lỗi DB trong các khối "cô lập" của pipeline
    làm hỏng cả giao dịch (→ MR23, mỗi khối một SAVEPOINT); **`/login` không chạy bcrypt khi tên không tồn tại → thời gian
    phản hồi lộ tài khoản có thật** (→ MR32); tài khoản mới đăng nhập dồn dập bằng trình duyệt hiếm bị đòi OTP 22/50 lần
    trong một lượt đo (→ MR26, báo nhầm)
- [x] **MR21 [Lõi, L] Một bộ luật duy nhất: gộp tầng 1 + tầng 2 vào rule engine v2, thêm "mức hành động tối thiểu"** (tuần 1)
  — chi tiết và số đo: [`rule-unification.md`](rule-unification.md)
  - [x] `RuleSpec.min_action` (+ kiểm hợp lệ khi khai báo, hiện ở `GET /rules`, trang "Cấu hình luật" và danh mục luật tự
    sinh). Khớp ở chế độ enforce → hành động ít nhất là mức đó; XÁC SUẤT của bằng chứng không đổi, chỉ điểm hiển thị được nâng
    lên ngưỡng của hành động (không có cảnh báo "điểm 10 nhưng bị khoá"). Thay hẳn cơ chế ghi đè riêng của `blocklist_hit`
    (bỏ `override_rule_ids` khỏi hồ sơ hybrid; hồ sơ cũ vẫn nạp được). Mức tạm thời đúng kế hoạch: `brute_force`,
    `credential_stuffing`, `impossible_travel` → alert; `success_after_failures` → step_up; `blocklist_hit` → lock (chốt ở MR25)
  - [x] Thành phần tầng 2: "chuỗi sai +40" → luật `brute_force` (cùng điều kiện); "thành công sau chuỗi sai +50" → luật
    `success_after_failures` (ngưỡng có sẵn 5 lần/10 phút, chặt hơn mức 3 lần của tầng 2); "lệch giờ +20", "vị trí lạ +30" →
    đặc trưng ML tương ứng (tầng 3 `hour_deviation_from_avg`/`is_new_location`, `hybrid_cp2` `new_country`). Bảng cộng điểm
    chỉ còn là phương pháp đối chứng của phép so sánh Tuần 7 (`ml/tier2_baseline.py`, để số trong ml-evaluation.md vẫn tái lập
    được). Điểm rủi ro duy nhất của lần đăng nhập (điểm hybrid) ghi cả vào `login_events.risk_score` và vào cảnh báo `ml_anomaly`
  - [x] Xoá `app/detection/rules.py` (`haversine_distance` → `app/utils/geo.py`), `scoring.py`, toàn bộ bộ đếm tầng 1 của
    `rate_counter.py` (chỉ còn kết nối Redis dùng chung). **Giữ** `scripts/backfill_baseline.py` và `baseline.py`: tầng 3 vẫn
    cần `UserBaseline`/thiết bị/vị trí quen (tới MR22). Xoá `test_rules.py`, `test_scoring.py`, `test_rate_counter.py`; giữ
    `test_baseline.py` (mã còn dùng). Test thay thế: `test_pipeline_mr21.py` (8 test qua pipeline thật, hồ sơ không ML để
    hành động chỉ đến từ luật), test cơ chế `min_action` ở `test_hybrid_combine.py`/`test_rule_engine_registry.py`,
    `test_geo.py`, `test_tier2_baseline.py`
  - [x] Sửa docstring sai ở `hybrid/combine.py` và `registry.py`; định nghĩa lại: `enforce` = bằng chứng có trọng số + được ép
    hành động tối thiểu; `shadow` = vẫn là bằng chứng có trọng số nhưng không bao giờ tự ép hành động; `off` = không chạy.
    Chọn định nghĩa này (không phải "shadow không góp điểm") để giữ nguyên công thức hiệu chỉnh MR11 và các số đã công bố
  - [x] Frontend tối thiểu để không vỡ giữa chừng: bản đồ vẽ đường bay từ toạ độ đi kèm cảnh báo hybrid (luật
    `impossible_travel`), trang luật hiện hành động tối thiểu. Phần thống nhất giao diện còn lại thuộc MR23
  - **Kết quả đo** (17 kịch bản qua pipeline thật, trước/sau): **không kịch bản nào mất phát hiện hay phát hiện muộn hơn**;
    3 kịch bản trước đây chỉ có alert tầng 1 trong khi hybrid nói "cho qua" giờ có hành động `alert` thật (botnet phân tán,
    xoay UA, nhịp đều); E2E TC1 vẫn `step_up`; cảnh báo không tính `ml_anomaly`: 44 → 15. Vẫn **10/25** hành vi vững (đổi cơ
    chế, không mất). Khoảng trống đã biết (dò danh sách, bot UA, Tor/datacenter/VPN...) vẫn còn — MR25, MR27–MR30
  - ⚠️ Đánh đổi ghi nhận: không còn đường dự phòng tầng 1 khi khối hybrid lỗi (một đường duy nhất); tổ hợp "lệch giờ + vị trí
    lạ" của tầng 2 không còn cảnh báo riêng (vẫn do tầng 3 chấm); điểm hiển thị của `blocklist_hit` từ 100 thành `lock_at`
- [x] **MR22 [Lõi, M] Một lớp ML: mô hình địa lý-thời gian (tầng 3) thành nguồn bằng chứng của hybrid** (tuần 1)
  — chi tiết và số đo: [`geo-model-integration.md`](geo-model-integration.md)
  - [x] Điểm Isolation Forest tầng 3 → xác suất → nguồn `ml_geo` của hybrid, cạnh `hybrid_cp2`. Đường logistic: độ dốc học trên
    điểm ngoài mẫu (5-fold) của tập train đã qua cổng (48,22), mốc neo ở ngưỡng của chính mô hình = ngưỡng `alert`, trần 0,382
    (một mình chỉ cảnh báo; thêm một tín hiệu độc lập đáng cảnh báo mới thành `step_up`). Không dùng thẳng isotonic: dữ liệu tự
    sinh thổi phồng xác suất (báo nhầm 4,8% ở ngưỡng alert, 47,6% ca bất thường lên 1,0). **Hai mô hình gộp bằng max**, không
    noisy-OR (dùng chung tín hiệu thiết bị/vị trí mới; bản đầu dùng noisy-OR + trần 0,57 thì "đổi điện thoại + đi công tác" bị
    KHOÁ, và bằng chứng dưới ngưỡng chồng lên nền ~0,29 của `hybrid_cp2` với IP Việt Nam đẩy báo nhầm từ 1,6% lên 8,0%).
    Không còn alert `ml_anomaly`; nhãn của nguồn mang các đặc trưng lệch nhất (`ml_model.explain`)
  - [x] Cổng cold-start N = 5 lần thành công trước đó, chọn bằng số đo: đăng nhập bình thường bị gắn cờ 100% (0 lần), 24,2% (1),
    2,4% (5–9), < 1% (≥ 10). Cái giá: 28/304 ca bất thường (9,2%) trong vùng đó không còn được tầng 3 chấm — ở đó độ chính xác
    của cờ chỉ 26,5% (qua cổng 93,7%)
  - [x] Cố định random seed **và** mốc thời gian của `ml/generate_dataset.py`; dữ liệu sinh lại (1.815 lần đăng nhập, 304 bất
    thường) tái lập đúng; số trong `ml-evaluation.md`/`model-b-geo-time.md` cập nhật theo bộ này
  - **Kết quả**: trên tập test, quyết định của `ml_geo` trùng hoàn toàn ngưỡng mô hình mà `ml_anomaly` dùng — recall **70,6%**,
    báo nhầm **1,6%**, `dormant_reactivation` 100%, `impossible_travel_geo` 66,7% (giữ nguyên). 20 kịch bản qua pipeline thật
    (commit MR21 vs MR22, cùng mô hình, cùng bộ chạy): không kịch bản nào mất/muộn phát hiện; **tài khoản mới hợp lệ không còn
    bị báo**; cảnh báo 74 → 44 hàng; rải mật khẩu chậm và proxy cùng nước từ "chỉ `ml_anomaly`, hybrid cho qua" thành `alert`;
    nhồi thông tin `alert` → `step_up`; không kịch bản nào lên `lock` vì tầng 3. **804/804** test
  - ⚠️ Tìm ra khi đo: bộ chạy kịch bản (`_insert_baseline`, dùng chung MR18/MR21) dựng lịch sử nền không ghi
    `known_devices`/`known_locations`/`user_baseline` → tầng 3 thấy mọi tài khoản kịch bản là "lạ" (caveat "`ml_anomaly` gần như
    luôn kêu" một phần do lỗi này; phần luật/hybrid đo lại giống hệt) — đã sửa, cùng lỗi trong test MR13; khối khoá tự động MR16
    so `expires_at` không múi giờ (SQLite) → `TypeError` — đã sửa
  - ⚠️ Còn lại: ngày đầu của kịch bản "đăng nhập theo thói quen" vẫn bị `hybrid_cp2` cảnh báo (0,50, có từ trước MR22 → MR26);
    tầng 3 vẫn chấm cả lần thử sai như trước dù chỉ học trên lần thành công (chưa đo riêng); phép đối chứng có/không 2 kiểu MR18
    trên cùng seed giờ làm được nhưng chưa chạy
  - Xong khi: recall các kiểu địa lý-thời gian giữ nguyên hoặc ghi rõ thay đổi; kịch bản tài khoản mới hợp lệ không bị báo
- [x] **MR23 [Lõi, M] Một sự cố = một cảnh báo, một điểm rủi ro** (đầu tuần 2) — chi tiết và số đo:
  [`incident-unification.md`](incident-unification.md)
  - [x] Viết lại `pipeline.py` theo 5 bước (ghi lần thử + ngữ cảnh → luật → mô hình → gộp điểm → sự cố/phản ứng/chiến dịch),
    mỗi khối một SAVEPOINT (nợ từ MR20: lỗi DB trong khối "cô lập" làm hỏng cả giao dịch Postgres); hồ sơ tài khoản cập nhật
    sau khi chấm. Chống trùng lặp thành **sự cố** (`alert_intelligence.Incident`): cùng tài khoản (hoặc IP nếu tên không tồn
    tại), không còn theo họ tấn công, cửa sổ 15 phút **trượt** và chặn hai phía; cảnh báo giữ đỉnh điểm, hành động nặng nhất,
    hợp mọi bằng chứng + chi tiết từng luật; họ và `rule_id` theo lần thử quyết định (luật đã ép hành động được ưu tiên)
  - [x] Migration `7d2c1e5a9b30`: xoá `login_events.risk_score`, `ml_anomaly_score`, `alerts.alert_type` (loại cũ giữ trong
    `explanation.legacy_alert_type`, 2.239 cảnh báo dev); chỉ mục sự cố mới. Chạy trên Postgres dev sau khi sao lưu, kiểm hai
    chiều: hạ cấp xong bảng `alerts` trùng từng byte với bản sao lưu. Bằng chứng di chuyển bất khả thi lưu cả hai đầu đường bay
  - [x] Frontend: bảng log/biểu đồ một điểm, biểu đồ kẻ đúng ngưỡng hành động từ API (`action_bands`), lọc theo hành động;
    danh sách cảnh báo hiện họ tấn công, hành động, số lần thử và toàn bộ bằng chứng, cập nhật real-time thay đúng hàng của sự
    cố; bản đồ đọc đường bay từ bằng chứng đã lưu (vẽ lại được sau khi tải lại trang). Kiểm tra trên trình duyệt với bản sao
    DB tạm (đã xoá)
  - [x] Sửa 23 test pipeline MR12–MR15 + test router/feedback theo luồng mới; thêm `test_pipeline_mr23.py` và test `Incident`
  - **Kết quả**: E2E TC1 = **1** cảnh báo liệt kê đủ bằng chứng (`success_after_failures`, step_up) — kiểm qua pipeline thật
    trên DB cô lập (kịch bản `tc1_like` dùng chính `user020`) và test; E2E trình duyệt với `user020` trên DB dev vẫn để MR34
    (tránh tự khoá tài khoản demo); 20 kịch bản: bước phát
    hiện và hành động nặng nhất **giống hệt** MR22, cảnh báo 44 → 40 (mọi tấn công vào một tài khoản = 1 cảnh báo); hành vi
    vững vẫn 10/25; độ trễ pipeline không đổi đo được (chênh 0–15 ms trong biên dao động giữa hai lượt đo)
  - ⚠️ Lỗi thật tìm ra (đã sửa, có test): (1) đặc trưng `minutes_since_last_login` của mọi lần đăng nhập thành công trên luồng
    thật = 0 từ Tuần 7 (lệch train/serve; test so khớp đặc trưng thật với lúc train); (2) tên họ tấn công của MR22 dài 67 ký
    tự > cột 64 — Postgres từ chối ghi cảnh báo, lần đăng nhập thành công trả 500 (SQLite trong test không kiểm độ dài); (3)
    cửa sổ sự cố thiếu chặn trên; (4) họ tấn công và `rule_id` có thể mâu thuẫn (từ MR21); (5) một test MR23 gọi
    `monkeypatch.undo()` đã ghi vào DB/Redis dev thật — đã khôi phục từ bản sao lưu, thêm lưới an toàn chặn mọi test chạm dịch
    vụ dev (lộ thêm `test_health` gọi Postgres dev từ Tuần 1)
  - ⚠️ Còn lại: hai lần thử đồng thời của một sự cố mới có thể tạo hai cảnh báo (không khoá hàng); cửa sổ 15 phút vẫn tự chọn;
    chưa có kịch bản đo riêng ảnh hưởng của lỗi (1) lên tài khoản "im lặng lâu ngày"
  - Xong khi: tấn công `user020` (E2E TC1) ra đúng 1 cảnh báo, liệt kê đủ bằng chứng; bản đồ vẫn vẽ đường bay; toàn bộ test và
    kịch bản qua
- [ ] **CP4 — sau MR23**: báo độ trễ, số cảnh báo/sự cố, số hành vi vững trước/sau; chủ dự án duyệt rồi mới hiệu chỉnh
  - Đã báo (03/10/2026, số đo ở [`incident-unification.md`](incident-unification.md) mục 4) — chờ chủ dự án duyệt

## Giai đoạn H — Hiệu chỉnh và độ tin cậy (tuần 2 – tuần 3)

- [x] **MR24 [Lõi, L] Bộ dữ liệu hiệu chỉnh có nhãn** (tuần 2) — data card: [`calibration-corpus.md`](calibration-corpus.md)
  - [x] 15 họ tấn công, mỗi họ biến thể ngẫu nhiên có seed (nạn nhân, IP, nhịp, số bước, giờ quen, thiết bị); IP thật: 13 kho
    × 30 IP lấy mẫu trong dải nhà mạng và CHỈ giữ IP mà GeoLite2 xác nhận đúng quốc gia + ASN, cộng danh sách Tor/datacenter/VPN
  - [x] 10 họ hợp lệ "khó": thói quen, tài khoản mới, gõ sai, quên mật khẩu, VPN, văn phòng NAT, đi công tác (tốc độ bay hợp
    lý, có test), thiết bị mới, đổi wifi/4G nhiều nhà mạng Việt Nam, đăng nhập đêm
  - [x] Bộ hiệu chỉnh seed 0–29 / bộ đánh giá seed 1000–1029, không giao nhau; nhãn từng lần thử; chạy qua pipeline thật (DB
    SQLite + fakeredis riêng mỗi biến thể), ghi bằng chứng thô (luật, xác suất hai mô hình) để MR25/26 tính lại không cần chạy
    lại (`python -m ml.corpus.run`, ~3 phút cho 1.500 biến thể)
  - **Số đo nền** (cấu hình sau MR23): lần thử hợp lệ bị cảnh báo **31,4% / 33,5%** (hiệu chỉnh / đánh giá); AUC `hybrid_cp2`
    **0,23** (nghịch lý Simpson, đính chính ở MR26: tách thành công/thất bại thì 0,88/0,94), `ml_geo` 0,93, điểm cuối 0,65. Tỉ lệ phát hiện tấn công (đa số
    100%, kể cả "mô phỏng tinh vi") chưa có ý nghĩa khi nền báo nhầm cao như vậy — việc của MR25–MR26
  - Xong khi: ≥ 30 biến thể mỗi họ; data card riêng ghi rõ dữ liệu tự sinh và giới hạn
- [x] **MR25 [Lõi, M] Hiệu chỉnh lại trọng số luật và mức tối thiểu** (tuần 2) — chi tiết và số đo:
  [`rule-recalibration.md`](rule-recalibration.md)
  - [x] Trọng số trên bộ MR24 cho 9/10 luật RBA không đo được và 3/4 luật ra 0% (`blocklist_hit` không có mẫu,
    `multi_context_simultaneous` < 20 lần khớp — giữ nguyên); giữ trọng số RBA cho 5 luật đo hợp lệ trên RBA; mọi trọng số ghi
    `source` + khoảng tin cậy. Đo bằng tỉ số khả năng quy về tỉ lệ tấn công của RBA (π = 6,32%), bootstrap theo biến thể; hai
    trần theo ngưỡng hành động: luật đo trên bộ tự dựng một mình chỉ đủ `alert` (≤ 0,57), VPN/datacenter một mình không cảnh
    báo (≤ 0,31). Nhóm danh tiếng gộp bằng max (cùng một IP). Phát lại ngoại tuyến khớp hành động thật 4.738/4.756 lần thử
    (18 khác đều do đổi max, 0 không giải thích được)
  - [x] Chốt `min_action`: giữ cả năm mức của MR21. `credential_stuffing`, `impossible_travel`: 0 lần thử hợp lệ bị ép;
    `success_after_failures` (step_up) và `brute_force` (alert): 1,5% / 1,85% — toàn bộ là "quên mật khẩu", số lần sai một
    mình không phân biệt được với dò mật khẩu ngắn (bỏ mức ép của `brute_force`: "nhập sai 5 lần" không còn cảnh báo nào)
  - **Kết quả** (bộ đánh giá): phát hiện trung bình 15 họ tấn công 89,3% → 95,1% (chỉ luật 58,4% → 71,8%); lần thử hợp lệ bị
    cảnh báo không đổi: chỉ luật 3,4%, mọi nguồn 33,5%. 20 kịch bản: thêm 4 kịch bản bị bắt (dò danh sách tài khoản, bot UA,
    Tor, nhảy quốc gia), 3 kịch bản hợp lệ không đổi, cảnh báo 40 → 44
  - ⚠️ **Chưa đạt ≤ 1%**: lớp luật 3,4% (ca "quên mật khẩu", cố ý); mọi nguồn 33,5% do `hybrid_cp2` → MR26. Người dùng VPN hợp
    lệ bị xác thực thêm/khoá 29 → 44/61 lần thử (trọng số datacenter cộng lên nền 0,45–0,67 của `hybrid_cp2`) — đo lại sau
    MR26. Ứng viên MR27–MR30: phân biệt "quên mật khẩu" bằng máy/vị trí quen (kiểu smart lockout)
  - Xong khi: báo nhầm trên bộ đánh giá ≤ 1% đăng nhập hợp lệ; bảng trước/sau cho từng luật
- [x] **MR26 [Lõi, M] Hiệu chỉnh cho người dùng Việt Nam + sức khoẻ mô hình có ý nghĩa** (tuần 3) — chi tiết và số đo:
  [`vn-recalibration.md`](vn-recalibration.md)
  - [x] Chẩn đoán: "AUC 0,23" của MR24 là nghịch lý Simpson (tách thành công/thất bại: 0,88/0,94); lỗi thật là lệch miền của lần
    THÀNH CÔNG — người dùng hợp lệ Việt Nam cao hơn RBA ~1,6–1,9 đơn vị log10 ở mọi phân vị. Sửa bằng độ lệch miền
    `MlDomainShift` (không train lại, ánh xạ RBA giữ nguyên): Δ = Q99 Việt Nam − Q99 RBA = **1,78** (KTC 1,61–1,97), chỉ dùng lưu
    lượng hợp lệ; Δ thất bại = 0. Phương án fit thẳng trên nhãn MR24 bị loại (ATO trên RBA 31,6% → 0%)
  - [x] PSI cửa sổ đầu so với gần nhất của chính hệ thống (đặc trưng + điểm mô hình); "khoảng cách RBA → hệ thống" tách riêng
    kèm Δ đang dùng và Δ ước lượng từ log thật (DB dev: 1,93)
  - [x] Đính chính MR25: tỉ lệ quy đổi π = 8,40% (không phải 6,32% — sai khung dữ liệu); 10 trọng số bị trần không đổi
  - **Kết quả** (bộ đánh giá): hợp lệ bị cảnh báo 33,5% → **19,3%**, bị OTP/khoá 6,0% → **1,7%**, riêng `hybrid_cp2` 24% →
    0,15%; phát hiện 95,1% → 94,7%. RBA: số MR11 tái tạo đúng, ATO không đổi. `benign_control` không bị báo (sau khi sửa hai lỗi
    của chính kịch bản — lịch sử thiếu sổ sách, "thói quen" dồn 10 lần trong 10 giờ); kịch bản "theo thói quen" hết bị báo
  - ⚠️ Còn lại 19,3% chủ yếu là cảnh báo (không cản) của `ml_geo` ở các họ khác thường nhưng hợp lệ — phương án hạ `ml_geo` đã
    đo (7,9% báo nhầm nhưng mất 100% "mô phỏng tinh vi"), chờ quyết định ở CP5
  - Xong khi: kịch bản đối chứng IP Việt Nam (MR13 `benign_control`) không bị báo; số đo ATO trên RBA không đổi; trang Model
    Health hiện số đọc được
- [ ] **CP5 — sau MR26** (đã báo, chờ duyệt — [`vn-recalibration.md`](vn-recalibration.md) mục 6): hành vi vững 10 → **18**/25;
  báo nhầm theo từng luật (chỉ `brute_force` 25, `success_after_failures` 20 lần thử hợp lệ tự ép hành động; VPN/datacenter khớp
  nhưng một mình không cảnh báo); độ trễ trung vị 83–104 ms (CP4: 103–120 ms)

## Giai đoạn I — Mở rộng hành vi (tuần 3 – tuần 4)

Một hành vi chỉ được tính "vững" khi: kịch bản tấn công (bộ đánh giá MR24) có cảnh báo nhờ CHÍNH tín hiệu đó, và lưu lượng hợp
lệ khó không vượt mục tiêu báo nhầm. Mỗi hành vi cập nhật vào [`behavior-coverage-matrix.md`](behavior-coverage-matrix.md).

- [x] **MR27 [Lõi, M] Đợt 1 — 5 hành vi đã có luật nhưng chưa tự báo**: dò danh sách tài khoản; rải mật khẩu chậm; botnet phân
  tán (thêm biến thể botnet cùng khu vực địa lý, chưa từng kiểm chứng); xoay UA; đăng nhập dồn dập (luật tốc độ thay tầng 3 đang
  bắt 0%) — chi tiết và số đo: [`behavior-expansion-1.md`](behavior-expansion-1.md)
  - [x] Đo "vững" đúng định nghĩa giai đoạn I (`ml/corpus/behaviors.py`): phát hiện nhờ CHÍNH tín hiệu ≥ 50% biến thể, báo nhầm của
    tín hiệu ≤ 1% lần thử hợp lệ (đặt trước). Dò danh sách tài khoản, xoay UA, botnet phân tán: đã vững nhờ trọng số MR25 (100% / 100%
    / 87%, 0% báo nhầm)
  - [x] Rải mật khẩu chậm: điều kiện tỉ lệ thành công ≤ 0,2 + `min_action=alert` ở phạm vi IP → 100% / 0% (kể cả NAT văn phòng cả
    ngày); RBA phạm vi IP 24,1 → 10,7/10.000. Phạm vi ASN của nhồi thông tin/rải mật khẩu không còn ép hành động (`forces`): RBA
    cảnh báo bị ép trên dòng bình thường ~685 → ~11/10.000
  - [x] Botnet cùng khu vực (họ mới, IP Việt Nam nhiều nhà mạng): 83% nhờ `distributed_bruteforce`, 0% báo nhầm
  - [x] Đăng nhập dồn dập: luật mới `success_burst` (≥ 8 lần thành công/10 phút) → 80% (đúng các biến thể ≥ 8), báo nhầm 0,03%;
    RBA: ≥ 3 lần (kiểu `rapid_fire` cũ) khớp 3,5–4,5% đăng nhập hợp lệ — xác nhận không phải tấn công
  - [x] Cổng "cùng phiên" của `ml_geo` (≤ 30 phút, cùng IP + thiết bị): "đăng nhập lại" bị cảnh báo 64 → 38/121 (cùng máy 0/57)
  - **Kết quả**: 14/18 hành vi đo được trên bộ dữ liệu vững; ma trận 26 hành vi: **vững 21** (CP5: 18). Cả hệ thống trên 25 họ cũ
    không đổi (19,3% / 1,67% / 94,7%); 20 kịch bản không xấu đi
- [x] **MR28 [Nên, M] Đợt 2 — 3 hành vi mới**: đoán mã OTP liên tục (`verify-otp` hiện chỉ đếm số lần trong một challenge, không
  ghi sự kiện); cố đăng nhập vào tài khoản đang bị khoá (đếm từ audit `reject_blocked_login`); một IP đăng nhập THÀNH CÔNG vào
  nhiều tài khoản — chi tiết và số đo: [`behavior-expansion-2.md`](behavior-expansion-2.md)
  - [x] `app/detection/gate.py`: lần thử bị từ chối vì khoá và lần sai mã OTP được ghi (audit + bộ đếm của rule engine), luật chấm ở lần
    đăng nhập kế tiếp — vẫn một bộ luật
  - [x] `otp_guessing` (≥ 10 lần sai mã/24 giờ → lock): 83% / 0% báo nhầm; `blocked_retry` (≥ 10 lần bị từ chối/1 giờ → step_up khi hết
    khoá): 83% / 0%; `multi_account_success` (≥ 5 tài khoản/giờ, IP và thiết bị đều lạ): trọng số 0,056 — phòng máy đào tạo giống hệt,
    chỉ là bằng chứng, hành vi KHÔNG vững
  - [x] Bộ chạy tái hiện cửa `/login` (bước OTP, khoá dựng sẵn), hai chế độ cửa: `setup` đo "vững", `full` đo cả hệ thống như chạy thật
    (phát hiện: nhiều hành vi bị khoá sớm bởi tín hiệu khác trước khi luật riêng đủ dữ kiện)
  - **Kết quả**: 16/21 hành vi đo được trên bộ dữ liệu vững; ma trận 29 hành vi: **vững 23**. Các họ cũ không đổi; 20 kịch bản không
    đổi
- [x] **MR29 [Nên, M] Đợt 3 — luật kết hợp**: Tor/VPN/datacenter + quốc gia mới, thiết bị mới hoặc đăng nhập sai; bot UA + đăng
  nhập sai — chi tiết và số đo: [`combined-rules.md`](combined-rules.md)
  - [x] Đo cả bốn tổ hợp (thiết kế trên bộ hiệu chỉnh, báo số trên bộ đánh giá): giữ **Tor/VPN/datacenter + thiết bị lạ** (báo nhầm 0,75%,
    toàn bộ là người dùng VPN đổi điện thoại); loại + quốc gia mới (4,06%), + đăng nhập sai (1,04%), bot/script UA + đăng nhập sai (không bắt
    thêm lần thử nào — bot/script một mình đã cảnh báo từ MR25)
  - [x] `anonymizer_new_device`: hành động tối thiểu `step_up`, trọng số giữ ở mức IP (0,31) — bản đầu với trọng số đo được cộng với mô hình
    thành KHOÁ 29/44 lần đăng nhập của người dùng VPN hợp lệ; bản chốt: 0 khoá, 29 OTP
  - [x] Họ mới: `vn_vps_takeover` (VPS đặt ở Việt Nam — kho IP `datacenter_vn`), `vpn_typo`, `vpn_new_device`
  - **Kết quả**: VPN/datacenter + thiết bị lạ 83%, VPS trong nước 97% (vững); chỉ luật: 0/23 → 19/23 và 0/30 → 29/30; 18/23 hành vi đo được
    vững; ma trận 31 hành vi: **vững 25**. Các họ cũ không đổi; 20 kịch bản: chỉ "ngủ đông" từ cảnh báo lên xác thực thêm
- [ ] **MR30 [Thêm, S] Ngôn ngữ trình duyệt lệch quốc gia của IP** (Accept-Language) — chỉ làm nếu MR27–MR29 xong trước hạn
- Mục tiêu giai đoạn: ≥ 20 hành vi vững trên khoảng 28

## Giai đoạn J — Dữ liệu thật và tự bảo vệ (tuần 4)

- [x] **MR31 [Nên, L] Kiểm chứng trên log thật LANL** — chi tiết và số đo: [`lanl-validation.md`](lanl-validation.md)
  - [x] ETL `auth` + `redteam` ([`ml/lanl/etl.py`](../backend/ml/lanl/etl.py), DuckDB đọc luồng tệp nén, chỉ tài khoản người dùng:
    341,7 triệu sự kiện, 125,9 triệu lần đăng nhập); mẫu MỌI người dùng bị tấn công + 20% còn lại (trọng số 5); chia theo thời gian như
    Tuor et al. 2018: ngày 1–12 học, 13–58 kiểm tra, bỏ cuối tuần/ngày lễ (nhận từ chu kỳ 7 ngày của số lần đăng nhập)
  - [x] Đặc trưng theo lịch sử tài khoản ([`ml/lanl/features.py`](../backend/ml/lanl/features.py)): máy nguồn/đích mới, kiểu xác thực
    mới, giờ hiếm, đếm 1 giờ, số máy đích mới trong 1 giờ; Isolation Forest + luật đếm cờ "mới" + từng đặc trưng
    ([`ml/lanl/evaluate.py`](../backend/ml/lanl/evaluate.py))
  - [x] So với Tuor et al. 2018 (user-ngày AUC: Isolation Forest 0,763, RNN tốt nhất 0,876; sự kiện: RNN ký tự 0,98): đồ án user-ngày
    AUC 0,873 [0,841–0,900] (Isolation Forest), 0,852 (luật đếm cờ); sự kiện 0,824 — KHÔNG cùng điều kiện (chỉ LogOn, đặc trưng khác),
    ghi rõ ở báo cáo; thực tế: xem 200 người/ngày (trong ~8.260) chỉ bắt 12,6% user-ngày bị tấn công (`new_dst_1h`: 24,1%)
  - Xong khi: báo cáo riêng ghi rõ đây là kiểm chứng PHƯƠNG PHÁP trên log thật (log đăng nhập Windows nội bộ, khác cấu trúc web,
    không nối vào `/login`) — đạt; dữ liệu không vào git
- [x] **MR32 [Lõi, S] Hệ thống tự bảo vệ mình** — chi tiết: [`security-review.md`](security-review.md)
  - [x] `/admin/login` ([`admin_guard.py`](../backend/app/admin_guard.py)): ≥ 10 lần sai/15 phút theo IP, ≥ 5 lần sai/15 phút theo
    tài khoản với **khoá thông minh** (IP quen và IP lạ đếm riêng — kẻ tấn công không khoá được quản trị viên ở máy quen) → 429 +
    `Retry-After`; kiểm tra trước bcrypt; ghi lần thử TRƯỚC khi đếm nên request song song không vượt được giới hạn; mọi lần thử vào
    `audit_log`, xem ở `GET /admin/login-attempts` + bảng "Đăng nhập quản trị gần đây" trên dashboard
  - [x] Rà bảo mật thủ công toàn bộ (11 phát hiện, 2 mức cao): khoá JWT mẫu công khai (máy dev đang dùng) → production từ chối khởi
    động, dev dùng khoá ngẫu nhiên tạm; tên không tồn tại vẫn chạy bcrypt (thời gian 212,9 so với 209,2 ms — hết lộ tài khoản, phát
    hiện ở MR20); token WebSocket chuyển từ URL (bị ghi vào access log) sang subprotocol; `X-Forwarded-For` chỉ tin từ
    `TRUSTED_PROXIES`, đọc từ phải; Postgres/Redis chỉ mở trên 127.0.0.1; CORS thu hẹp; mật khẩu ≤ 128 ký tự; JWT bắt buộc
    `exp`/`iat`/`sub`; OTP demo không trả về khi `APP_ENV=production`; 401 → tự đăng xuất, có nút "Đăng xuất". Quét lịch sử git:
    không lộ khoá bí mật. Chưa chạy quét lỗ hổng thư viện (cần gửi ra dịch vụ ngoài)
  - [x] Ghi chú dữ liệu cá nhân (lưu gì, mục đích, ai xem, không lưu gì, Luật 91/2025/QH15 + Nghị định 356/2025/NĐ-CP, đề xuất thời
    hạn lưu giữ và quy trình xoá — chưa có tác vụ xoá tự động)
  - Kiểm trên trình duyệt với bản sao DB tạm: WebSocket "Real-time", khoá sau 5 lần sai hiện đúng thông báo, khởi động lại backend → tự
    về trang đăng nhập (bắt được và sửa một lỗi của chính bộ chặn 401); script mô phỏng MR16 cho kết quả như cũ (sửa thêm lỗi có từ MR20)
- [x] **MR33 [Nên, S] Dọn repo và mã**
  - [x] `_soak_test_raw.json` (115 KB số liệu thô) ra khỏi git; `scripts/soak_test.py` ghi vào `ml/artifacts/` (đã bỏ qua)
  - [x] FastAPI `lifespan` thay `@app.on_event("startup")` — hết cảnh báo ngừng hỗ trợ
  - [x] Console UTF-8 dùng chung (`app/utils/console.py`, gọi từ `scripts/__init__.py`, `ml/__init__.py`): `create_admin.py` và 32
    script khác in tiếng Việt từng ném `UnicodeEncodeError` khi stdout bị chuyển hướng mà thiếu `PYTHONIOENCODING`
  - [x] Code chết: quét bằng phân tích cú pháp — 11 import không dùng đã xoá; không còn hàm/module nào của `app/` không được dùng sau
    hợp nhất (2 hàm chỉ test gọi là móc dọn cache cho test, giữ); 5 script không ai import đều là lệnh chạy tay có trong tài liệu
  - [ ] ruff/format: chưa làm — ruff chưa cài trong venv (cần tải, chờ đồng ý); định dạng lại toàn bộ sẽ tạo diff rất lớn

## Giai đoạn K — Nghiệm thu và đóng băng (tuần 5)

- [ ] **MR34 [Lõi, M] Nghiệm thu toàn bộ**: regression + độ phủ test (`pytest-cov`); E2E trình duyệt cho mọi hành vi vững thao
  tác được qua UI; benchmark (tài khoản mới); soak 60 phút; sửa lỗi chặn demo
- [ ] **MR35 [Lõi, M] Đồng bộ tài liệu với kiến trúc mới**: README, sơ đồ kiến trúc, api-contract, db-schema, getting-started,
  model card, ma trận phủ hành vi, hướng dẫn tái lập; tài liệu cũ đánh dấu "lịch sử"
- [ ] **MR36 [Lõi, S] Demo chắc chắn**: khởi động một lệnh (docker compose cả backend + frontend, hoặc script), script reset dữ
  liệu demo, tài khoản demo, chạy kịch bản tấn công một lệnh, quay video dự phòng
- [ ] **CP6 — đóng băng code**: sau mốc này chỉ sửa lỗi chặn demo

## Giai đoạn L — Báo cáo và bảo vệ (tuần 6)

- [ ] **MR37 [Lõi, L] Báo cáo đồ án** theo mẫu của trường; mọi hình và bảng lấy từ số đo thật
- [ ] **MR38 [Lõi, M] Slide + kịch bản demo 10–15 phút** (kèm video dự phòng từ MR36)
- [ ] **MR39 [Lõi, M] Ngân hàng câu hỏi hội đồng** (~60 câu: kiến trúc, ML, dữ liệu, đánh giá, bảo mật, hạn chế) + đáp án + 2
  buổi bảo vệ thử

## Song song suốt 6 tuần

- [ ] **H1–H5 — Hiểu hệ thống** (cuối mỗi tuần): giải thích phần vừa đổi + 10 câu hỏi kiểu hội đồng. H1 sơ đồ một trang và luồng
  5 bước; H2 luật, mức tối thiểu, noisy-OR; H3 ML (Isolation Forest, LightGBM, recall/FPR/ROC-AUC, hiệu chỉnh); H4 hành vi và
  đánh giá báo nhầm; H5 dữ liệu (RBA, LANL, tự sinh) và bảo mật
- [ ] **DC — Đề cương** viết theo kiến trúc cuối cùng: bản nháp sau CP4, chốt sau CP5

**Không làm trong giai đoạn này:** MR-S1–S4 (chưa duyệt); mô hình chuỗi/đồ thị; LLM; gọi API bên ngoài khi chưa hỏi; tải danh
sách mật khẩu bị lộ (chỉ làm nếu duyệt thêm).
