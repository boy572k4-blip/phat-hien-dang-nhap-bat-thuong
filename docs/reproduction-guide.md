# Hướng dẫn tái lập toàn bộ (MR19, cập nhật MR35)

Gom **theo đúng thứ tự phụ thuộc** mọi lệnh tái lập đã nằm rải rác ở cuối từng tài liệu riêng (mỗi tài liệu vẫn là
nguồn giải thích số liệu — tài liệu này chỉ lo thứ tự chạy). Nếu chỉ cần chạy hệ thống lên (không cần huấn luyện lại
mô hình/tái lập số liệu nghiên cứu), dừng ở Giai đoạn 0 và xem [`getting-started.md`](getting-started.md); chỉ cần demo:
`demo\start.ps1` ([`demo-guide.md`](demo-guide.md)). Tệp mô hình vận hành đã có trong git (10/10/2026), nên Giai đoạn 1–5 chỉ cần khi
muốn huấn luyện lại hoặc tái lập số đo nghiên cứu. Kiến trúc hiện hành: [`architecture.md`](architecture.md).

Tất cả lệnh chạy từ `backend/`, môi trường ảo đã activate (`venv\Scripts\activate`). Từ MR33 mọi lệnh `python -m scripts.…` /
`python -m ml.…` tự in tiếng Việt đúng trên console Windows (không cần `PYTHONIOENCODING`).

## Giai đoạn 0 — Hạ tầng và dữ liệu demo (bắt buộc để chạy web app)

Đã có sẵn trên máy dev hiện tại; chỉ cần trên máy mới hoàn toàn. Chi tiết đầy đủ: [`getting-started.md`](getting-started.md).

```bash
docker compose up -d                                       # Postgres + Redis
alembic upgrade head                                        # toàn bộ schema, 15 bảng — docs/db-schema.md
python -m scripts.create_admin --username admin --password "MatKhauManh123!"
python -m scripts.generate_labeled_anomalies --reset        # 25 user demo dashboard (Tuần 3)
python -m ml.generate_dataset --reset                       # 40 user, 7 kiểu bất thường (user101-140, Tuần 7 + MR18)
```

## Giai đoạn 1 — Bộ dữ liệu RBA (bắt buộc cho mọi thứ ở Giai đoạn 2-4)

Cần file `rba-dataset.zip` (Kaggle `dasgroup/rba-dataset`, 9GB, **không giải nén**) đặt ở `RBA_ZIP_PATH` hoặc
`backend/ml/data/rba/` hoặc Downloads. Chi tiết, giấy phép, cảnh báo "dữ liệu tổng hợp": [`rba-data-card.md`](rba-data-card.md).

```bash
python -m ml.check_env      # xác nhận tìm thấy file zip trước khi chạy gì tốn thời gian
python -m ml.rba.etl        # zip -> ml/data/rba/rba_full.parquet, ~5 phút
python -m ml.rba.sample     # -> rba_sample.parquet, ~30 giây — 2.707.021 dòng/401.092 user dùng cho mọi bước sau
python -m pytest tests/test_rba_features*.py tests/test_rba_model_table.py   # 29 test: đặc trưng v2 không rò rỉ — rba-features.md
```

## Giai đoạn 2 — Bộ mô phỏng kẻ tấn công + kiểm định dấu vân tay

**Chạy trước khi tin bất kỳ số nào ở bài `attacker/*`** — nếu kiểm định không đạt, bộ mô phỏng còn "dấu vân tay" và
mô hình học từ nó sẽ cho recall giả tạo (từng xảy ra ở CP1, xem [`rba-evaluation.md`](rba-evaluation.md) mục 5).

```bash
python -m ml.rba.attackers                     # bộ test, ~10 phút — nên chạy nền
python -m ml.rba.attackers --period trainval    # bộ train/val để huấn luyện/chọn mô hình, ~8 phút
python -m ml.rba.audit                          # kiểm định tổng thể (test) — nhóm cur/history/rhythm/rarity/infra phải ≈ 0,5
python -m ml.rba.audit trainval                 # ... và train, val
python -m ml.rba.audit conditional              # kiểm định CÓ ĐIỀU KIỆN (MR8) — phát hiện dấu vân tay còn sót ở infra_ip/rarity
```

## Giai đoạn 3 — Huấn luyện và đánh giá bản MR6 (13 mô hình baseline, dùng để so sánh công bằng)

```bash
python -m ml.rba.train                          # huấn luyện toàn bộ 13 mô hình, ~8 phút -> ml/artifacts/rba/ (chỉ hybrid_cp2 có trong git)
python -m ml.rba.report all --n-boot 300        # 13 mô hình × 11 bài, khoảng tin cậy bootstrap, ~15 phút -> ml/artifacts/rba_reports/
python -m ml.rba.analysis gbm_attack_ip gbm_attacker_sim hybrid   # chuyển ngưỡng, hiệu chỉnh xác suất, gán công (bản MR6)
python -m ml.rba.summary                        # bảng ma trận mô hình × bài, đọc nhanh từ báo cáo đã lưu
```

Kiểm chứng bổ sung (không bắt buộc để có số chính, nhưng là nguồn của các kết luận "tổng quát hoá kém với họ mới"):

```bash
python -m ml.rba.holdout    # giấu 1 họ IP tấn công khỏi train — ml-holdout-ablation.md
python -m ml.rba.ablation   # bỏ từng nhóm đặc trưng — ml-holdout-ablation.md
python -m ml.rba.errors     # phân tích lỗi theo trường hợp — ml-holdout-ablation.md
python -m ml.rba.explain_eval all --hybrid hybrid   # giải thích + ngưỡng vận hành bản MR6 — ml-explanations.md
```

## Giai đoạn 4 — Chốt mô hình CP2 (`hybrid_cp2`, mô hình VẬN HÀNH thật)

Đây là mô hình `/login` thật sự dùng (Giai đoạn 6). Chi tiết cơ chế chọn: [`ml-model-selection.md`](ml-model-selection.md).

```bash
python -m ml.rba.selection all     # chọn nhóm đặc trưng (bootstrap ghép cặp) + huấn luyện hybrid_cp2, ~15-20 phút -> ml/artifacts/rba/hybrid_cp2.joblib (báo cáo: rba_cp2/)
python -m ml.rba.report gbm_attack_ip_cp2 gbm_attacker_sim_cp2 isolation_forest_cp2 hybrid_cp2 --n-boot 300
python -m ml.rba.analysis hybrid_cp2                # chuyển ngưỡng + gán công cho hybrid_cp2 — số ở ml-evaluation-v2.md mục "Tóm tắt vận hành"
python -m ml.rba.explain_eval all                   # giải thích + ngưỡng vận hành bản cp2 (mặc định) -> ml/artifacts/rba_cp2/explain/
python -m pytest tests/test_rba_selection.py         # 12 test
```

## Giai đoạn 5 — Mô hình địa lý–thời gian `ml_geo` (dữ liệu tự sinh, KHÁC bộ RBA; trước MR22 gọi là "tầng 3")

```bash
python -m ml.extract_features    # trích đặc trưng từ dữ liệu Giai đoạn 0 (user101-140), chống rò rỉ tương lai
python -m ml.train                # huấn luyện Isolation Forest/LOF/Autoencoder -> backend/ml/artifacts/
python -m ml.evaluate              # so sánh + xuất biểu đồ vào docs/figures/ — ml-evaluation.md, model-b-geo-time.md
```

## Giai đoạn 6 — Chạy hệ thống (nạp `hybrid_cp2` tự động)

```bash
uvicorn app.main:app --reload --port 8000
```

Khởi động lần đầu SAU khi Giai đoạn 4 đã tạo `ml/artifacts/rba/hybrid_cp2.joblib`, backend tự đăng ký mô hình
vào bảng `model_registry` — không có lệnh nạp riêng (xem [`model-card-rba.md`](model-card-rba.md) mục "Trạng thái").
Thiếu artifact thì hệ thống KHÔNG lỗi, chỉ tắt thành phần ML (rơi về hồ sơ dự phòng chỉ-luật).

## Giai đoạn 7 — Kiểm chứng bằng kịch bản mô phỏng qua HTTP thật (không phải test đơn vị)

Mỗi script tự dựng CSDL/Redis riêng trong bộ nhớ hoặc chạy qua `TestClient` — **không** chạy qua `pytest` (xem
docstring từng script), kết quả ghi lại thành tài liệu `docs/*.md` tương ứng:

```bash
python -m scripts.attack_scenario_runner       # 9 kịch bản thật qua HTTP -> docs/attack-scenarios-v2.md (MR18)
python -m scripts.alert_intelligence_sim       # ưu tiên hoá + dedup cảnh báo -> alert-intelligence-v2.md (MR13)
python -m scripts.feedback_loop_sim            # vòng phản hồi + ngưỡng thích nghi -> feedback-loop.md (MR15)
python -m scripts.automated_response_sim       # OTP + khoá tài khoản/IP -> automated-response.md (MR16)
```

⚠️ Một số script (kẻ tấn công mô phỏng, thứ tự chọn IP...) không có hạt giống ngẫu nhiên cố định — số liệu có thể
lệch nhẹ giữa các lần chạy; xem caveat cụ thể ở từng tài liệu đích trước khi so sánh với số đã công bố.

## Giai đoạn 8 — Bộ kịch bản có nhãn, hiệu chỉnh và đo hành vi (MR24–MR29)

Bộ 39 họ (tấn công + hợp lệ khó) chạy qua đúng pipeline, Postgres/Redis giả lập trong tiến trình — data card:
[`calibration-corpus.md`](calibration-corpus.md). Số của ma trận hành vi hiện hành lấy từ thư mục `mr29`.

```bash
python -m ml.corpus.run --split both --with-model-inputs --out-dir ml/artifacts/corpus/mr29                    # ~3-5 phút
python -m ml.corpus.run --split evaluation --with-model-inputs --gate full --out-dir ml/artifacts/corpus/mr29_full
python -m ml.corpus.behaviors            # hành vi "vững", báo nhầm theo họ -> mr29/behaviors_report.json (behavior-coverage-matrix.md)
python -m ml.corpus.calibrate_rules      # trọng số luật (MR25, rule-recalibration.md); --write ghi vào hồ sơ đang dùng
python -m ml.corpus.calibrate_ml         # độ lệch miền của hybrid_cp2 (MR26, vn-recalibration.md); đọc thư mục mr26
```

`--write` ghi đè `app/detection/hybrid/profiles/rba_calibrated.json` — chỉ dùng khi chủ động hiệu chỉnh lại; bản trong git là bản đã
dùng để đo.

## Giai đoạn 9 — Kiểm chứng trên log thật LANL (MR31)

Cần 2 tệp `auth.txt.gz` (7,6 GB nén) và `redteam.txt.gz` của bộ "Comprehensive, Multi-Source Cyber-Security Events" (đăng ký trên trang
LANL) đặt ở `ml/data/lanl/` — [`lanl-validation.md`](lanl-validation.md).

```bash
python -m ml.lanl.etl         # ~4 phút
python -m ml.lanl.features    # ~25 phút
python -m ml.lanl.evaluate    # ~5 phút -> ml/artifacts/lanl/evaluation.json
```

## Giai đoạn 10 — Kiểm thử, hiệu năng, soak test, nghiệm thu (MR34)

Đo trên bản sao DB tạm, không đo trên DB đang dùng: [`acceptance-mr34.md`](acceptance-mr34.md).

```bash
pytest -q                                                  # 903 test, không cần Docker (SQLite in-memory + fakeredis)
pytest -q --cov=app --cov=ml --cov=scripts                 # độ phủ (pytest-cov) — lâu hơn nhiều (~15 phút)
venv\Scripts\ruff.exe check .                             # chỉ nhóm bắt lỗi F/E9 (backend/ruff.toml)
python -m scripts.benchmark_login --n 50 --accounts 10    # tuần tự, xoay vòng 10 tài khoản MỚI
python -m scripts.benchmark_login --n 100 --accounts 20 --concurrency 10
python -m scripts.soak_test --minutes 60 --server-pid <PID uvicorn>   # tải nhẹ liên tục + bộ nhớ server — docs/soak-test.md
```

Benchmark phải xoay vòng tài khoản: ≥ 8 lần thành công/10 phút vào MỘT tài khoản khớp luật `success_burst` (MR27) và bị đòi OTP/khoá.
Thêm `--base-url http://127.0.0.1:<cổng>` khi đo một server tạm ở cổng khác.

## Tổng thời gian ước tính

Giai đoạn 1-4 (toàn bộ pipeline RBA từ đầu) mất khoảng **60-90 phút** trên máy dev hiện tại, phần lớn ở Giai đoạn 2-4
(mô phỏng kẻ tấn công + huấn luyện + báo cáo bootstrap). Giai đoạn 9 (LANL) khoảng 35 phút sau khi tải dữ liệu; soak 60 phút; các giai
đoạn còn lại mỗi giai đoạn dưới 10 phút. Không có bước nào cần GPU.
