# Mục lục tài liệu

Hai loại tài liệu: **hiện hành** (mô tả đúng hệ thống đang chạy, cập nhật ở MR35 — 10/10/2026) và **ghi chép theo thời điểm** (báo cáo
từng MR: vì sao đi tới thiết kế hiện tại và số đo lúc đó; mỗi tệp có dòng ghi chú ở đầu). Khi hai loại nói khác nhau, tin tài liệu
hiện hành.

## Bắt đầu

| Tài liệu | Nội dung |
|---|---|
| [`../README.md`](../README.md) | Giới thiệu, chạy nhanh, kết quả chính |
| [`architecture.md`](architecture.md) | **Kiến trúc hiện hành**: thành phần, luồng một lần đăng nhập, hai mô hình, cách gộp điểm, số đo, giới hạn |
| [`demo-guide.md`](demo-guide.md) | Demo một lệnh, kịch bản 12 phút, xử lý sự cố |
| [`getting-started.md`](getting-started.md) | Môi trường phát triển, dữ liệu mẫu, lỗi thường gặp |
| [`reproduction-guide.md`](reproduction-guide.md) | Tái lập mọi số đo theo thứ tự phụ thuộc |

## Tham chiếu hiện hành

| Tài liệu | Nội dung |
|---|---|
| [`api-contract.md`](api-contract.md) | 18 endpoint, định dạng request/response, xác thực |
| [`db-schema.md`](db-schema.md) | 15 bảng PostgreSQL |
| [`rule-catalog.md`](rule-catalog.md) | 24 luật — **tự sinh từ mã**, test báo lỗi nếu lệch |
| [`rba-features.md`](rba-features.md) | Đặc tả 50 đặc trưng của `hybrid_cp2` |
| [`model-card-rba.md`](model-card-rba.md) | Thẻ mô hình `hybrid_cp2` (mục đầu: cách dùng hiện tại) |
| [`rba-data-card.md`](rba-data-card.md) | Bộ dữ liệu RBA — **tổng hợp**, cách nói đúng khi trích dẫn |
| [`calibration-corpus.md`](calibration-corpus.md) | Bộ kịch bản có nhãn (39 họ) dùng hiệu chỉnh và đo |
| [`security-review.md`](security-review.md) | Rà soát bảo mật, bảo vệ cổng quản trị, dữ liệu cá nhân |
| [`geoip-setup.md`](geoip-setup.md) | Cài GeoLite2 |

## Đánh giá

| Tài liệu | Nội dung |
|---|---|
| [`behavior-coverage-matrix.md`](behavior-coverage-matrix.md) | **Bảng hiện hành**: hành vi nào bị bắt, bởi tín hiệu nào, báo nhầm bao nhiêu |
| [`lanl-validation.md`](lanl-validation.md) | Kiểm chứng phương pháp trên log thật LANL, so với Tuor et al. 2018 |
| [`acceptance-mr34.md`](acceptance-mr34.md) | Nghiệm thu: hồi quy, độ phủ, E2E, hiệu năng, soak |
| [`soak-test.md`](soak-test.md) | Soak 60 phút (MR34) |

## Ghi chép theo thời điểm (lịch sử)

| Giai đoạn | Tài liệu |
|---|---|
| Tuần 1–8 | [`history.md`](history.md) (nhật ký README cũ), [`e2e-test-report.md`](e2e-test-report.md), [`ml-evaluation.md`](ml-evaluation.md) (mô hình địa lý–thời gian), [`performance.md`](performance.md) |
| MR1–MR8b: học máy trên RBA | [`rba-evaluation.md`](rba-evaluation.md), [`rba-baseline-comparison.md`](rba-baseline-comparison.md), [`ml-evaluation-v2.md`](ml-evaluation-v2.md), [`ml-holdout-ablation.md`](ml-holdout-ablation.md), [`ml-explanations.md`](ml-explanations.md), [`ml-model-selection.md`](ml-model-selection.md) |
| MR9–MR19: rule engine, tích hợp, dashboard | [`rule-replay.md`](rule-replay.md), [`rule-tuning.md`](rule-tuning.md), [`rule-ml-overlap.md`](rule-ml-overlap.md), [`hybrid-risk-engine.md`](hybrid-risk-engine.md), [`realtime-integration.md`](realtime-integration.md), [`alert-intelligence-v2.md`](alert-intelligence-v2.md), [`campaign-correlation.md`](campaign-correlation.md), [`feedback-loop.md`](feedback-loop.md), [`automated-response.md`](automated-response.md), [`dashboard-v2.md`](dashboard-v2.md), [`attack-scenarios-v2.md`](attack-scenarios-v2.md), [`model-b-geo-time.md`](model-b-geo-time.md), [`e2e-test-report-v2.md`](e2e-test-report-v2.md), [`commercial-comparison.md`](commercial-comparison.md), [`untested-behaviors-measured.md`](untested-behaviors-measured.md) |
| MR20–MR23: hợp nhất kiến trúc | [`rule-unification.md`](rule-unification.md), [`geo-model-integration.md`](geo-model-integration.md), [`incident-unification.md`](incident-unification.md) |
| MR25–MR29: hiệu chỉnh, mở rộng hành vi | [`rule-recalibration.md`](rule-recalibration.md), [`vn-recalibration.md`](vn-recalibration.md), [`behavior-expansion-1.md`](behavior-expansion-1.md), [`behavior-expansion-2.md`](behavior-expansion-2.md), [`combined-rules.md`](combined-rules.md) |

Kế hoạch và tiến độ toàn dự án: [`checklist.md`](checklist.md).
