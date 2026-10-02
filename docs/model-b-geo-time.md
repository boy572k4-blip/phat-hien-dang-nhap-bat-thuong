# Mô hình B (địa lý-thời gian) — dữ liệu từ thư viện tấn công mô phỏng v2 (MR18)

> Từ MR22 mô hình này là nguồn bằng chứng `ml_geo` của hybrid risk engine (không còn alert `ml_anomaly` riêng), có cổng
> cold-start, và dữ liệu sinh với seed cố định — xem [`geo-model-integration.md`](geo-model-integration.md).

`docs/checklist.md` MR6 ghi: "Mô hình B (địa lý-thời gian) chuyển sang MR18: cần thư viện kịch bản tấn công của MR18
và simulator hiện tại (`ml/generate_dataset.py`) dựa trên DB". "Mô hình B" **không phải một mô hình xây MỚI** — chính
là tầng 3 đã có từ Tuần 7 (Isolation Forest/LOF/Autoencoder, [`docs/ml-evaluation.md`](ml-evaluation.md)), đặc trưng
[`ml/features.py`](../backend/ml/features.py) (giờ trong ngày, khoảng cách tới "nhà", thiết bị/vị trí mới) — ĐÚNG phần
"địa lý-thời gian" mà RBA không có (`docs/rba-features.md` mục 5: "Đặc trưng địa lý và giờ trong ngày không có ở đây
vì RBA không hỗ trợ... chúng thuộc mô hình B trên simulator"). MR18 bổ sung DỮ LIỆU (2 kiểu bất thường mới, tinh vi
hơn 5 kiểu gốc) và huấn luyện/đánh giá LẠI, không đổi kiến trúc mô hình.

## Chỉ 2/9 kịch bản MR18 dịch được sang khuôn dữ liệu tầng 3 — vì sao

`ml/features.py` có 9 đặc trưng: `hour_sin/cos`, `day_of_week`, `hour_deviation_from_avg`, `is_new_location`,
`is_new_device`, `minutes_since_last_login`, `logins_last_24h`, `distance_km_from_home` — **không có đặc trưng nào về
IP/ASN cụ thể, số lượng IP/tài khoản khác nhau, hay tốc độ thử sai**. 7/9 kịch bản của
[`ml/attack_scenarios.py`](../backend/ml/attack_scenarios.py) (rải mật khẩu chậm, botnet phân tán, proxy cùng quốc
gia, xoay User-Agent, mô phỏng tinh vi, dò danh sách tài khoản, nhồi thông tin quy mô lớn) đo ĐÚNG những tín hiệu tầng
3 KHÔNG THẤY ĐƯỢC — dịch chúng thành nhãn tầng 3 sẽ chỉ tạo ra các dòng "trông giống bình thường" về mặt đặc trưng dù
nhãn là "bất thường", không dạy được gì cho mô hình (và có thể làm HỎNG việc huấn luyện bằng nhiễu nhãn). Đây là một
GIỚI HẠN PHẠM VI thật của tầng 3, không phải sơ suất — đã ghi từ Tuần 7 (`model-card-rba.md` mục 3: "phát hiện tấn
công dựa trên địa lý/giờ trong ngày... phần đó thuộc mô hình B").

Chỉ 2 kịch bản có tín hiệu ĐÚNG phạm vi geo/time của tầng 3:
- **`dormant_reactivation`** — khoảng cách thời gian CỰC LỚN kể từ lần đăng nhập trước (`minutes_since_last_login`)
  cộng vị trí mới — kiểu bất thường HOÀN TOÀN MỚI so với 5 kiểu gốc (không kiểu nào của Tuần 7 dựng riêng tín hiệu
  "im lặng lâu ngày").
- **`impossible_travel_geo`** — TỔ HỢP thời gian cực ngắn VÀ khoảng cách cực xa CÙNG LÚC kể từ lần trước — khác
  `unusual_location` gốc (không ràng buộc thời gian, có thể xảy ra sau nhiều ngày).

Đã thêm vào [`ml/generate_dataset.py`](../backend/ml/generate_dataset.py) (`_make_dormant_reactivation_anomaly`,
`_make_impossible_travel_geo_anomaly`), chạy lại toàn bộ pipeline (`generate_dataset --reset` → `extract_features` →
`train` → `evaluate`).

## Kết quả — recall theo kiểu bất thường (Isolation Forest, tốt nhất trong 3 mô hình, tập test)

Số của bộ dữ liệu sinh với seed cố định (MR22, tái lập được — `python -m ml.evaluate` →
`ml/artifacts/evaluation_geo_by_type.csv`). Hai cột: điểm làm việc đã công bố từ Tuần 7 (gắn cờ 14,2% điểm cao nhất của
tập test) và ngưỡng của chính mô hình — ngưỡng mà luồng thật dùng (trước MR22 cho alert `ml_anomaly`, từ MR22 là mốc của
nguồn `ml_geo` trong hybrid: [`geo-model-integration.md`](geo-model-integration.md)).

| Kiểu bất thường | Số ca (test) | Recall (điểm đã công bố) | Recall (ngưỡng mô hình = luồng thật) |
|---|---|---|---|
| `dormant_reactivation` (MỚI) | 13 | **100%** | **100%** |
| `impossible_travel_geo` (MỚI) | 18 | **55,6%** | **66,7%** |
| `unusual_hour+unusual_location` | 9 | 100% | 100% |
| `unusual_device+unusual_hour` | 5 | 100% | 100% |
| `unusual_device+unusual_location` | 4 | 75% | 75% |
| `unusual_location` | 18 | 72,2% | 77,8% |
| `unusual_hour` | 18 | 72,2% | 94,4% |
| `unusual_device` | 28 | 46,4% | 57,1% |
| `rapid_fire` | 13 | 0% | 0% |
| **Tổng** / báo nhầm | 126 / 435 | 62,7% / 0,2% | 70,6% / 1,6% |

**2 kiểu MỚI hoạt động tốt** — `dormant_reactivation` bắt được TOÀN BỘ, `impossible_travel_geo` ở mức của
`unusual_location`. Hợp lý: cả hai đều có tín hiệu THỜI GIAN/KHOẢNG CÁCH cực đoan (khoảng cách giờ/phút rất lớn hoặc rất
nhỏ so với phân phối thường thấy), loại tín hiệu Isolation Forest vốn đã mạnh nhất (`docs/ml-evaluation.md`: yếu nhất ở
`rapid_fire`/`unusual_device` đơn lẻ, mạnh nhất ở tín hiệu đơn giản/cực đoan).

## So sánh "trước/sau" — đã có seed, chưa chạy cấu hình đối chứng

Bản MR18 của tài liệu này ghi: `ml/generate_dataset.py` **không cố định random seed**, nên số đo giữa hai lần chạy (vd
56,9% recall trên 5 kiểu gốc trong lần chạy MR18 so với 78,3% của Tuần 7) không so sánh được — nhiều khả năng là dao động
ngẫu nhiên (mẫu 13–62 ca mỗi kiểu), không phải "thêm 2 kiểu mới làm hỏng mô hình". Trong chính lần chạy đó, 2 kiểu MR18
còn có recall cao hơn 5 kiểu gốc (78,1% so với 56,9%).

MR22 đã cố định seed **và** mốc thời gian (`--seed`, `--reference-time`): số trong bảng trên chạy lại ra đúng như vậy. Trên
bộ dữ liệu này, recall theo điểm đã công bố: 5 kiểu gốc 58,9% (56/95), 2 kiểu MR18 74,2% (23/31) — cùng xu hướng với lần
chạy MR18 (theo ngưỡng mô hình: 67,4% và 80,6%). Phép đối chứng đúng
nghĩa — cùng seed, sinh dữ liệu **có** và **không có** 2 kiểu mới, so 5 kiểu gốc — giờ làm được nhưng **chưa chạy** (không
thuộc phạm vi MR22).

## Giới hạn khác

- Mẫu nhỏ (13-18 ca/kiểu mới trong tập test) — đủ để thấy xu hướng, không đủ cho khoảng tin cậy chặt.
- `dormant_reactivation` dùng khoảng cách 35 ngày (không phải 90 ngày như `dormant_account_login` của rule engine,
  MR9) — tầng 3 không có ngưỡng cứng, chỉ cần lệch rõ so với phân phối khoảng cách thường thấy (~2-3 ngày/lần trên
  90 ngày, 30-55 lần/user) để mô hình học được; không nhằm khớp số của một luật ở tầng khác.
- 7/9 kịch bản KHÔNG dịch được sang tầng 3 (xem trên) — muốn tầng 3 "thấy" được kiểu tấn công đó cần THÊM đặc trưng
  mới (IP/ASN, tốc độ) vào `ml/features.py`, về bản chất là làm lại một phần việc RBA (`ml/rba/features.py`) đã làm
  cho tầng khác — không phải việc của MR18.
- Chưa vẽ lại ma trận nhầm lẫn/ROC cho RIÊNG 2 kiểu mới (biểu đồ `ml.evaluate` hiện vẫn gộp toàn bộ tập test).
