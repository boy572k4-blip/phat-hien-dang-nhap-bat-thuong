# Một bộ luật duy nhất (MR21)

Trước MR21, một lần đăng nhập đi qua **năm cơ chế chồng nhau**: tầng 1 (ba luật đếm Redis riêng của Tuần 3, mỗi lần khớp
tạo một alert riêng), tầng 2 (bảng cộng điểm tay của Tuần 4, alert `high_risk_score`), tầng 3 (ML địa lý-thời gian,
alert `ml_anomaly`), rule engine v2 (MR9, 19 luật) và hybrid risk engine (MR11, alert `hybrid_risk`). Hai trong số đó —
tầng 1 và rule engine v2 — chấm **cùng** dấu hiệu dò mật khẩu, nhồi thông tin, di chuyển bất khả thi bằng hai bộ đếm
khác nhau; một cuộc tấn công ra nhiều cảnh báo cho cùng một sự việc.

MR21 **xoá tầng 1 và tầng 2**. Mọi dấu hiệu đó giờ chỉ còn là luật của rule engine v2, và luật xác định mang **hành động
tối thiểu** để vẫn tự cảnh báo được. Mã: [`app/detection/engine/`](../backend/app/detection/engine/),
[`app/detection/hybrid/combine.py`](../backend/app/detection/hybrid/combine.py),
[`app/detection/pipeline.py`](../backend/app/detection/pipeline.py). Danh mục luật (tự sinh): [`rule-catalog.md`](rule-catalog.md).

## 1. Ánh xạ thành phần cũ → mới

| Thành phần cũ | Điều kiện | Giờ là |
|---|---|---|
| Tầng 1 `brute_force` | ≥ 5 lần sai vào một tên đăng nhập / 5 phút | luật v2 `brute_force` (cùng ngưỡng), hành động tối thiểu `alert` |
| Tầng 1 `credential_stuffing` | ≥ 10 lần sai và ≥ 5 tên khác nhau từ một IP / 5 phút | luật v2 `credential_stuffing` (cùng ngưỡng, thêm phạm vi ASN), tối thiểu `alert` |
| Tầng 1 `impossible_travel` | > 900 km/h giữa hai lần thử liên tiếp | luật v2 `impossible_travel` (cùng ngưỡng), tối thiểu `alert`; toạ độ điểm trước đi theo cảnh báo hybrid để bản đồ vẫn vẽ đường nối |
| Tầng 2 "chuỗi sai +40" | đang bị dò mật khẩu (= điều kiện tầng 1 `brute_force`) | luật v2 `brute_force` (như trên) |
| Tầng 2 "thành công sau chuỗi sai +50" | thành công sau ≥ 3 lần sai / 5 phút | luật v2 `success_after_failures` (≥ 5 lần / 10 phút — ngưỡng có sẵn từ MR9, chặt hơn để giảm báo nhầm), tối thiểu `step_up` |
| Tầng 2 "lệch giờ +20" | giờ đăng nhập lệch > 2,5 độ lệch chuẩn so với thói quen | đặc trưng ML `hour_deviation_from_avg` (tầng 3, thành nguồn bằng chứng của hybrid ở MR22) |
| Tầng 2 "vị trí lạ +30" | (quốc gia, thành phố) chưa từng thành công | đặc trưng ML `is_new_location` (tầng 3) và `new_country`/`llr_country` (mô hình `hybrid_cp2`) |
| Ghi đè `blocklist_hit` của hybrid (MR11) | nguồn trong blocklist | luật `blocklist_hit` với hành động tối thiểu `lock` |

Công thức tầng 2 vẫn còn, nhưng chỉ là **phương pháp đối chứng** trong phép so sánh tầng 2 với ML của Tuần 7
([`ml/tier2_baseline.py`](../backend/ml/tier2_baseline.py), dùng bởi `ml/evaluate.py`), để con số đã đưa vào
[`ml-evaluation.md`](ml-evaluation.md) vẫn chạy lại được. Luồng đăng nhập không còn dùng nó.

## 2. Hành động tối thiểu

**Vấn đề.** Trọng số của luật trong hybrid là độ chính xác đo trên RBA. RBA không có toạ độ, IP là giả, gần như không có
bot, nên nhiều luật xác định không đo được hoặc chỉ đo trên mẫu rất nhỏ: `impossible_travel` 5% (mặc định), `brute_force`
10,1%, `success_after_failures` 0,0% (mẫu 40 dòng). Chỉ **1/19** luật (`credential_stuffing`, 34,6%) đủ một mình vượt
ngưỡng cảnh báo — trước MR21, dò mật khẩu và di chuyển bất khả thi chỉ được cảnh báo nhờ tầng 1 đứng riêng.

**Không** sửa bằng cách nâng trọng số bằng tay: trọng số là xác suất đo được, nâng tay làm sai ý nghĩa của nó. Thay vào đó
mỗi luật xác định khai báo `min_action` (`RuleSpec`, [`registry.py`](../backend/app/detection/engine/registry.py)):

- khớp ở chế độ `enforce` → hành động ít nhất là mức đó (`alert` < `step_up` < `lock`), bất kể điểm;
- **xác suất** của bằng chứng (`RiskResult.probability`) không đổi; chỉ **điểm hiển thị** được nâng lên ngưỡng thấp nhất của
  hành động đó (vd brute force: bằng chứng 10% → điểm hiển thị = `alert_at`), để không có cảnh báo kiểu "điểm 10 nhưng bị khoá";
- nhiều luật cùng ép thì lấy mức nặng nhất; điểm đã tự đạt mức cao hơn thì luật không đổi gì (`overridden_by = None`);
- cảnh báo ghi rõ luật nào đã ép (`explanation.forced_by`, câu "Mức '…' là hành động tối thiểu của luật …").

| Luật | Hành động tối thiểu (tạm thời) |
|---|---|
| `brute_force`, `credential_stuffing`, `impossible_travel` | `alert` |
| `success_after_failures` | `step_up` (người dùng thật gõ sai nhiều lần chỉ phải xác thực thêm; kẻ đã đoán trúng mật khẩu bị chặn ở bước đó) |
| `blocklist_hit` | `lock` |

Các mức này là **tạm thời theo kế hoạch** — MR25 chốt lại bằng số đo báo nhầm trên lưu lượng hợp lệ "khó".

**Chế độ của luật, định nghĩa lại** (trước MR21 tài liệu ghi "shadow không tạo cảnh báo" — đúng với rule engine chạy riêng
lúc replay, nhưng sai trên luồng thật, nơi chỉ hybrid tạo cảnh báo; đã đo ở
[`untested-behaviors-measured.md`](untested-behaviors-measured.md)):

- `enforce`: bằng chứng có trọng số + được ép hành động tối thiểu;
- `shadow`: vẫn là bằng chứng có trọng số (theo độ chính xác đã hiệu chỉnh), nhưng **không bao giờ tự ép hành động**;
- `off`: không chạy.

Quản trị viên đổi chế độ ở trang "Cấu hình luật" (MR17); trang này giờ hiện cả hành động tối thiểu của từng luật.

## 3. Đo trước/sau trên cùng kịch bản

Chạy lại 9 kịch bản MR18 ([`attack-scenarios-v2.md`](attack-scenarios-v2.md)), 7 kịch bản bổ sung
([`untested-behaviors-measured.md`](untested-behaviors-measured.md)) và một kịch bản tái hiện E2E TC1 qua **chính pipeline
thật** (DB cô lập, mô hình `hybrid_cp2` thật), trước và sau MR21. "Bước" là lần thử đầu tiên có cảnh báo KHÔNG tính
`ml_anomaly` (tầng 3 gần như luôn kêu với tài khoản mới — xem caveat ở attack-scenarios-v2.md), kèm hành động hybrid cao nhất.

> MR22 phát hiện bộ chạy kịch bản dựng lịch sử nền thiếu bảng thiết bị/vị trí quen, nên số `ml_anomaly` của bảng này không
> đáng tin. Phần không tính `ml_anomaly` (luật, hybrid: số cảnh báo, bước, hành động) đo lại bằng bộ chạy đã sửa thì **giống
> hệt** ở cả 17 kịch bản. Bảng đo lại MR21 và MR22 với bộ chạy đã sửa: [`geo-model-integration.md`](geo-model-integration.md) mục 5.

| Kịch bản | Trước: cảnh báo | Trước: bước · hành động | Sau: cảnh báo | Sau: bước · hành động |
|---|---|---|---|---|
| Rải mật khẩu chậm | ml_anomaly ×18 | chỉ `ml_anomaly` · allow | ml_anomaly ×18 | chỉ `ml_anomaly` · allow |
| Botnet phân tán vào một tài khoản | impossible_travel ×5; ml_anomaly ×6 | 1/8 · allow | hybrid_risk ×2 (impossible_travel); ml_anomaly ×6 | 1/8 · **alert** |
| Proxy cùng quốc gia, khác nhà mạng | ml_anomaly ×1 | chỉ `ml_anomaly` · allow | ml_anomaly ×1 | chỉ `ml_anomaly` · allow |
| Xoay User-Agent | brute_force ×5; high_risk_score ×5; ml_anomaly ×9 | 5/9 · allow | hybrid_risk ×1 (brute_force); ml_anomaly ×9 | 5/9 · **alert** |
| Tài khoản ngủ đông đăng nhập lại | hybrid_risk ×1 (datacenter_ip); ml_anomaly ×1 | 1/1 · alert | hybrid_risk ×1 (datacenter_ip); ml_anomaly ×1 | 1/1 · alert |
| Mô phỏng tinh vi (Targeted mimic) | hybrid_risk ×1 (chỉ ML); ml_anomaly ×1 | 1/1 · alert | hybrid_risk ×1 (chỉ ML); ml_anomaly ×1 | 1/1 · alert |
| Dò danh sách tài khoản | — | — · allow | — | — · allow |
| Nhồi thông tin đăng nhập quy mô lớn | credential_stuffing ×7; hybrid_risk ×6 (credential_stuffing) | 10/16 · alert | hybrid_risk ×6 (credential_stuffing) | 10/16 · alert |
| Di chuyển bất khả thi | hybrid_risk ×1 (impossible_travel); impossible_travel ×1; ml_anomaly ×2 | 2/2 · step_up | hybrid_risk ×1 (impossible_travel); ml_anomaly ×2 | 2/2 · step_up |
| User-Agent là bot | — | — · allow | — | — · allow |
| Nhịp thử đều như máy | brute_force ×6 | 5/10 · allow | hybrid_risk ×1 (brute_force) | 5/10 · **alert** |
| Tor exit node | — | — · allow | — | — · allow |
| IP datacenter | — | — · allow | — | — · allow |
| IP VPN thương mại | — | — · allow | — | — · allow |
| Cùng lúc nhiều quốc gia | hybrid_risk ×1 (impossible_travel); impossible_travel ×1; ml_anomaly ×2 | 2/2 · step_up | hybrid_risk ×1 (impossible_travel); ml_anomaly ×2 | 2/2 · step_up |
| Thử từ nhiều quốc gia | — | — · allow | — | — · allow |
| E2E TC1: 5 lần sai + 1 lần đúng | brute_force ×1; high_risk_score ×2; hybrid_risk ×1 (success_after_failures); ml_anomaly ×6 | 5/6 · step_up | hybrid_risk ×1 (success_after_failures); ml_anomaly ×6 | 5/6 · step_up |

**Kết luận đo:**

- **Không kịch bản nào mất phát hiện, không kịch bản nào phát hiện muộn hơn** (bước đầu tiên giữ nguyên ở cả 17). Không mất
  hành vi vững nào so với bảng 10/25 ([`behavior-coverage-matrix.md`](behavior-coverage-matrix.md), mục "Cập nhật sau MR21").
- Ba kịch bản trước đây chỉ có cảnh báo tầng 1 trong khi hybrid nói "cho qua" (`allow`) — botnet phân tán, xoay User-Agent,
  nhịp đều như máy — giờ có hành động `alert` thật: trước MR21 hai hệ thống đưa ra hai kết luận trái nhau cho cùng một lần thử.
- Số cảnh báo không tính `ml_anomaly` trên 17 kịch bản: **44 → 15** (gộp: dò mật khẩu 5 lần sai trước đây ra 5 alert tầng 1 +
  5 alert tầng 2, giờ ra 1 alert hybrid nhờ chống trùng lặp MR13). MR23 tiếp tục mục tiêu "một sự cố = một cảnh báo".
- Các khoảng trống đã biết **vẫn còn**, không đổi: dò danh sách tài khoản, bot UA, Tor/datacenter/VPN, thử từ nhiều quốc gia
  không có cảnh báo (trọng số 0–5%, không có hành động tối thiểu) — MR25 (mức hành động có số đo báo nhầm) và MR27–MR30.

## 4. Đánh đổi và giới hạn

- **Một đường duy nhất.** Trước đây khối hybrid hỏng thì alert tầng 1 vẫn còn làm dự phòng; giờ không còn. Các thành phần
  của khối (ngữ cảnh đăng nhập, rule engine, mô hình) đều không raise với lỗi thường gặp, khối vẫn được bọc riêng để lỗi không
  làm mất lần đăng nhập đã ghi (`tests/test_pipeline_mr12.py`).
- **Tổ hợp "lệch giờ + vị trí lạ" (20 + 30 = 50, cảnh báo của tầng 2) không còn cảnh báo riêng.** Hai dấu hiệu này vẫn được
  tầng 3 (ML) chấm và cảnh báo `ml_anomaly` như trước; MR22 đưa tầng 3 vào hybrid làm nguồn bằng chứng `ml_geo`
  ([`geo-model-integration.md`](geo-model-integration.md)).
- **Điểm hiển thị của `blocklist_hit`** đổi từ 100 (ghi đè cũ) thành ngưỡng `lock_at` của hồ sơ đang dùng; hành động vẫn là `lock`.
- **Một điểm rủi ro cho mỗi lần đăng nhập:** cột `login_events.risk_score` (trước là điểm cộng tay của tầng 2) giờ chứa đúng
  điểm hybrid, cảnh báo `ml_anomaly` cũng mang điểm đó — bảng log và biểu đồ hiện có tiếp tục hoạt động. Mức low/medium/high
  của bộ lọc nhật ký vẫn là 40/70 (Tuần 4); MR23 gộp hẳn hai cột và đồng bộ các mức với ngưỡng hành động của hybrid.
- Mức hành động tối thiểu là tạm thời, chưa có số đo báo nhầm (MR24–MR25).

## 5. Kiểm thử

- Xoá `test_rules.py`, `test_scoring.py`, `test_rate_counter.py` (mã tầng 1-2 đã xoá). Logic của các luật v2 thay thế đã có
  test riêng từ MR9 (`test_rule_engine_rules.py`). Thêm `test_pipeline_mr21.py` kiểm **qua pipeline thật**, với hồ sơ không có
  mô hình ML để hành động chỉ có thể đến từ luật: 5 lần sai/5 phút → `alert`; cùng 5 lần sai rải 30 phút (thời gian sự kiện) →
  không; `brute_force` chuyển sang shadow → vẫn góp điểm nhưng không ép; nhồi thông tin → `alert`; thành công sau 5 lần sai →
  `step_up`; Hà Nội rồi Mỹ sau 5 phút → cảnh báo kèm toạ độ hai điểm; mọi lần đăng nhập có đúng một điểm.
- `test_hybrid_combine.py`: cơ chế hành động tối thiểu trên sổ luật giả (không phụ thuộc mức đang đặt), cộng một test khoá
  đúng các mức tạm thời của kế hoạch. `test_geo.py`, `test_tier2_baseline.py`: phần còn dùng của mã cũ.
