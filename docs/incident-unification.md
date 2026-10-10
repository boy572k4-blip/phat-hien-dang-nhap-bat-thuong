# Một sự cố = một cảnh báo, một điểm rủi ro (MR23)

> **Ghi chép theo thời điểm (MR23)** — mô tả và số đo lúc đó, giữ để truy vết; hệ thống đã thay đổi ở các MR sau (đến MR36). Bản hiện hành: [`architecture.md`](architecture.md) · mục lục tài liệu: [`README.md`](README.md).

Sau MR21 (một bộ luật) và MR22 (một lớp ML), một lần đăng nhập đã chỉ có **một** điểm và **một** hành động — nhưng dữ liệu
và giao diện vẫn mang dấu vết của năm cơ chế cũ: hai cột điểm song song trên `login_events`, cột `alert_type` với sáu giá
trị mà chỉ còn một được tạo, chống trùng lặp theo họ tấn công nên một cuộc tấn công đổi kiểu giữa chừng vẫn ra nhiều cảnh
báo, bản đồ chỉ vẽ được đường bay từ payload WebSocket. MR23 dọn nốt phần đó và viết lại `pipeline.py` theo đúng năm bước
của kiến trúc.

Mã: [`app/detection/pipeline.py`](../backend/app/detection/pipeline.py),
[`app/detection/alert_intelligence.py`](../backend/app/detection/alert_intelligence.py) (`Incident`),
migration [`7d2c1e5a9b30`](../backend/alembic/versions/7d2c1e5a9b30_mr23_one_incident_one_score.py), frontend
[`services/risk.js`](../frontend/src/services/risk.js) và các khu vực dashboard.

## 1. Pipeline năm bước, mỗi khối một SAVEPOINT

| Bước | Hàm | Việc |
|---|---|---|
| 1. Ghi lần thử + ngữ cảnh | `_record_attempt`, `build_login_context` | GeoIP, ASN, User-Agent; lịch sử tài khoản/IP/ASN dựng MỘT lần (MR20) |
| 2. Luật | `build_rule_engine(...).evaluate` | 19 luật v2; luật xác định mang hành động tối thiểu (MR21) |
| 3. Mô hình | `_score_models` | `hybrid_cp2` + mô hình địa lý-thời gian (`ml_geo`, chỉ khi qua cổng cold-start — MR22) |
| 4. Gộp điểm | `_combine` | một điểm 0–100 + một hành động; ngưỡng riêng của tài khoản nếu có (MR15) |
| 5. Hành động | `_raise_incident`, `_respond`, `_correlate_campaign` | một sự cố = một cảnh báo; step_up/lock (MR16); chiến dịch (MR14) |

Lần đăng nhập thành công cập nhật hồ sơ tài khoản (baseline giờ, thiết bị/vị trí quen) **sau** khi chấm — chỉ đặc trưng của
mô hình địa lý-thời gian đọc các bảng đó và phải thấy hồ sơ *trước* lần này.

**SAVEPOINT** (nợ từ MR20): trên Postgres một lệnh SQL lỗi làm hỏng cả giao dịch; try/except quanh từng khối không cứu được
— lần commit cuối vẫn lỗi và mất luôn lần thử đã ghi. Mỗi khối (chấm điểm và cảnh báo, chiến dịch, hồ sơ tài khoản) giờ
chạy trong `db.begin_nested()`: lỗi chỉ huỷ phần việc của khối đó; không còn trạng thái nửa vời kiểu "có điểm mà không có
cảnh báo". Lỗi thật đầu tiên mà cơ chế này chặn được ở mục 5 (lỗi #2).

## 2. Một sự cố = một cảnh báo

Sự cố là chuỗi lần thử bị đánh giá khác `allow` của **cùng tài khoản** (hoặc **cùng IP** khi tên đăng nhập không tồn tại), mỗi
lần cách lần trước không quá **15 phút** — cửa sổ **trượt** theo `last_seen_at`, và **không** phụ thuộc họ tấn công.

| | Trước MR23 (MR13) | Từ MR23 |
|---|---|---|
| Khoá gộp | tài khoản/IP **+ họ tấn công** | tài khoản/IP |
| Cửa sổ | 15 phút tính từ lần **đầu tiên** | 15 phút tính từ lần **gần nhất**, chặn cả hai phía |
| Điểm / hành động của cảnh báo | điểm lớn nhất / hành động nặng nhất | như cũ |
| Bằng chứng | đóng góp của lần thử **cuối** | **hợp** của mọi lần thử (mỗi nguồn giữ trọng số lớn nhất) + chi tiết từng luật |
| Họ tấn công, `rule_id` | của lần thử cuối | của lần thử **quyết định** (điểm cao nhất); luật đã ép hành động được ưu tiên |

Trạng thái sự cố nằm ngay trong hàng `Alert` (`explanation`: `contributions`, `action`, `forced_by`, `lead_rule`,
`evidence`) — không thêm bảng. `evidence` lưu chi tiết của mọi luật đã khớp, gồm **hai đầu đường bay** của di chuyển bất khả
thi, nên bản đồ vẽ lại được cả sau khi tải lại trang. Nhiều tài khoản bị nhắm từ cùng hạ tầng vẫn là nhiều cảnh báo (mỗi chủ
tài khoản một sự cố, step_up/lock theo từng tài khoản) và được gom thành **chiến dịch** (MR14).

Phản hồi tự động chỉ ghi khi sự cố mới hoặc hành động vừa tăng (như MR13). Lần thử mật khẩu đúng có hành động `step_up` vẫn
luôn bị đòi OTP — hành động của **lần thử** quyết định response HTTP, không phải của sự cố.

## 3. Một điểm, một loại cảnh báo (migration `7d2c1e5a9b30`)

- **Xoá** `login_events.risk_score` (điểm cộng tay của tầng 2; từ MR21 chỉ là bản sao điểm hybrid) và
  `login_events.ml_anomaly_score` (tầng 3; từ MR22 là nguồn `ml_geo` bên trong điểm hybrid). Điểm duy nhất:
  `hybrid_risk_score` + `hybrid_action`.
- **Xoá** `alerts.alert_type`. 2.239 cảnh báo cũ của dev DB giữ loại gốc trong `explanation.legacy_alert_type`
  (`ml_anomaly` 1.876, `credential_stuffing` 198, `brute_force` 111, `high_risk_score` 50, `impossible_travel` 4); cảnh báo
  tầng 1 cũ chưa có `rule_id` nhận mã luật v2 cùng tên.
- Chỉ mục tra sự cố đang mở `(user_id, status, last_seen_at)` thay cho `(user_id, attack_family, status)`.
- **Đã chạy trên Postgres dev** (sau khi sao lưu) và **kiểm tra hai chiều**: nâng cấp → hạ cấp → bảng `alerts` (loại, `rule_id`,
  `explanation`) và chỉ mục **trùng khớp từng byte** với bản sao lưu trước nâng cấp. Hạ cấp không khôi phục được điểm tầng 2
  cũ hơn MR21 và `ml_anomaly_score` (đã ghi trong docstring migration).

API: `GET /login-events` lọc theo `action` (allow/alert/step_up/lock — hành động **đã lưu**, đã gồm ngưỡng riêng MR15 và hành
động tối thiểu MR21) thay cho mức low/medium/high theo ngưỡng cứng 40/70 của Tuần 4, và trả kèm `action_bands` (ngưỡng đang
dùng); `AlertOut`, payload WebSocket và dòng thời gian chiến dịch không còn `alert_type`. Payload WebSocket có cùng trường với
`AlertOut` để dashboard thay đúng hàng của sự cố.

Dashboard: bảng log và biểu đồ dùng một điểm (biểu đồ trước đó vẽ điểm tầng 2 trong khi cảnh báo dùng điểm hybrid) và kẻ đúng
ngưỡng alert/step_up/lock của hồ sơ; danh sách cảnh báo hiện họ tấn công, hành động nặng nhất, số lần thử và **toàn bộ bằng
chứng** (mở/gọn được); cập nhật real-time thay hàng của sự cố thay vì chèn hàng trùng; bản đồ đọc đường bay từ bằng chứng đã
lưu. Đã kiểm tra trên trình duyệt với một bản sao DB dev (xoá sau kiểm tra): tấn công thử alice từ Hà Nội rồi Mỹ (6 lần sai)
ra **một** cảnh báo liệt kê 5 bằng chứng (mô hình địa lý-thời gian, `hybrid_cp2`, dò mật khẩu, di chuyển bất khả thi 13.027 km,
IP datacenter), bản đồ vẽ đường bay sau khi tải lại trang, lần thử thứ 7 cập nhật đúng hàng đó (7 lần thử).

## 4. Đo trước/sau (CP4)

**Kịch bản** — 17 kịch bản tấn công + 3 hợp lệ, qua pipeline thật, cùng mô hình, cùng bộ chạy (cột: bước phát hiện đầu tiên ·
hành động nặng nhất · số cảnh báo):

| Kịch bản | MR22 | MR23 |
|---|---|---|
| Rải mật khẩu chậm (18 tài khoản) | 1/18 · alert · 17 | 1/18 · alert · 17 |
| Botnet phân tán vào một tài khoản | 1/8 · alert · **3** | 1/8 · alert · **1** |
| Proxy cùng quốc gia, khác nhà mạng | 1/1 · alert · 1 | 1/1 · alert · 1 |
| Xoay User-Agent | 1/9 · alert · **2** | 1/9 · alert · **1** |
| Tài khoản ngủ đông đăng nhập lại | 1/1 · alert · 1 | 1/1 · alert · 1 |
| Mô phỏng tinh vi | 1/1 · alert · 1 | 1/1 · alert · 1 |
| Dò danh sách tài khoản | — · allow · 0 | — · allow · 0 |
| Nhồi thông tin quy mô lớn (nhiều tài khoản) | 1/16 · step_up · **13** | 1/16 · step_up · **12** |
| Di chuyển bất khả thi | 2/2 · step_up · 1 | 2/2 · step_up · 1 |
| Bot UA / Tor / datacenter / VPN / thử từ nhiều quốc gia | — · allow · 0 | — · allow · 0 |
| Nhịp thử đều như máy | 5/10 · alert · 1 | 5/10 · alert · 1 |
| Cùng lúc nhiều quốc gia | 2/2 · step_up · 1 | 2/2 · step_up · 1 |
| **E2E TC1: 5 lần sai + 1 lần đúng** | 5/6 · step_up · 1 | 5/6 · step_up · **1** (`success_after_failures`, đủ bằng chứng) |
| Hợp lệ: tài khoản mới / theo thói quen / điện thoại mới ở thành phố khác | 0 / 1 / 1 cảnh báo | 0 / 1 / 1 cảnh báo |

- **Không kịch bản nào đổi bước phát hiện hay hành động nặng nhất.** Tổng số cảnh báo **44 → 40**; mọi tấn công vào **một**
  tài khoản giờ đúng **1** cảnh báo. Tấn công nhiều tài khoản vẫn một cảnh báo cho mỗi tài khoản, gom thành chiến dịch.
- **Hành vi vững: vẫn 10/25** — MR23 không đổi cơ chế phát hiện nào ([`behavior-coverage-matrix.md`](behavior-coverage-matrix.md)).
- E2E TC1 được kiểm qua pipeline thật trên DB cô lập (kịch bản dùng chính `user020`) và `test_pipeline_mr23.py`; chạy lại E2E
  trên trình duyệt với `user020` của DB dev để MR34 (tránh tự khoá tài khoản demo giữa chừng).

**Độ trễ** — thời gian chạy pipeline trong tiến trình (ms, trung vị / p95, 30 lần/khối lượng, bỏ 2 lần đầu), trên MỘT bản sao
DB dev dùng chung cho cả hai phiên bản (mọi thay đổi rollback), hai lượt xen kẽ:

| Khối lượng | MR22 lượt 1 | MR23 lượt 1 | MR22 lượt 2 | MR23 lượt 2 |
|---|---|---|---|---|
| alice (lịch sử ~1,4 nghìn lần), IP Việt Nam | 105,6 / 113,7 | 106,9 / 119,1 | 117,3 / 128,9 | 119,1 / 130,6 |
| alice, 127.0.0.1 | 103,8 / 111,4 | 106,9 / 123,2 | 118,0 / 129,4 | 118,0 / 141,0 |
| tài khoản mới, IP Việt Nam | 87,3 / 103,8 | 102,7 / 126,7 | 116,6 / 137,0 | 116,9 / 126,1 |
| dò mật khẩu alice (thất bại, có cảnh báo) | 95,7 / 107,9 | 108,8 / 128,0 | 116,7 / 127,9 | 119,6 / 134,8 |

Chênh lệch giữa hai phiên bản trong cùng lượt là 0–15 ms, nằm trong biên dao động giữa hai lượt (lượt 2 chậm hơn lượt 1 khoảng
12 ms ở **cả hai** phiên bản): **không đo được thay đổi độ trễ** do MR23. Ba SAVEPOINT mỗi lần thử chỉ thêm vài lượt hỏi đáp
cục bộ. Không đo lại qua HTTP: phần ngoài pipeline (bcrypt ~230 ms) không đổi.

## 5. Lỗi tìm ra khi làm MR23

1. **Lệch đặc trưng train/serve của mô hình địa lý-thời gian, có từ Tuần 7.** Pipeline ghi lần thử hiện tại *trước* khi tính
   đặc trưng, còn truy vấn "lần thành công gần nhất" thiếu chặn `created_at < bây giờ` — nên với mọi lần đăng nhập
   **thành công** trên luồng thật, `minutes_since_last_login` = 0 (lúc train là khoảng cách thật; lần đầu của tài khoản lẽ ra
   là 1.440). Mô hình vì thế không thể thấy "im lặng lâu ngày" trên luồng thật. Test cũ không lộ vì không ghi lần thử hiện tại
   trước khi tính. Đã sửa (`ml/features.py`) và thêm test **so khớp đặc trưng thật với đặc trưng train** trên cùng một chuỗi
   đăng nhập (9 đặc trưng, mọi lần) — test này thất bại trên mã cũ.
2. **Tên họ tấn công của MR22 dài 67 ký tự, cột chỉ 64.** Postgres từ chối ghi cảnh báo; ở MR22 lỗi đó làm hỏng cả giao dịch:
   lần đăng nhập **thành công** mà mô hình địa lý-thời gian dẫn đầu sẽ trả **lỗi 500**. Test chạy SQLite (không kiểm độ dài
   VARCHAR) nên không thấy — lộ ra khi đo độ trễ trên Postgres. Đã rút gọn và thêm test kiểm mọi tên họ có thể sinh ra vừa cột.
3. **Cửa sổ sự cố thiếu chặn trên.** Một lần thử đến trễ hoặc ghi lùi ngày (đồng thời, nạp lại) đã gộp vào cảnh báo xảy ra sau
   nó nhiều tháng. Đã chặn hai phía và không cho lần thử đến trễ kéo lùi `last_seen_at`; có test.
4. **Họ tấn công và `rule_id` có thể "đá nhau"** từ MR21: `rule_id` lấy luật đã ép hành động, họ tấn công lấy bằng chứng trọng
   số cao nhất (các luật cùng 5% mặc định thì theo thứ tự sổ đăng ký) — một lần thử bị khoá vì blocklist mang họ "dò mật
   khẩu". Giờ cả hai cùng theo luật đã ép hành động.
5. **Cách ly test**: một test gọi `monkeypatch.undo()` giữa chừng (để gỡ lỗi giả lập) gỡ luôn patch của fixture, nên lần thử
   sau của test **ghi vào Postgres/Redis dev thật** (1 lần thử, 1 phản hồi, 1 nhật ký, 1 mục khoá đã hết hạn, sửa 1 cảnh báo có
   sẵn). Đã xoá và **khôi phục từng cột từ bản sao lưu** (đối chiếu số dòng mọi bảng với bản sao lưu), sửa test, và thêm lưới
   an toàn cho cả bộ test (`conftest.never_touch_dev_services`): engine Postgres dev từ chối mọi kết nối, client Redis dev bị
   thay bằng đối tượng báo lỗi — rơi về dịch vụ thật thì test **fail ngay**. Lưới này lộ thêm `test_health`: từ Tuần 1 test đó
   gọi thẳng Postgres dev (cần Docker đang chạy) — đã chuyển sang DB SQLite của fixture, thêm ca DB không kết nối được.

## 6. Giới hạn

- Hai lần thử **đồng thời** của cùng một sự cố mới có thể cùng không thấy sự cố đang mở và tạo hai cảnh báo (không khoá hàng);
  hiếm, chấp nhận ở quy mô đồ án.
- Cửa sổ 15 phút vẫn là hằng số tự chọn từ MR13, chưa đối chiếu với dữ liệu tấn công thật.
- Cảnh báo cũ hơn MR23 không có bằng chứng chi tiết (chỉ `legacy_alert_type`), không gộp được với sự cố mới.
- Kết quả kịch bản ở mục 4 đã gồm sửa lỗi #1; số lần thử bị mô hình địa lý-thời gian gắn cờ trong 20 kịch bản **không đổi** so
  với MR22 (các kịch bản này ít phụ thuộc khoảng cách thời gian). Số đo trên tập test của mô hình (MR22) là offline, không bị
  lỗi #1 ảnh hưởng; ảnh hưởng thật của lỗi #1 là trên luồng sống với "im lặng lâu ngày" — chưa có kịch bản riêng đo phần đó.

## 7. Kiểm thử

- `test_pipeline_mr23.py` (qua pipeline thật): E2E TC1 = đúng 1 cảnh báo đủ bằng chứng; đổi kiểu tấn công giữa chừng vẫn 1
  sự cố; cửa sổ trượt (tấn công chậm 1 giờ = 1 cảnh báo, nghỉ 16 phút = sự cố mới); sự cố đã xử lý không bị mở lại; lần thử
  ghi lùi ngày không gộp vào sự cố tương lai; lỗi SQL sau khi đã ghi cảnh báo không để lại trạng thái nửa vời; khối chiến dịch
  hỏng không làm mất cảnh báo; payload WebSocket cùng trường với API.
- `test_alert_intelligence.py`: `Incident` (đỉnh điểm, hành động chỉ tăng, hợp bằng chứng, lần thử quyết định, dựng lại từ hàng
  `Alert`, cảnh báo cũ), bằng chứng JSON-an toàn, họ theo luật đã ép, độ dài tên họ.
- `test_ml_features.py`: so khớp đặc trưng thật/train. `test_events_filter.py`: lọc theo hành động, `action_bands`, một điểm.
- 23 test pipeline MR12–MR15 và các test router/feedback sửa theo luồng mới (không còn `alert_type`, cột điểm cũ).
