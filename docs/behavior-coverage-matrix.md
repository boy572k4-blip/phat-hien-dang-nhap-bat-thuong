# Ma trận phủ hành vi (MR19)

Tổng hợp **toàn bộ** hành vi tấn công mà hệ thống có cơ chế nhận diện — từ tầng 1 gốc (Tuần 3), luật tầng 2 (rule
engine v2, MR9), tới hành vi bất thường tầng 3 (ML, Tuần 7 + MR18) — cùng bằng chứng ĐO ĐƯỢC THẬT (không phải suy
đoán) cho từng hàng, lấy từ [`rule-catalog.md`](rule-catalog.md), [`hybrid-risk-engine.md`](hybrid-risk-engine.md),
[`ml-evaluation.md`](ml-evaluation.md), [`attack-scenarios-v2.md`](attack-scenarios-v2.md),
[`model-b-geo-time.md`](model-b-geo-time.md). Mục tiêu: một bảng DUY NHẤT trả lời "hành vi X có được phát hiện
không, bằng gì, đo được tới đâu" — không phải liệt kê tính năng, mà là liệt kê **bằng chứng**.

## Chú giải

- **✅** enforce/đo được, hoạt động như kỳ vọng · **🌓** `shadow` (chạy, ghi nhận, KHÔNG tự tạo alert riêng — vẫn là
  bằng chứng cho hybrid risk engine, MR11) hoặc kết quả mơ hồ · **❌** không có cơ chế / đo được là bỏ sót thật ·
  **—** không áp dụng.
- "Trọng số hybrid" = trọng số hiệu chỉnh của luật đó trong hybrid risk engine (MR11,
  [`hybrid-risk-engine.md`](hybrid-risk-engine.md)) — quyết định luật đó tự đủ tạo alert hybrid_risk hay chỉ là bằng
  chứng phụ. `blocklist_hit` là NGOẠI LỆ: GHI ĐÈ điểm 100 bất kể trọng số.

## Bảng

| Hành vi tấn công | Tầng 1 gốc (Tuần 3) | Luật tầng 2 (MR9) | Tầng 3 ML (Tuần 7 / MR18 "mô hình B") | Bằng chứng đo được thật |
|---|---|---|---|---|
| Dò mật khẩu 1 tài khoản | ✅ `brute_force` (5 lần/5') | ✅ `brute_force` (enforce, trọng số 10,1%) | — | test tích hợp (MR12) |
| Nhồi thông tin đăng nhập | ✅ `credential_stuffing` | ✅ `credential_stuffing` (enforce, trọng số **34,6%** — mạnh nhất) | — | ✅ MR18: phát hiện ở bước 10/16 |
| Rải mật khẩu chậm | ❌ | ✅ `password_spray_slow` (enforce, trọng số 10,2%) | — | ✅ MR18: phát hiện bước 1/18 (qua `ml_anomaly`, xem caveat cold-start ở `attack-scenarios-v2.md`) |
| Dò mật khẩu phân tán (botnet) | ❌ | ✅ `distributed_bruteforce` (enforce, **trọng số 0,0%** — mẫu val chỉ 2 dòng) | — | ⚠️ MR18: chỉ bắt được "TÌNH CỜ" qua `impossible_travel` (IP chọn cách xa nhau) — botnet cùng khu vực địa lý nhiều khả năng LỌT, chưa kiểm chứng trực tiếp |
| Dò danh sách tài khoản (enumeration) | ❌ | ✅ `username_enumeration` (enforce, trọng số 0,05 CHƯA hiệu chỉnh, không luật tầng 1 dự phòng) | — | ❌ MR18: **KHÔNG tạo alert nào** dù vượt hẳn ngưỡng riêng — bỏ sót thật |
| Thành công sau chuỗi sai | — (tầng 2 hành vi cũ dùng risk_score, cơ chế khác) | ✅ `success_after_failures` (enforce, trọng số 0%, mẫu val=40) | — | chưa đo riêng ở MR18 |
| Bot User-Agent | ❌ | ✅ `bot_user_agent` (enforce, chỉ dựa UA — dễ né bằng cách nói dối UA) | — | — |
| Client kịch bản (curl, python-requests...) | ❌ | ✅ `scripted_client` (enforce) | — | script demo `attack-sim/` tự khớp luật này (dùng httpx) |
| Xoay User-Agent | ❌ | ✅ `ua_rotation` (enforce, trọng số 0,05 chưa hiệu chỉnh) | — | ✅ MR18: phát hiện bước 1/9 (qua `brute_force` tầng 1 + `high_risk_score`) |
| Nhịp thử đều như máy | ❌ | 🌓 `regular_rhythm` (**shadow** — chưa kiểm chứng trên log thật) | — | — |
| Tor exit node | ❌ | ✅ `tor_exit` (enforce, cần danh sách công khai) | — | — |
| IP datacenter | ❌ | 🌓 `datacenter_ip` (**shadow** — dễ báo nhầm VPN doanh nghiệp) | — | — |
| VPN thương mại | ❌ | 🌓 `vpn_ip` (**shadow**) | — | — |
| Nguồn trong blocklist | ❌ | ✅ `blocklist_hit` (enforce, **GHI ĐÈ** điểm 100 bất kể trọng số) | — | ✅ MR16: khoá tài khoản/IP THẬT (không chỉ đề xuất), admin mở khoá qua `GET/DELETE /blocklist` |
| Di chuyển bất khả thi | ✅ `impossible_travel` (900km/h) | ✅ `impossible_travel` (enforce) | ✅ `impossible_travel_geo` (MR18, Isolation Forest recall **63,2%**) | ✅ MR18: phát hiện bước 1/2 qua CẢ hai tầng cùng lúc |
| Đăng nhập cùng lúc nhiều quốc gia | ❌ | ✅ `multi_context_simultaneous` (enforce, trọng số 0%, mẫu val=96) | — | bổ sung cho `impossible_travel` khi thiếu toạ độ |
| Tài khoản bị thử nhiều quốc gia (proxy xoay) | ❌ | 🌓 `country_hop` (**shadow**, trọng số 0%) | — | — |
| Tài khoản ngủ đông đăng nhập lại | ❌ | ✅ `dormant_account_login` (enforce, 90 ngày + đổi ngữ cảnh) | ✅ `dormant_reactivation` (MR18, Isolation Forest recall **100%**) | ✅ MR18: phát hiện bước 1/1 |
| Proxy/IP hiếm CÙNG quốc gia | ❌ | 🌓 `rare_network_login` (**shadow**, trọng số 2,6%) | — | 🌓 MR18: **MỘT MÌNH không đủ vượt ngưỡng alert** — trả lời câu hỏi để ngỏ ở `rule-catalog.md` |
| Mô phỏng tinh vi (không luật nào khớp rõ) | ❌ | ❌ (không có luật phù hợp) | 🌓 (chỉ tín hiệu ML yếu, không chắc phân biệt được với tài khoản mới) | 🌓 MR18 `targeted_mimic`: bị gắn cờ nhưng KHÔNG đủ tin cậy để khẳng định là phát hiện đúng kiểu — kết quả mơ hồ tự nó là phát hiện trung thực |
| Giờ đăng nhập lạ | — (risk_score cũ CÓ, cơ chế khác) | ❌ | ✅ `unusual_hour` (recall 58,8%, lần chạy gần nhất — dao động do thiếu random seed cố định) | `ml-evaluation.md`/`model-b-geo-time.md` |
| Vị trí lạ | — (risk_score cũ CÓ) | ❌ | ✅ `unusual_location` (recall 88,9%) | nt |
| Thiết bị lạ | ❌ | ❌ | ✅ `unusual_device` (recall 39,1% — điểm yếu đã biết từ Tuần 7) | nt |
| Đăng nhập dồn dập (rapid fire) | ❌ | ❌ | ✅ `rapid_fire` (**recall 0%** ở lần chạy MR18 — điểm yếu, xem giới hạn thiếu seed) | nt |
| Chiếm tài khoản thật (ATO, dữ liệu RBA) | — | — | — (mô hình `hybrid_cp2` riêng, không phải tầng 3 demo) | ✅ **36,8%** recall @ FPR 1% (38 ca ATO tương lai thật, `ml-evaluation-v2.md`) — mô hình duy nhất có tín hiệu đáng kể là Isolation Forest không giám sát |

## Khoảng trống đã biết (tổng hợp từ toàn bộ MR1-18, không phải mới ở MR19)

Liệt kê TRUNG THỰC — đây là những gì hệ thống **chưa** làm tốt, không che giấu để báo cáo đẹp hơn:

1. **`username_enumeration` không tạo alert được trong thực tế** (MR18) dù luật tự nó khớp đúng — trọng số hybrid
   0,05 mặc định (chưa có dữ liệu val để hiệu chỉnh) không đủ một mình, và đây là hành vi DUY NHẤT trong nhóm "đoán/dò
   mật khẩu" không có luật tầng 1 dự phòng.
2. **`distributed_bruteforce` có trọng số hybrid = 0,0** (mẫu val chỉ 2 dòng khi hiệu chỉnh, MR11) — một botnet dùng
   hạ tầng CÙNG khu vực địa lý (không kích hoạt `impossible_travel` "tình cờ") nhiều khả năng không bị phát hiện.
3. **ATO ở tài khoản CHƯA CÓ lịch sử: 0% recall ở mọi mô hình** (35% số ATO thật của RBA rơi vào nhóm này,
   `ml-evaluation-v2.md` mục 4) — khoảng trống lớn nhất của toàn hệ thống, chưa có hướng giải quyết ngoài "cần dữ
   liệu/luật khác".
4. **`rapid_fire` (tầng 3) yếu** — recall 0-43% tuỳ lần chạy, luôn là một trong hai kiểu yếu nhất từ Tuần 7.
5. **Kẻ tấn công bắt chước hoàn hảo (Targeted, cả IP)** nằm ngoài phạm vi chấm điểm theo thuộc tính đăng nhập —
   giới hạn kiến trúc đã biết từ MR6, không phải thiếu sót có thể vá bằng tinh chỉnh.
6. **5 luật ở chế độ `shadow`** (`regular_rhythm`, `country_hop`, `rare_network_login`, `datacenter_ip`, `vpn_ip`)
   chưa được kiểm chứng đủ trên log thật để bật `enforce` — vẫn là bằng chứng cho hybrid nhưng không tự báo alert
   riêng.
7. **7/9 kịch bản MR18 không dịch được sang dữ liệu tầng 3** (không có đặc trưng IP/ASN/tốc độ ở `ml/features.py`) —
   tầng 3 chỉ "thấy" được phần hành vi địa lý/thời gian của một cuộc tấn công, không thấy phần hạ tầng/tốc độ.

## Cập nhật sau MR19: đã đo 7 hành vi "chưa đo" và rà lại toàn bộ trọng số

Đo trực tiếp qua pipeline thật ([`untested-behaviors-measured.md`](untested-behaviors-measured.md), mã
[`scripts/measure_untested_behaviors.py`](../backend/scripts/measure_untested_behaviors.py)) cho `bot_user_agent`,
`regular_rhythm`, `tor_exit`, `datacenter_ip`, `vpn_ip`, `multi_context_simultaneous`, `country_hop`: **cả 7 luật khớp
đúng logic, nhưng không luật nào tự tạo được cảnh báo** — trọng số hybrid 5% (mặc định, chưa hiệu chỉnh) hoặc 0,0%
(hiệu chỉnh trên mẫu val rất nhỏ). `success_after_failures` khớp trên luồng thật qua trình duyệt
([`e2e-test-report-v2.md`](e2e-test-report-v2.md) TC1-TC2) và được **tầng 2 tự cảnh báo** (+50 điểm) dù luật v2 đóng
góp 0%.

**Rà lại trọng số toàn bộ 19 luật** (`app/detection/hybrid/profiles/rba_calibrated.json`): trong hybrid risk engine,
chỉ **MỘT** luật (`credential_stuffing`, 34,6%) đủ một mình vượt `alert_at=32`. 10 luật dùng trọng số mặc định 5% vì
RBA không đo được chúng (IP giả, không toạ độ, gần như không có UA bot — kể cả `impossible_travel`; `blocklist_hit`
cũng 5% nhưng là luật GHI ĐÈ nên trọng số không quan trọng), 4 luật hiệu chỉnh ra 0,0% do mẫu val quá nhỏ, 4 luật còn
lại hiệu chỉnh được nhưng thấp (`password_spray_slow` 10,2%, `brute_force` 10,1%, `rare_network_login` 2,6%,
`dormant_account_login` 2,5%). Phát hiện "vững" thật sự đến từ tầng 1 (tự cảnh báo độc lập), tầng 2, tầng 3, mô
hình `hybrid_cp2` và luật ghi đè `blocklist_hit` — không đến từ trọng số luật trong hybrid.

Tổng hợp lại 25 hành vi theo "có cảnh báo thật khi kiểm chứng, nhờ tín hiệu nào":

| Nhóm | Số | Hành vi |
|---|---|---|
| Vững (tín hiệu của chính nó đủ cảnh báo, đã đo) | **10** | dò 1 tài khoản, nhồi thông tin, thành công sau chuỗi sai (tầng 2), blocklist, di chuyển bất khả thi, tài khoản ngủ đông (tầng 3), giờ lạ, vị trí lạ, thiết bị lạ (yếu), chiếm tài khoản thật |
| Phụ thuộc hoàn cảnh (có cảnh báo nhưng nhờ tín hiệu khác) | **6** | rải mật khẩu chậm (chỉ qua `ml_anomaly`), botnet phân tán, client kịch bản, xoay UA, nhịp đều như máy, nhiều quốc gia cùng lúc |
| Không cảnh báo | **8** | dò danh sách tài khoản, bot UA, Tor, datacenter, VPN, thử từ nhiều quốc gia, proxy IP hiếm cùng nước, đăng nhập dồn dập |
| Mơ hồ có chủ đích | **1** | `targeted_mimic` |

⚠️ Bản tóm tắt trước đó (nói miệng, ngoài tài liệu) xếp 11 hành vi vào nhóm "vững" — rà lại trọng số cho thấy
`password_spray_slow` (10,2%, chỉ phát hiện qua `ml_anomaly`) và `scripted_client` (5%) không tự cảnh báo được, còn
`success_after_failures` thì có (qua tầng 2). Số đúng là **10**.

## Cập nhật sau MR21: một bộ luật duy nhất

Tầng 1 và bảng cộng điểm của tầng 2 đã xoá ([`rule-unification.md`](rule-unification.md)); hai cột "Tầng 1 gốc" và phần
"tầng 2" trong bảng trên là lịch sử. Đo lại 17 kịch bản qua pipeline thật trước/sau MR21: **không hành vi nào mất phát
hiện hay bị phát hiện muộn hơn**. Số hành vi vững vẫn là **10**, chỉ đổi cơ chế:

| Hành vi vững | Trước MR21 | Sau MR21 |
|---|---|---|
| Dò mật khẩu 1 tài khoản | alert riêng của tầng 1 (+ tầng 2 "+40") | luật `brute_force`, hành động tối thiểu `alert` |
| Nhồi thông tin đăng nhập | tầng 1 + luật v2 (34,6%) | luật `credential_stuffing` (34,6%), tối thiểu `alert` |
| Thành công sau chuỗi sai | tầng 2 (+50) | luật `success_after_failures`, tối thiểu `step_up` |
| Nguồn trong blocklist | ghi đè của hybrid | luật `blocklist_hit`, tối thiểu `lock` |
| Di chuyển bất khả thi | alert riêng của tầng 1 | luật `impossible_travel`, tối thiểu `alert` |
| Tài khoản ngủ đông, giờ lạ, vị trí lạ, thiết bị lạ (yếu) | tầng 3 (ML) | không đổi — tầng 3 (MR22 đưa vào hybrid) |
| Chiếm tài khoản thật (RBA) | mô hình `hybrid_cp2` | không đổi |

Ba hành vi nhóm "phụ thuộc hoàn cảnh" (botnet phân tán, xoay User-Agent, nhịp đều như máy) trước đây có alert tầng 1 trong
khi hybrid quyết định "cho qua"; giờ hybrid ra `alert` thật nhờ luật đi kèm (`impossible_travel`, `brute_force`) — vẫn là
"nhờ tín hiệu khác", nên vẫn thuộc nhóm đó.

## Cập nhật sau MR22: tầng 3 thành nguồn `ml_geo` của hybrid

Tầng 3 không còn alert `ml_anomaly` riêng; nó là nguồn bằng chứng `ml_geo` của hybrid, chỉ chấm tài khoản đã có ≥ 5 lần đăng
nhập thành công ([`geo-model-integration.md`](geo-model-integration.md)). Trên tập test, quyết định cảnh báo của tầng 3
**trùng hoàn toàn** với trước (recall 70,6%, báo nhầm 1,6%; `dormant_reactivation` 100%, `impossible_travel_geo` 66,7%).
MR22 cũng sửa bộ chạy kịch bản: lịch sử nền chưa từng được ghi vào bảng thiết bị/vị trí quen, nên trước đây tầng 3 thấy mọi
tài khoản trong kịch bản là "lạ" — caveat "`ml_anomaly` gần như luôn kêu" ở các mục trên một phần do lỗi đó.

| Thay đổi | Trước MR22 | Sau MR22 |
|---|---|---|
| Tài khoản ngủ đông, giờ lạ, vị trí lạ, thiết bị lạ (yếu) — vẫn **vững** | alert `ml_anomaly` riêng | nguồn `ml_geo` → cảnh báo hybrid; **chỉ** với tài khoản đã có ≥ 5 lần thành công. Kịch bản "ngủ đông" của MR18 (1 lần thành công trước đó) vẫn cảnh báo, nhưng nhờ luật `dormant_account_login` + `datacenter_ip` + `hybrid_cp2` |
| Rải mật khẩu chậm — vẫn **phụ thuộc hoàn cảnh** | chỉ `ml_anomaly`, hybrid "cho qua" | hybrid `alert` ở mọi tài khoản bị thử, nhờ `ml_geo` (IP kẻ tấn công ở thành phố khác), không phải nhờ luật rải mật khẩu |
| Proxy IP hiếm cùng nước: **không cảnh báo → phụ thuộc hoàn cảnh** | chỉ `ml_anomaly` (không tính vì caveat trên) | hybrid `alert` nhờ `ml_geo` — proxy trong kịch bản ở thành phố khác (Huế so với Hà Nội); proxy cùng thành phố sẽ không bị bắt |
| Nhồi thông tin quy mô lớn — vẫn **vững** | `alert` | `step_up` (tầng 3 cộng với các luật) |
| Tài khoản mới hợp lệ | `ml_anomaly` ngay lần đầu | không cảnh báo |

Tổng hợp 25 hành vi: **vững 10** (không đổi), **phụ thuộc hoàn cảnh 7** (+1: proxy cùng nước), **không cảnh báo 7** (dò danh
sách tài khoản, bot UA, Tor, datacenter, VPN, thử từ nhiều quốc gia, đăng nhập dồn dập), **mơ hồ có chủ đích 1**.

## Cập nhật sau MR23: một sự cố = một cảnh báo

MR23 không đổi cơ chế phát hiện nào: trên 20 kịch bản, bước phát hiện đầu tiên và hành động nặng nhất **giống hệt** MR22; số
cảnh báo 44 → 40 (mọi tấn công vào một tài khoản giờ đúng một cảnh báo liệt kê đủ bằng chứng — botnet phân tán 3 → 1, xoay
User-Agent 2 → 1). Tổng hợp giữ nguyên: **vững 10**, phụ thuộc hoàn cảnh 7, không cảnh báo 7, mơ hồ 1
([`incident-unification.md`](incident-unification.md)).

## Cập nhật sau MR25–MR26 (CP5)

MR25 đo trọng số cho các luật RBA không đo được ([`rule-recalibration.md`](rule-recalibration.md)): 10 luật mạnh nay đủ **một
mình** cảnh báo (trọng số 0,57 — trần "một mình chỉ cảnh báo"). Trên 20 kịch bản, luật dẫn đầu của từng kịch bản chính là tín
hiệu của nó: dò danh sách tài khoản (`username_enumeration`), bot UA (`bot_user_agent`), Tor (`tor_exit`), thử từ nhiều quốc gia
(`country_hop`), botnet phân tán (`distributed_bruteforce`), client kịch bản (`scripted_client`), xoay UA (`ua_rotation`), nhịp
đều như máy (`regular_rhythm`, phát hiện từ bước 2 thay vì 5). MR26 ([`vn-recalibration.md`](vn-recalibration.md)) không đổi
phát hiện của kịch bản tấn công nào; kịch bản hợp lệ "theo thói quen" hết bị báo.

Tổng hợp 25 hành vi: **vững 18** (+8), **phụ thuộc hoàn cảnh 3** (rải mật khẩu chậm, nhiều quốc gia cùng lúc, proxy cùng nước),
**không cảnh báo 3** (datacenter, VPN — cố ý, một mình loại IP không đủ cảnh báo; đăng nhập dồn dập), **mơ hồ có chủ đích 1**.

## Cập nhật sau MR27

MR27 ([`behavior-expansion-1.md`](behavior-expansion-1.md)) đo "vững" đúng định nghĩa giai đoạn I trên bộ đánh giá MR24 mở rộng
(phát hiện nhờ chính tín hiệu ≥ 50% biến thể, báo nhầm của chính tín hiệu ≤ 1% lần thử hợp lệ): **14/18** hành vi đo được trên bộ dữ
liệu là vững. Thay đổi so với CP5: **rải mật khẩu chậm** thành vững (điều kiện tỉ lệ thành công + hành động tối thiểu ở phạm vi IP);
**đăng nhập dồn dập** thành vững (luật mới `success_burst`, ≥ 8 lần thành công/10 phút — kiểu `rapid_fire` 3–4 lần cũ không coi là tấn
công); thêm hành vi **botnet phân tán cùng khu vực** (IP Việt Nam) — vững (83%).

Tổng hợp 26 hành vi: **vững 21**, **phụ thuộc hoàn cảnh 2** (nhiều quốc gia cùng lúc, proxy cùng nước), **không cảnh báo 2** (datacenter,
VPN — cố ý), **mơ hồ có chủ đích 1**. ⚠️ "Dò mật khẩu một tài khoản" và "thành công sau chuỗi sai" vững theo định nghĩa gộp nhưng với riêng
họ "quên mật khẩu" báo nhầm 11–14% (đếm số lần sai không phân biệt được).

## Cập nhật sau MR28

MR28 ([`behavior-expansion-2.md`](behavior-expansion-2.md)) thêm 3 hành vi: **đoán mã OTP liên tục** — vững (83%, 0% báo nhầm, luật
`otp_guessing` → khoá); **cố đăng nhập khi đang bị khoá** — vững (83%, 0%, `blocked_retry` → xác thực thêm khi hết khoá); **một IP đăng
nhập thành công vào nhiều tài khoản** — phụ thuộc hoàn cảnh (luật `multi_account_success` chỉ là bằng chứng: phòng máy đào tạo trông giống
hệt; kẻ tấn công vẫn bị bắt 100% nhờ tín hiệu khác). 16/21 hành vi đo được trên bộ dữ liệu vững.

Tổng hợp 29 hành vi: **vững 23**, **phụ thuộc hoàn cảnh 3** (nhiều quốc gia cùng lúc, proxy cùng nước, một IP vào nhiều tài khoản),
**không cảnh báo 2** (datacenter, VPN — cố ý), **mơ hồ có chủ đích 1**.

## Nguồn dữ liệu

Mọi con số trong bảng lấy TRỰC TIẾP từ tài liệu đã dẫn — không tính lại riêng cho bảng này. `[Đo được thật]` nghĩa là
có ít nhất một lần chạy qua CHÍNH pipeline thật (không phải suy luận từ thiết kế); ô để trống (`—`) ở cột cuối nghĩa
là cơ chế tồn tại nhưng chưa có phép đo chuyên biệt bằng kịch bản mô phỏng (khác với luật không được kích hoạt).
