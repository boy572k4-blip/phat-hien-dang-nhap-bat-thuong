# Đo 7 hành vi còn "chưa đo" (bổ sung sau MR19)

> **Ghi chép theo thời điểm (sau MR19)** — mô tả và số đo lúc đó, giữ để truy vết; hệ thống đã thay đổi ở các MR sau (đến MR36). Bản hiện hành: [`architecture.md`](architecture.md) · mục lục tài liệu: [`README.md`](README.md).

> **Ảnh chụp kết quả TRƯỚC MR21** (còn tầng 1 và tầng 2). Sau MR21 hai tầng đó đã gộp vào rule engine v2 — so sánh trước/sau trên đúng các kịch bản này: [`rule-unification.md`](rule-unification.md) mục 3. Chạy lại script để có kết quả hiện tại.
>
> **MR22:** tầng 3 không còn alert `ml_anomaly` (thành nguồn `ml_geo` của hybrid); bộ chạy kịch bản dùng chung đã sửa cách dựng lịch sử nền — đo lại: [`geo-model-integration.md`](geo-model-integration.md) mục 5–6.

Người dùng yêu cầu kiểm chứng trực tiếp (không chỉ đọc mã) cho 7 hành vi còn đánh dấu "chưa đo" ở [`behavior-coverage-matrix.md`](behavior-coverage-matrix.md). Dùng lại NGUYÊN hạ tầng kịch bản thật của MR18 (`ml/attack_scenarios.py` + `scripts/attack_scenario_runner.py`) — không phải MR mới, không đổi checklist.

Mỗi hành vi đo HAI điều khác nhau: **(1) luật có khớp không** (gọi thẳng rule engine, record=False, trả lời đúng câu hỏi "logic luật đúng không" bất kể enforce/shadow) và **(2) có tạo alert nhìn thấy được không** (qua pipeline thật, MR12). Với luật `shadow`, (1)=có và (2)=không là kết quả **ĐÚNG THEO THIẾT KẾ**, không phải thất bại — shadow chỉ góp bằng chứng cho hybrid risk engine, không tự báo alert riêng (đã xác nhận cho `rare_network_login` ở MR18).

| Hành vi | Luật | Luật có khớp? | Trọng số hybrid | Có alert? | Cơ chế alert thật sự (nếu có) |
|---|---|---|---|---|---|
| User-Agent là bot | `bot_user_agent` | ✅ Có | 5.0% (mặc định CHƯA hiệu chỉnh) | ➖ | — |
| Nhịp thử đều như máy | `regular_rhythm` | ✅ Có | 5.0% (mặc định CHƯA hiệu chỉnh) | ✅ | brute_force |
| Đăng nhập từ Tor exit node | `tor_exit` | ✅ Có | 5.0% (mặc định CHƯA hiệu chỉnh) | ➖ | — |
| Đăng nhập từ dải IP datacenter | `datacenter_ip` | ✅ Có | 5.0% (mặc định CHƯA hiệu chỉnh) | ➖ | — |
| Đăng nhập từ dải IP VPN thương mại | `vpn_ip` | ✅ Có | 5.0% (mặc định CHƯA hiệu chỉnh) | ➖ | — |
| Đăng nhập cùng lúc từ nhiều quốc gia | `multi_context_simultaneous` | ✅ Có | 0.0% (hiệu chỉnh, mẫu=96) | ✅ | hybrid_risk (rule=impossible_travel); impossible_travel; ml_anomaly |
| Tài khoản bị thử từ nhiều quốc gia | `country_hop` | ✅ Có | 0.0% (hiệu chỉnh, mẫu=58) | ➖ | — |

## Tóm tắt: 7/7 luật khớp đúng với kịch bản dàn dựng

**Cả 7 luật đều khớp đúng logic** — không có bug nào trong RULE LOGIC bản thân chúng. Nhưng chỉ **2/7 kịch bản có alert nhìn thấy**, và quan trọng: **cả 2 lần alert đó đều KHÔNG phải do luật đang đo**, mà do một luật KHÁC cùng khớp (`brute_force`, `impossible_travel` — xem cột "Cơ chế alert thật sự"):

- **`bot_user_agent`**: chưa có dữ liệu val để hiệu chỉnh, dùng trọng số mặc định **5%** — một mình cho điểm hybrid ~5/100, xa ngưỡng `alert_at=32`. Cùng tình trạng với `username_enumeration` (MR18).
- **`regular_rhythm`**: chưa có dữ liệu val để hiệu chỉnh, dùng trọng số mặc định **5%** — một mình cho điểm hybrid ~5/100, xa ngưỡng `alert_at=32`. Cùng tình trạng với `username_enumeration` (MR18).
- **`tor_exit`**: chưa có dữ liệu val để hiệu chỉnh, dùng trọng số mặc định **5%** — một mình cho điểm hybrid ~5/100, xa ngưỡng `alert_at=32`. Cùng tình trạng với `username_enumeration` (MR18).
- **`datacenter_ip`**: chưa có dữ liệu val để hiệu chỉnh, dùng trọng số mặc định **5%** — một mình cho điểm hybrid ~5/100, xa ngưỡng `alert_at=32`. Cùng tình trạng với `username_enumeration` (MR18).
- **`vpn_ip`**: chưa có dữ liệu val để hiệu chỉnh, dùng trọng số mặc định **5%** — một mình cho điểm hybrid ~5/100, xa ngưỡng `alert_at=32`. Cùng tình trạng với `username_enumeration` (MR18).
- **`multi_context_simultaneous`**: trọng số hiệu chỉnh = **0,0%** (mẫu val chỉ 96 dòng) — một mình KHÔNG BAO GIỜ đủ vượt ngưỡng `alert_at=32`, dù khớp hoàn hảo. Cùng tình trạng với `distributed_bruteforce` (MR18).
- **`country_hop`**: trọng số hiệu chỉnh = **0,0%** (mẫu val chỉ 58 dòng) — một mình KHÔNG BAO GIỜ đủ vượt ngưỡng `alert_at=32`, dù khớp hoàn hảo. Cùng tình trạng với `distributed_bruteforce` (MR18).

⚠️ **Phát hiện đúng ra ngoài câu hỏi ban đầu**: khi đọc mã mới nhận ra `app/detection/hybrid/combine.py` (dòng 10-12) ghi "chế độ shadow chỉ quyết định RuleEngine có tự tạo cảnh báo hay không" — nhưng đọc `app/detection/engine/engine.py::evaluate()` thì KHÔNG thấy RuleEngine tự tạo cảnh báo ở đâu cả (chỉ trả `Evaluation.hits`); alert DUY NHẤT được tạo ở `pipeline.py` dựa trên điểm HYBRID tổng hợp, áp dụng GIỐNG HỆT cho hit từ luật enforce lẫn shadow. Nói cách khác: **trên luồng `/login` thật, enforce/shadow KHÔNG quyết định được có alert hay không — chỉ trọng số hiệu chỉnh mới quyết định** (shadow và enforce với trọng số thấp cho kết quả giống hệt nhau về mặt alert). Phân biệt enforce/shadow có ý nghĩa cho công cụ tinh chỉnh/replay ngoại tuyến (MR10), không phải cho hành vi runtime của `/login`. Không sửa gì (ngoài phạm vi yêu cầu đo), chỉ ghi nhận để tài liệu không còn gây hiểu nhầm nếu đọc riêng docstring mà không đối chiếu code.

## Giới hạn của phép đo này

- Mỗi kịch bản chạy **đúng 1 lần**, tham số dàn dựng để vượt HẲN ngưỡng (không sát biên) — không đo độ nhạy ở biên.
- Kết quả "luật có khớp" xác nhận LOGIC đúng trên một kịch bản cụ thể, không phải tỉ lệ phát hiện trên nhiều biến thể.
- IP công khai thật (Tor/datacenter/VPN lấy trực tiếp từ `backend/threat_intel/`), không phải hạ tầng tấn công thật.

