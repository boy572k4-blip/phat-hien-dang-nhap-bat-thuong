# MR31 — Kiểm chứng phương pháp trên log xác thực thật (LANL)

> **Đây là kiểm chứng PHƯƠNG PHÁP, không phải kiểm thử hệ thống.** LANL là log đăng nhập Windows của một mạng nội bộ (Kerberos/NTLM,
> máy nguồn → máy đích), khác cấu trúc với log đăng nhập web của đồ án; mã ở `backend/ml/lanl/` KHÔNG nối vào `/login`. Câu hỏi được trả
> lời: cách tiếp cận của hệ thống — đặc trưng "mới với chính tài khoản", đếm trong cửa sổ thời gian, Isolation Forest không giám sát, luật
> đơn giản — có tách được tấn công THẬT (do red team thực hiện, có nhãn) khỏi hoạt động thật của hàng nghìn người dùng hay không, trên dữ
> liệu nhóm không tự tạo ra.

## 1. Dữ liệu

- **Nguồn:** "Comprehensive, Multi-Source Cyber-Security Events", A. D. Kent, Los Alamos National Laboratory, 2015,
  doi:10.17021/1179829. Tải sau khi đăng ký trên trang của LANL; chỉ tải hai tệp `auth.txt.gz` (7,6 GB nén) và `redteam.txt.gz`.
  Dữ liệu KHÔNG đưa vào git (`.gitignore`: `backend/ml/data/lanl/`).
- **Quy mô:** 58 ngày; ~1,05 tỉ sự kiện xác thực. Sau khi chỉ giữ tài khoản người dùng (`U…@…`, bỏ tài khoản máy `C…$`, `SYSTEM`,
  `ANONYMOUS LOGON`…): 341.692.445 sự kiện, 12.414 người dùng; trong đó **125.885.289 lần đăng nhập** (`LogOn`) của 11.270 người dùng.
- **Nhãn:** `redteam.txt` — 749 dòng (715 bộ (thời điểm, người dùng, máy nguồn, máy đích) khác nhau, 98 người dùng). Một sự kiện được gán
  nhãn tấn công khi trùng đúng bộ bốn đó; **702 lần đăng nhập** khớp (316 ở ngày 1–12, 386 ở ngày 13–58). Nhãn chỉ dùng để ĐO, không dùng
  để học.

## 2. Cách làm

| Bước | Mã | Chi tiết |
|---|---|---|
| ETL | `ml/lanl/etl.py` | DuckDB đọc luồng tệp nén một lượt (không giải nén ra đĩa), ghi parquet; 209 s |
| Lấy mẫu | `ml/lanl/features.py` | MỌI người dùng có sự kiện red team + 20% người dùng còn lại (chọn bằng băm tên, tái lập được), trọng số 5 cho nhóm lấy mẫu — giống cách lấy mẫu RBA ở MR2; 28.366.703 lần đăng nhập, 2.374 người dùng |
| Đặc trưng | `ml/lanl/features.py` | Sắp xếp một lần theo (người dùng, thời điểm), đọc tuần tự và dựng lịch sử từng tài khoản — chỉ dùng QUÁ KHỨ của tài khoản, không rò rỉ tương lai; 1.468 s |
| Đánh giá | `ml/lanl/evaluate.py` | ~270 s, ghi `ml/artifacts/lanl/evaluation.json` |

**Đặc trưng** (mỗi lần đăng nhập) và tương ứng trong hệ thống đồ án:

| Đặc trưng LANL | Ý nghĩa | Tương ứng trong hệ thống |
|---|---|---|
| `new_src` | máy nguồn chưa từng dùng | thiết bị mới |
| `new_dst` | máy đích chưa từng vào | vị trí mới |
| `new_auth`, `new_logon` | kiểu xác thực / kiểu đăng nhập mới | User-Agent mới |
| `hour_rarity` | giờ hiếm với tài khoản | lệch giờ quen |
| `events_1h` | số lần đăng nhập trong 1 giờ | tốc độ (`u_attempts_1h`) |
| `new_dst_1h` | số máy đích MỚI trong 1 giờ | (không có trong web) — dấu hiệu di chuyển ngang |
| `fails_1h` | số lần thất bại trong 1 giờ | luật dò mật khẩu |
| `log_prior` | độ dày lịch sử | cổng cold-start |

**Bộ chấm điểm** (không giám sát, điểm cao = bất thường hơn):

- `isolation_forest` — Isolation Forest (200 cây, tham số mặc định, `random_state=0`) học trên 1.000.000 lần đăng nhập lấy ngẫu nhiên
  của ngày 1–12; cùng họ mô hình với thành phần bất thường của `hybrid_cp2` và mô hình địa lý–thời gian của hệ thống.
- `novelty_count` — tổng bốn cờ "mới" (`new_src + new_dst + new_auth + new_logon`): baseline kiểu luật, không học.
- Từng đặc trưng một, để biết tín hiệu nào thật sự mang thông tin.

**Cách chia và chỉ số — theo Tuor et al. 2018** (arXiv:1712.00557, công trình hay được trích trên đúng bộ dữ liệu này):

- Ngày 1–12 là giai đoạn phát triển (mô hình học ở đây), **ngày 13–58 là tập kiểm tra**.
- Hai mức: **từng sự kiện**, và **user-ngày** (điểm của một người dùng trong một ngày = điểm cao nhất trong ngày, như bài báo). User-ngày
  có tấn công: 57 ở giai đoạn phát triển, 119 ở tập kiểm tra.
- Bài báo bỏ cuối tuần và ngày lễ. Dữ liệu đã ẩn ngày tháng nên nhận ra từ số lần đăng nhập mỗi ngày: số liệu có chu kỳ 7 ngày rõ ràng,
  cuối tuần = hai "thứ" có trung bình thấp nhất, ngày lễ = ngày thường dưới 70% trung vị ngày thường. Kết quả: 16 ngày cuối tuần
  (4–5, 11–12, …, 53–54) và hai ngày lễ (20, 48). Mọi sự kiện red team đều rơi vào ngày thường.
- Chỉ số: AUC (khoảng tin cậy 95% bootstrap theo ca dương); **AvgPct** — "AP" của Tuor et al. là *average percentile*: với mỗi ca tấn
  công, thứ hạng phần trăm của điểm nó trong mọi điểm CÙNG NGÀY, lấy trung bình (không phải average precision); recall ở tỉ lệ báo
  nhầm 1%; và **"lọt top N mỗi ngày"**: nếu người phân tích mỗi ngày chỉ xem N user-ngày điểm cao nhất thì bắt được bao nhiêu phần trăm
  user-ngày bị tấn công (các ca bằng điểm xếp ngẫu nhiên). Mọi số đo có trọng số lấy mẫu, dùng chung bộ đo với RBA (`ml/rba/metrics.py`).

## 3. Kết quả (tập kiểm tra ngày 13–58, bỏ cuối tuần/ngày lễ)

**Mức user-ngày** (trung bình 8.260 người dùng hoạt động mỗi ngày thường, ~4 user-ngày bị tấn công mỗi ngày):

| Bộ chấm | AUC [KTC 95%] | AvgPct | Lọt top 10 / 50 / 200 mỗi ngày |
|---|---|---|---|
| **Isolation Forest** | **0,873** [0,841–0,900] | 0,856 | 0% / 0% / 12,6% |
| `novelty_count` (luật đếm cờ "mới") | 0,852 [0,816–0,887] | 0,830 | 0,0% / 0,2% / 5,0% |
| `new_dst_1h` | 0,802 [0,760–0,841] | 0,787 | 0,8% / 9,2% / 24,1% |
| `new_dst` | 0,789 [0,751–0,831] | 0,772 | 0,6% / 2,8% / 11,3% |
| `new_src` | 0,771 [0,729–0,813] | 0,756 | 0,5% / 2,4% / 9,5% |
| `events_1h` | 0,682 [0,627–0,747] | 0,678 | 4,2% / 10,9% / 17,1% |
| `hour_rarity` | 0,588 [0,526–0,645] | 0,529 | 0% / 0% / 1,7% |
| `new_auth` | 0,541 [0,516–0,570] | 0,530 | 0,3% / 1,3% / 5,2% |

**Mức từng sự kiện** (386 lần đăng nhập tấn công):

| Bộ chấm | AUC [KTC 95%] | AvgPct | Recall @ báo nhầm 1% |
|---|---|---|---|
| Isolation Forest | 0,824 [0,793–0,852] | 0,849 | 31,4% |
| `new_dst_1h` | **0,840** [0,820–0,863] | 0,834 | **41,2%** |
| `novelty_count` | 0,696 [0,673–0,718] | 0,695 | 39,4% |
| `hour_rarity` | 0,426 [0,407–0,451] | 0,443 | 2,1% |

Giai đoạn phát triển (ngày 1–12, cùng phương án bỏ cuối tuần): Isolation Forest user-ngày AUC 0,776 [0,746–0,809], AvgPct 0,898; sự
kiện AUC 0,848. Phương án giữ mọi ngày cho số gần như nhau (user-ngày Isolation Forest kiểm tra 0,887). Toàn bộ số trong
`ml/artifacts/lanl/evaluation.json`.

## 4. So với kết quả đã công bố

| | User-ngày AUC | User-ngày AvgPct | Sự kiện AUC |
|---|---|---|---|
| Tuor et al. 2018 — PCA | 0,754 | 0,739 | — |
| Tuor et al. 2018 — Isolation Forest | 0,763 | 0,750 | — |
| Tuor et al. 2018 — RNN tốt nhất (BEM, mức từ) | 0,876 | 0,870 | — |
| Tuor et al. 2018 — RNN mức ký tự tốt nhất | — | — | 0,98 |
| **Đồ án — Isolation Forest** | **0,873** [0,841–0,900] | 0,856 | 0,824 |
| Đồ án — `novelty_count` | 0,852 | 0,830 | 0,696 |

**Đọc bảng này thế nào — không phải so sánh "cùng điều kiện":**

1. **Tiền xử lý khác.** Bài báo giữ MỌI dòng log gắn với người dùng (cả LogOff, cấp vé Kerberos…); đồ án chỉ giữ lần đăng nhập (`LogOn`,
   37% số dòng) cho vừa máy 16 GB và cho giống một lần gọi `/login`. Bài báo dùng mọi người dùng; đồ án dùng mẫu 20% có trọng số (ước
   lượng có trọng số ra 108,8 triệu lần đăng nhập so với 125,9 triệu thật — mẫu băm tên lệch nhẹ về người dùng ít hoạt động).
2. **Đặc trưng khác.** Isolation Forest của bài báo học trên vector ĐẾM theo user-ngày; Isolation Forest của đồ án học trên đặc trưng
   "mới với chính tài khoản" của từng lần đăng nhập rồi lấy max theo ngày. Chênh 0,763 → 0,873 vì thế nói về **giá trị của đặc trưng
   theo lịch sử tài khoản**, không phải đồ án "giỏi hơn" bài báo.
3. **Nhiều công trình trên LANL cho số khác nhau** chỉ vì cách gán nhãn/tiền xử lý (arXiv:2607.29390, 2026, cảnh báo đúng điều này) — vì thế báo cáo bám sát cách chia của một bài cụ thể và ghi rõ chỗ khác.
4. **Ở mức sự kiện, đồ án kém xa** mô hình chuỗi ký tự (0,82 so với 0,98): đặc trưng tổng hợp không thay được mô hình học trực tiếp trên
   chuỗi log.

## 5. Kết luận rút ra cho đồ án

- **Phương pháp có tín hiệu trên tấn công thật.** Không học từ nhãn, không chỉnh tham số theo tập kiểm tra, Isolation Forest trên đặc
  trưng theo lịch sử tài khoản xếp user-ngày bị tấn công cao hơn ~87% user-ngày bình thường, ngang mô hình học sâu tốt nhất của bài báo
  ở mức này. Luật đơn giản đếm cờ "mới" đã đạt 0,85 — khớp lựa chọn thiết kế của hệ thống: luật "thiết bị/vị trí mới" là nền, ML bổ sung.
- **Nhưng AUC cao chưa phải là dùng được để báo động.** Mỗi ngày có ~4 user-ngày bị tấn công giữa ~8.260; AvgPct 0,856 nghĩa là ca tấn
  công điển hình đứng quanh top 14% (~1.200 người). Người phân tích xem 200 người/ngày chỉ bắt được 12,6% (Isolation Forest) hoặc 24,1%
  (`new_dst_1h`). Điều này đúng cả với số đã công bố (AvgPct 0,87 của bài báo cũng là top ~13%). Đây là lý do hệ thống của đồ án KHÔNG
  dùng ML một mình để khoá, mà làm bằng chứng trong điểm hợp nhất cùng luật có hành động tối thiểu (MR21, MR25).
- **Tín hiệu đơn mạnh nhất là "nhiều máy đích mới trong 1 giờ"** (sự kiện AUC 0,84, recall 41% ở báo nhầm 1%) — đúng bản chất di chuyển
  ngang. Trên web, tương ứng gần nhất là các luật tốc độ/lan rộng theo tài khoản đã có (`success_burst`, `multi_context_simultaneous`,
  `country_hop`).
- **"Giờ lạ" gần như vô dụng ở đây** (sự kiện AUC 0,43 — red team làm việc đúng giờ hành chính). Khớp cách hệ thống dùng lệch giờ: chỉ
  là một đặc trưng trong mô hình, không có luật riêng.

## 6. Tái lập

```
cd backend
venv\Scripts\python.exe -m ml.lanl.etl         # 209 s, ghi ml/data/lanl/auth_users.parquet, redteam.parquet
venv\Scripts\python.exe -m ml.lanl.features    # ~25 phút, ghi ml/data/lanl/features.parquet
venv\Scripts\python.exe -m ml.lanl.evaluate    # ~5 phút, ghi ml/artifacts/lanl/evaluation.json
```

Cần ~9 GB đĩa (7,2 GiB tệp nén + 1,8 GiB parquet trung gian). Test (`tests/test_lanl.py`) dùng dữ liệu tự dựng vài dòng: gán nhãn đúng bộ bốn,
đặc trưng chỉ dùng quá khứ, nhận ngày nghỉ, chỉ số theo ngày và xử lý điểm bằng nhau.

**Những gì đã đổi sau lần chạy đầu** (để không bị hiểu là chỉnh theo tập kiểm tra): sửa lỗi lấy mẫu huấn luyện (DuckDB lấy mẫu TRƯỚC
khi lọc ngày → chỉ 180.689 dòng, nay 1.000.000); thay ngưỡng nhận ngày nghỉ "dưới 50% trung vị" (không bắt được ngày nào) bằng chu kỳ 7
ngày; thêm chỉ số "lọt top N", sửa cách tính điểm bằng nhau. Đặc trưng và tham số Isolation Forest giữ nguyên từ đầu; lần chạy đầu cho
user-ngày Isolation Forest 0,889 (mọi ngày), lần cuối 0,887.

## 7. Hội đồng có thể hỏi

- **"Dữ liệu tổng hợp, có dữ liệu thật không?"** — RBA là dữ liệu tổng hợp (không nói là thật). LANL là log thật của một mạng thật, có
  tấn công thật của red team có nhãn; đồ án dùng nó để kiểm chứng phương pháp, có ghi rõ khác biệt với web.
- **"Sao không chạy hệ thống trên LANL?"** — Không có IP công cộng, User-Agent, quốc gia, OTP; cấu trúc là máy → máy trong mạng nội bộ.
  Chạy nguyên hệ thống sẽ là so sai. Kiểm chứng giữ đúng phần chuyển được: đặc trưng theo lịch sử tài khoản + mô hình không giám sát + luật.
- **"0,873 cao hơn Isolation Forest của bài báo, có chắc không?"** — Không so cùng điều kiện (mục 4). Kết luận đúng: đặc trưng theo lịch
  sử tài khoản mang nhiều thông tin hơn vector đếm theo ngày; và cả hai đều cách xa mức dùng được để báo động tự động.
- **"Recall 12,6% ở top 200 thì có ích gì?"** — Đó là giới hạn chung của phát hiện không giám sát trên log xác thực với tỉ lệ tấn công
  ~0,05% user-ngày; vì vậy hệ thống kết hợp luật (hành động tối thiểu), ML (bằng chứng) và phản hồi của người phân tích.
- **"Có dùng nhãn để học không?"** — Không. Nhãn red team chỉ dùng để đo; Isolation Forest học trên ngày 1–12 có lẫn cả tấn công, như
  bài báo.
- **"Lấy mẫu 20% người dùng có làm sai số không?"** — Mọi người dùng bị tấn công đều được giữ; người dùng còn lại chọn bằng băm tên
  (không theo kết quả), trọng số 5. Khoảng tin cậy bootstrap chỉ tính dao động của ca dương, không tính dao động do lấy mẫu người dùng.
