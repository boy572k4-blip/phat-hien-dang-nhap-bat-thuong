# Đo & tối ưu tốc độ POST /login (nhiệm vụ 5.2)

> **Ghi chép theo thời điểm (Tuần 5–MR23; số mới nhất ở acceptance-mr34.md)** — mô tả và số đo lúc đó, giữ để truy vết; hệ thống đã thay đổi ở các MR sau (đến MR36). Bản hiện hành: [`architecture.md`](architecture.md) · mục lục tài liệu: [`README.md`](README.md).

> ⚠️ **Cập nhật MR19 (28/09/2026):** số ở mục "Phương pháp/Kết quả" gốc bên dưới là của **Tuần 5** (chỉ tầng 1-2, chưa
> có rule engine v2/hybrid ML/MR16). Số hiện tại — **chậm hơn đáng kể** — và phân tích nguyên nhân ở mục
> "Đo lại sau MR9-18" cuối tài liệu.
>
> **Cập nhật MR20 (01/10/2026):** đã profiling thật, sửa và đo lại — xem mục cuối "MR20". Chẩn đoán của MR19 (đọc mã
> nguồn, chưa profiling) đúng nhưng KHÔNG phải nguyên nhân lớn nhất; mục MR20 ghi lại chẩn đoán đúng.

## Phương pháp

`backend/scripts/benchmark_login.py` — 50 request tuần tự tới `POST /login`
trên cùng máy (`localhost`), dùng tài khoản `alice`. Đo **trước** khi tối
ưu bằng cách `git stash` tạm quay lại code cuối Tuần 4 (detection engine
chạy đồng bộ, chặn response), rồi `git stash pop` để đo **sau** khi tối ưu
(detection engine chạy nền qua `BackgroundTasks`).

## Kết quả

| | min | avg | median | p95 | max |
|---|---|---|---|---|---|
| **Trước** (Tuần 4, đồng bộ) | 242.2 ms | 289.8 ms | 247.6 ms | 258.8 ms | 2328.5 ms |
| **Sau** (Tuần 5, `BackgroundTasks`) | 248.9 ms | 303.4 ms | 260.3 ms | 282.6 ms | 2337.6 ms |

**Không cải thiện đáng kể — kết quả thật, không chỉnh sửa.** Lý do:

1. **bcrypt chiếm gần hết thời gian phản hồi.** Đo riêng `verify_password()`:

   ```
   bcrypt.checkpw đơn lẻ: min=221.5ms avg=226.8ms max=237.1ms
   ```

   Với cost factor mặc định (12 rounds — cố ý chậm để chống brute force),
   một lần `bcrypt.checkpw()` đã chiếm ~227ms trong tổng ~250-260ms median
   của cả request. Phần detection engine (GeoIP + Redis + vài query DB) mà
   Tuần 4 làm đồng bộ chỉ chiếm phần chênh lệch còn lại (~20-60ms) — dời nó
   ra nền không thể cải thiện quá phần đó.

2. **Benchmark tuần tự trên 1 kết nối HTTP keep-alive** không đo được lợi
   ích thật của `BackgroundTasks`. Lợi ích chính của việc tách detection ra
   nền là **throughput khi có nhiều request đồng thời** (server rảnh tay xử
   lý request tiếp theo trong lúc detection của request trước chạy nền),
   không phải độ trễ của từng request đơn lẻ trên cùng 1 kết nối tuần tự —
   đây là hạn chế của phương pháp đo, không phải tối ưu vô nghĩa.

## Kết luận & khuyến nghị

- Việc dời detection engine ra `BackgroundTasks` (xem
  [`backend/app/detection/pipeline.py`](../backend/app/detection/pipeline.py))
  **vẫn đúng về mặt kiến trúc** — response không còn phụ thuộc vào số bước
  DB/Redis mà detection engine cần (quan trọng nếu sau này detection nặng
  hơn, ví dụ gọi GeoIP qua mạng thay vì file cục bộ, hoặc thêm tầng ML ở
  Tuần 7 chạy chậm hơn nhiều).
- **Ngưỡng "dưới 300ms" (docs/api-contract.md mục 6) khó đạt được** với
  bcrypt cost factor mặc định — đây là đánh đổi cố ý giữa bảo mật (chống
  brute force offline nếu DB bị lộ) và độ trễ. Không hạ cost factor vì đó
  sẽ làm yếu khả năng chống brute force của chính hash — nếu hội đồng hỏi,
  đây là câu trả lời: "chấp nhận ~250-300ms vì đó là chi phí bảo mật của
  bcrypt, không phải lỗi hiệu năng chưa tối ưu."
- Cache GeoIP (`app/detection/geoip.py`) vẫn giữ lại vì có giá trị khi
  chuyển sang provider GeoIP qua mạng trong tương lai, dù hiện tại
  `geoip2.Reader` đọc file cục bộ đã rất nhanh nên không đo được khác biệt.

## Kiểm tra không hồi quy

Toàn bộ 44 unit test (bao gồm rule-based Tuần 3, scoring Tuần 4) vẫn pass
sau khi tái cấu trúc sang `BackgroundTasks` — không có test nào fail thêm
so với trước khi tối ưu.

## Đo lại sau MR9-18 (MR19)

**Đo thật, `scripts/benchmark_login.py` không đổi tham số đo (vẫn tài khoản `alice`), backend/Postgres/Redis dev thật
đang chạy, không có tải nào khác đồng thời (ngoài chính benchmark):**

| Kịch bản | min | avg | median | p95 | p99 / max |
|---|---|---|---|---|---|
| Tuần 5 (gốc, chỉ tầng 1-2) | 242,2 ms | 289,8 ms | 247,6 ms | 258,8 ms | 2328,5 ms |
| **MR19, tuần tự, n=50** | 541,4 ms | 646,1 ms | **614,4 ms** | 669,0 ms | 2809,8 ms |
| **MR19, 3 request đồng thời, n=20** | 705,3 ms | 1373,8 ms | **1061,5 ms** | 3742,1 ms | 3742,1 ms |

`--concurrency 10` (n=100) **timeout thật** (`httpx.ReadTimeout`, giới hạn mặc định 10s của script) — không hoàn
thành được, không phải số bị làm tròn hay bỏ qua.

**Không cải thiện — chậm đi rõ rệt, kết quả thật, không chỉnh sửa cho đẹp.** Đọc mã nguồn xác nhận (không chỉ suy
đoán) hai nguyên nhân cụ thể ở [`rba_live_features.py`](../backend/app/detection/rba_live_features.py):

1. **`_user_events()` (dòng 62-64) lấy TOÀN BỘ lịch sử đăng nhập của tài khoản, không giới hạn số dòng** — tài khoản
   `alice` dùng làm chuẩn benchmark từ Tuần 5 đã tích luỹ **1.422 dòng** (đếm trực tiếp trong Postgres dev lúc viết
   tài liệu này) sau 8 tuần bị dùng lại liên tục để test/demo/benchmark qua toàn bộ MR1-19 — CHÍNH benchmark này mỗi
   lần chạy lại làm `alice` có thêm N dòng, nên lần chạy SAU luôn có xu hướng chậm hơn lần chạy TRƯỚC một chút (hiệu
   ứng tự cộng dồn, không phải nhiễu đo). Với tài khoản mới (0 lịch sử), truy vấn này rẻ; **độ trễ không bị chặn trên
   theo số lần đăng nhập của một tài khoản** — đây là rủi ro mở rộng thật cho một tài khoản dùng lâu năm.
2. **Truy vấn đếm toàn cục cho đặc trưng độ hiếm (`GlobalCountsCache`, dòng ~115) quét TOÀN BẢNG `login_events`**
   (mọi đăng nhập thành công, mọi tài khoản) mỗi khi cache (TTL 30 giây) hết hạn — **không có khoá (`Lock`) chống
   nhiều request cùng lúc cùng làm mới cache**: nếu ≥ 2 request đến đúng lúc cache vừa hết hạn, CẢ HAI đều tự quét lại
   toàn bảng thay vì một request quét, còn lại chờ — khớp với việc độ trễ ở `--concurrency 3` tệ hơn nhiều so với tỉ
   lệ tuyến tính từ số tuần tự (median tăng 73% chỉ với 3 request đồng thời, p95 tăng gần 6 lần).

⚠️ **Chưa profiling để tách chính xác bao nhiêu % do nguyên nhân (1) so với (2)** so với chi phí cố định của
`hybrid_cp2.predict()` (LightGBM + Isolation Forest trên 50 đặc trưng) hay chi phí đồng bộ hoá MR16 thêm cho lần thử
ĐÚNG mật khẩu (docs/api-contract.md ước lượng ~140ms trung vị, đo riêng, không cộng dồn được trực tiếp vào bảng
trên vì đo trên baseline khác) — đây là **hai nguyên nhân xác nhận được qua đọc mã nguồn**, không phải toàn bộ bức
tranh. `run_detection_pipeline` (MR12, `pipeline.py` dòng 516) đã đúng đắn dùng `asyncio.to_thread` nên KHÔNG chặn
event loop — tình trạng chậm ở đây là chi phí DB/CPU thật của từng thread, không phải lỗi kiến trúc async.

**Khuyến nghị (chưa làm, ngoài phạm vi MR19):** giới hạn `_user_events` theo cửa sổ thời gian hoặc số dòng gần nhất
(đã có tiền lệ — `_ip_events`/`_asn_events` cùng file đã giới hạn 24 giờ); thêm khoá hoặc "single-flight" cho
`GlobalCountsCache` khi cache miss; xem xét benchmark bằng tài khoản MỚI mỗi lần chạy thay vì tái sử dụng `alice` để
số đo không tự phình theo thời gian.

## MR20 — profiling thật, sửa, đo lại (01/10/2026)

### Cách đo

1. **Từng bước của pipeline, trong tiến trình**: chạy thẳng `_run_detection_pipeline_sync` trên Postgres dev thật, bọc
   từng hàm bằng bộ bấm giờ (không dùng cProfile — nó làm chậm phóng đại những đoạn gọi hàm Python dày đặc như vòng lặp
   cây của Isolation Forest). Mọi dòng ghi trong lúc đo nằm trong MỘT giao dịch và bị rollback ở cuối, nên trước/sau đo
   trên cùng trạng thái DB. Con số tuyệt đối ở cách này hơi cao hơn vận hành thật (giao dịch lớn, savepoint mỗi lần).
2. **Qua HTTP thật**: `scripts/benchmark_login.py`, server uvicorn thật, Postgres + Redis Docker, cùng máy (12 CPU logic).
   Đo bản trước MR20 bằng cách tạm cất (`git stash`) mã nguồn luồng đăng nhập về commit `07b0463` rồi khởi động lại server.

### Sửa lại chẩn đoán của MR19

MR19 nêu hai nguyên nhân qua đọc mã nguồn: `_user_events` nạp toàn bộ lịch sử tài khoản, và `GlobalCountsCache` không
có khoá. Cả hai **có thật nhưng không lớn nhất**. Profiling (bản trước MR20, tài khoản `alice` ~1.400 dòng, mỗi lần
đăng nhập thành công) xếp theo mức tốn:

| # | Nguyên nhân | Tốn | Ghi chú |
|---|---|---|---|
| 1 | Tương quan chiến dịch (MR14) nạp **toàn bộ bảng `alerts`** vào Python rồi mới lọc | ~140 ms | chỉ khi lần thử có cảnh báo; tăng tuyến tính theo số cảnh báo tích luỹ (3.500 lúc đo) |
| 2 | Mô hình `hybrid_cp2` chạy **2 lần** mỗi lần đăng nhập (một lần lấy xác suất, một lần lấy thành phần dẫn đầu cho MR13); Isolation Forest của sklearn chấm 1 dòng chậm vì gọi riêng từng cây (200–300 cây) qua joblib; tầng 3 cũng chấm 2 lần (`predict` + `score_samples`) | ~50 ms (chạy 2 lần) + ~50–60 ms (Isolation Forest, tầng 3) | |
| 3 | `DbGlobalStats` (luật nhà mạng hiếm) **dựng mới mỗi lần chấm** nên cache TTL vô dụng — quét toàn bảng ở MỌI lần đăng nhập có ASN; còn đếm cả chính lần thử đang chấm (lệch với replay lúc hiệu chỉnh, nơi thống kê chỉ cập nhật SAU khi chấm) | 13–22 ms | nguyên nhân MR19 chưa thấy |
| 4 | Lịch sử tài khoản nạp toàn bộ vào Python **hai lần** (rule engine + đặc trưng); cửa sổ IP/ASN 24 giờ nạp từng dòng | ~30 ms (`alice`) | cửa sổ IP/ASN tăng theo chính lượng tấn công dồn dập từ IP/ASN đó |
| 5 | **bcrypt chạy thẳng trong hàm `async` `/login`** — chặn vòng lặp sự kiện dùng chung, mọi request đồng thời xếp hàng chờ nhau | ~230 ms × số request đang chờ | lý do chính khiến 10 request đồng thời mất 3–5 giây; MR19 chưa thấy |
| 6 | **Nhiễu của chính phép đo**: script gọi `localhost`; trên Windows "localhost" thử IPv6 (`::1`) trước trong khi uvicorn chỉ nghe IPv4, mỗi KẾT NỐI MỚI mất thêm ~2 giây (đo: 2.073 ms so với 30 ms qua `127.0.0.1`) | ~2 s mỗi kết nối mới | toàn bộ cột "max" ~2,3–2,9 s ở MR19 và một phần p95 khi đo đồng thời là của máy đo, không phải server |

### Đã sửa

- [`login_context.py`](../backend/app/detection/login_context.py) (mới) — **ngữ cảnh đăng nhập dựng MỘT lần**, dùng
  chung cho rule engine, đặc trưng RBA và novelty của cảnh báo. Mọi phép đếm do DB làm (`count ... FILTER`, `GROUP BY`),
  Python chỉ nhận vài con số: lịch sử tài khoản = 1 truy vấn đếm + 1 truy vấn gom các lần thành công theo 7 thuộc tính;
  IP và ASN mỗi bên 1 truy vấn đếm. Câu lệnh SQL dựng sẵn một lần khi nạp module (dựng lại cây biểu thức SQLAlchemy ở
  mỗi lần gọi tốn ~5 ms, nhiều hơn chính DB thực thi ~1,5 ms). Đặc tả `ml/rba/features.py` đổi sang dạng tổng hợp
  (`UserHistory`, `InfraStats`) — chính đặc tả này vẫn được so với DuckDB ở các test MR3.
- **Một bộ đếm toàn cục** (`GlobalCountsCache`) thay hai bộ, có khoá: khi hết hạn chỉ một request tính lại, request khác
  chờ rồi dùng chung. DB gom nhóm sẵn nên mỗi lần tính lại ~4–16 ms (350 nhóm thay vì ~4.800 dòng, trước đó ~67 ms).
  Mốc cắt lùi 5 giây để request đồng thời đến lệch thứ tự vẫn dùng chung được; không bao giờ đếm chính lần thử đang chấm.
- Tương quan chiến dịch lọc IP/ASN và cửa sổ thời gian **ngay trong SQL**.
- Mô hình chạy **một lần** cho mỗi lần đăng nhập (`HybridMinTail.score_with_trigger`); Isolation Forest (của `hybrid_cp2`
  và tầng 3) chấm bằng [`ml/fast_iforest.py`](../backend/ml/fast_iforest.py) — cùng công thức sklearn nhưng gọi thẳng
  `tree_.apply`, **chỉ được dùng khi kiểm tra lúc nạp cho kết quả trùng từng bit với sklearn** trên 128 dòng thử, không
  trùng thì tự quay về sklearn.
- `/login`: bcrypt chạy ở threadpool (thư viện bcrypt nhả GIL khi băm: 8 lần kiểm tra trên 8 luồng nhanh hơn tuần tự 7,2
  lần trên máy đo).
- **Hai lỗi tranh chấp thật** lộ ra khi request đồng thời thật sự chạy song song (trước đó bị bcrypt vô tình xếp hàng):
  10 lần đăng nhập đầu tiên đồng thời của một tài khoản mới → 9/10 request lỗi 500 (`UniqueViolation` khoá chính
  `user_baseline`, server cắt kết nối không trả lời). Sửa: chèn trong SAVEPOINT, trùng thì đọc lại dòng request kia đã
  ghi; bộ đếm cộng trong SQL để không mất lượt. Cùng lớp lỗi ở chỗ chèn mục khoá tự động (MR16, ràng buộc duy nhất
  `kind, value`) — sửa cùng cách.
- `scripts/benchmark_login.py`: tài khoản MỚI mỗi lần chạy (trước luôn dùng `alice`, tự làm phình lịch sử của chính tài
  khoản đang đo), gọi `127.0.0.1`, User-Agent trình duyệt thật, `--ip` (qua `X-Forwarded-For`), đếm kết quả từng loại
  (thành công / OTP / bị khoá) để lần thử bị khoá — trả về rất nhanh — không làm số đo đẹp giả tạo.

### Kết quả

**Từng lần chạy pipeline, trong tiến trình** (n=30 mỗi dòng, median ms; cùng trạng thái DB, rollback sau khi đo):

| | Trước MR20 | Sau MR20 |
|---|---|---|
| `alice` (~1.400 dòng lịch sử), IP 127.0.0.1 | 393,8 | 103,8 |
| `alice`, IP Việt Nam (có ASN) | 411,1 | 108,8 |
| Tài khoản mới, IP 127.0.0.1 | 355,9 | 79,2 |
| Tài khoản mới, IP Việt Nam | 164,3 (p95 421,8) | 88,0 |

Sau MR20, một lần đăng nhập của tài khoản mới tốn chủ yếu ở: mô hình `hybrid_cp2` ~13 ms, tầng 3 (đặc trưng + chấm)
~16 ms, ngữ cảnh đăng nhập ~8 ms, rule engine ~6 ms, baseline tầng 2 ~4 ms. Với `alice`, riêng baseline tầng 2 còn
~21 ms vì vẫn đọc mọi lần thành công để tính giờ đăng nhập trung bình (tầng 2 bị thay ở MR21).

**Qua HTTP thật** (`127.0.0.1`; tài khoản mới dùng User-Agent CHƯA TỪNG xuất hiện trong DB; mọi lần chạy 100% đăng nhập
thành công; hai bên cùng tỉ lệ cảnh báo — tài khoản mới không có cảnh báo nào, `alice` có cảnh báo ở ~97% lần thử):

| Kịch bản | Trước MR20: median / p95 / max | Sau MR20: median / p95 / max |
|---|---|---|
| Tài khoản mới, tuần tự n=50 | 394,6 / 476,7 / 625,9 ms | **318,9 / 336,5 / 473,7 ms** |
| Tài khoản mới, IP Việt Nam, tuần tự n=50 | 394,7 / 560,8 / 622,0 ms | **323,0 / 338,1 / 355,3 ms** |
| `alice` (~1.900 dòng lúc đo), tuần tự n=50 | 688,6 / 772,1 / 787,7 ms | **349,1 / 429,3 / 471,5 ms** |
| Tài khoản mới, **10 request đồng thời**, n=100 | 2.659 / 4.992 / 5.526 ms | **542 / 855 / 1.639 ms** |
| `alice`, **10 request đồng thời**, n=100 | 5.312 / 6.553 / 6.780 ms | **839 / 2.888 / 4.235 ms** |

Không có timeout nào ở cả hai bên trong lượt đo này (MR19 từng gặp timeout ở `--concurrency 10` khi còn đo qua `localhost`).
Log server bản sau MR20 không có lỗi nào trong toàn bộ lượt đo.

### Bảo đảm không đổi hành vi phát hiện

- `tests/test_login_context.py`: ~260 lần thử ngẫu nhiên (hạt giống cố định, có đợt dồn dập, thuộc tính thiếu, nhiều phiên
  bản trình duyệt cùng họ): **cả 50 đặc trưng bằng TUYỆT ĐỐI** với đặc tả ở mọi lần đăng nhập; `AccountHistory` của rule
  engine và novelty của cảnh báo bằng tuyệt đối với mã trước MR20 (giữ nguyên trong test làm chuẩn so sánh).
- Trên Postgres dev thật: tính lại 50 lần đăng nhập đã lưu bằng mã CŨ (lấy từ git) và mã MỚI — **50/50 lần có 50 đặc trưng
  giống hệt**, xác suất ML giống hệt và khớp đúng điểm đã lưu lúc chạy.
- ⚠️ Một lượt đo đầu tiên trong ngày cho thấy bản cũ yêu cầu OTP 22/50 lần còn bản mới 0 lần — **không phải do MR20**: lượt
  đo bản cũ chạy khi User-Agent Chrome 124 của benchmark chưa từng xuất hiện trong DB (bị chấm là "hiếm"), lượt đo bản mới
  chạy sau khi UA đó đã xuất hiện 350 lần; tính lại chính các lần thử đó bằng mã mới cho đúng điểm cũ. Vì vậy bảng HTTP ở
  trên dùng UA chưa từng xuất hiện cho CẢ HAI bên. Bản thân hiện tượng (tài khoản mới đăng nhập dồn dập bằng một trình
  duyệt hiếm bị đòi OTP) là một ca báo nhầm cần đo ở MR26.

### Còn lại / giới hạn

- **bcrypt ~230 ms mỗi lần là chi phí bảo mật cố ý** — median tuần tự ~320 ms ≈ bcrypt + ~80 ms pipeline.
- **Đuôi dài khi nhiều request đồng thời vào CÙNG một tài khoản lịch sử dài có cảnh báo** (`alice`: p95 2,2–2,9 s, max ~4,2 s
  qua hai lượt đo): KHÔNG do khoá DB — theo dõi `pg_stat_activity` mỗi 50 ms trong cả lượt đo: 0 lần backend chờ khoá. Giả
  thuyết (chưa xác minh): tranh chấp GIL, vì pipeline là mã Python chạy CPU và 10 luồng dùng chung một GIL. Hướng xử lý
  thường gặp là chạy nhiều worker uvicorn, nhưng WebSocket hiện chỉ phát cảnh báo trong một tiến trình — cần pub/sub trước.
- Baseline tầng 2 vẫn đọc mọi lần thành công của tài khoản (~21 ms với `alice`) — tầng 2 được thay bằng luật v2 ở MR21.
- Bộ đếm toàn cục vẫn quét toàn bảng (trong DB) mỗi 30 giây thời gian sự kiện; ở quy mô rất lớn cần bộ đếm cộng dồn lưu riêng.
- Truy vấn ASN 24 giờ đi qua chỉ mục chỉ có cột `asn` — với nhà mạng chiếm phần lớn lưu lượng, một chỉ mục `(asn, created_at)`
  sẽ biến nó thành quét theo khoảng thời gian. Chưa thêm (chưa cần ở quy mô hiện tại, cần migration).
- Lỗi DB bên trong các khối `try/except` "cô lập" của pipeline (MR12, MR14) làm hỏng cả giao dịch trên Postgres, nên lần
  commit cuối vẫn lỗi — "cô lập" hiện chỉ đúng với lỗi Python. **Đã sửa ở MR23**: mỗi khối một SAVEPOINT.
- **Phát hiện bảo mật (đã sửa ở MR32, [`security-review.md`](security-review.md)):** `/login` không chạy bcrypt khi tên đăng nhập
  không tồn tại, nên thời gian phản hồi (~vài ms so với ~230 ms) để lộ tài khoản nào có thật — dù thông báo lỗi đã giống hệt nhau.
  Nay tên không tồn tại được so với một hash giả cùng độ khó (`check_password`).
- Benchmark tạo tài khoản `bench_*` trong DB dev ở mỗi lần chạy và không tự xoá (tên được in ra để tra lại log). Dữ liệu
  benchmark của MR20 (24 tài khoản `bench_*`, 1.150 lần đăng nhập của `alice`) đã xoá khỏi DB dev ngày 03/10/2026 theo yêu
  cầu của chủ dự án; đo ở MR23 dùng bản sao DB tạm và rollback (dưới).

## MR23 — đo lại sau khi viết lại pipeline (03/10/2026)

Đo **trong tiến trình** thời gian chạy `_run_detection_pipeline_sync` cho MR22 và MR23 trên CÙNG một bản sao DB dev (khôi phục từ
bản sao lưu vào cơ sở dữ liệu tạm, mọi thay đổi rollback, Redis db riêng), 30 lần mỗi khối lượng, hai lượt xen kẽ — bảng đầy
đủ ở [`incident-unification.md`](incident-unification.md) mục 4. Chênh lệch giữa hai phiên bản trong cùng lượt 0–15 ms, nhỏ
hơn dao động giữa hai lượt (~12 ms ở cả hai phiên bản): **không đo được thay đổi độ trễ**. Trung vị ~100–120 ms mỗi lần (cao hơn
~79–104 ms đo ở MR20 trên DB khi đó chứa thêm/khác dữ liệu benchmark — không so trực tiếp hai đợt đo khác bộ dữ liệu).
Khi đo trên Postgres lộ ra lỗi của MR22: tên họ tấn công 67 ký tự > cột 64 (đã sửa ở MR23).
