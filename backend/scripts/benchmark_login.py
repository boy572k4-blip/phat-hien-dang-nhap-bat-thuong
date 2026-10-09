"""Đo thời gian phản hồi POST /login (nhiệm vụ 5.2) — chạy trước và sau khi
tối ưu để so sánh. KHÔNG tự tối ưu gì — chỉ đo.

Chạy (backend phải đang chạy ở port 8000, Postgres dev đang chạy):
    cd backend
    venv\\Scripts\\python.exe -m scripts.benchmark_login --n 50                       # tài khoản MỚI tạo cho lần chạy này
    venv\\Scripts\\python.exe -m scripts.benchmark_login --n 100 --concurrency 10     # tải: 10 request đồng thời (MR12)
    venv\\Scripts\\python.exe -m scripts.benchmark_login --n 50 --username alice --password CorrectHorse123   # tài khoản có sẵn
    venv\\Scripts\\python.exe -m scripts.benchmark_login --pipeline                    # kèm độ trễ pipeline nền (xem ghi chú dưới)

MR20: mặc định TẠO TÀI KHOẢN MỚI (`bench_<thời điểm>`, ghi thẳng vào DB dev bằng `app.security.hash_password`) cho MỖI lần
chạy. Trước đó script luôn đăng nhập `alice` — chính các lần benchmark (và test/demo) làm lịch sử của `alice` phình lên
hơn 1.400 dòng, nên số đo sau chậm dần một phần vì CHÍNH việc đo trước đó (xem docs/performance.md). Muốn đo riêng tài
khoản có lịch sử dài thì truyền `--username`/`--password`. Tài khoản bench không bị xoá sau khi chạy (dữ liệu dev; tên
được in ra để tra lại log).

Mỗi request gửi User-Agent của một trình duyệt thật (Chrome trên Windows, đổi bằng `--user-agent`): đây là phép đo một lần
đăng nhập HỢP LỆ, không phải công cụ tự động (UA mặc định của httpx khớp luật `scripted_client`). Báo cáo đếm cả mã phản
hồi: lần thử bị khoá (423) trả về rất nhanh vì không qua bcrypt/pipeline — lẫn vào mà không đếm riêng sẽ làm số đo đẹp
giả tạo. `--ip`: gửi kèm `X-Forwarded-For` để server coi request đến từ IP đó (chỉ có tác dụng khi `.env` bật
`TRUST_FORWARDED_FOR=true`) — `127.0.0.1` không có GeoIP/ASN nên KHÔNG đi qua các nhánh tra vị trí/nhà mạng như một người
dùng thật.

MR12 thêm p99 (bên cạnh p95 sẵn có) và `--concurrency` để đo "tải" theo đúng yêu cầu checklist ("đo độ trễ p50/p95/p99
và tải"), không chỉ độ trễ tuần tự. `--concurrency N > 1` gửi N request cùng lúc bằng `httpx.Client` với một
`ThreadPoolExecutor` (đơn giản hơn asyncio cho một script CLI ngắn, đủ để tạo tải thật lên server).

`--pipeline` in kèm độ trễ pipeline NỀN đo được ở server (`app/detection/perf.py`, endpoint chẩn đoán `GET /health`
không lộ số này — script gọi thẳng qua import, chỉ dùng được khi chạy CÙNG máy/tiến trình Python có thể import
`app.detection.perf`; khi benchmark nhắm một server đang chạy Ở TIẾN TRÌNH KHÁC, cờ này không có gì để in vì độ trễ
nền nằm trong bộ nhớ của tiến trình server, không phải của script — xem `docs/realtime-integration.md` mục đo đạc)."""

from __future__ import annotations

import argparse
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import httpx

# 127.0.0.1, KHÔNG phải "localhost": trên Windows, "localhost" thử IPv6 (::1) trước trong khi uvicorn chỉ nghe IPv4, mỗi
# KẾT NỐI MỚI mất thêm ~2 giây trước khi quay về IPv4 (đo ở MR20: 2.073 ms so với 30 ms). Chi phí đó thuộc về máy đo, không
# phải server, nhưng đã lẫn vào "max" của mọi lần đo trước MR20 và vào p95 khi đo đồng thời (mỗi luồng mở kết nối riêng).
URL = "http://127.0.0.1:8000/login"
BENCH_PASSWORD = "BenchPassword-2026"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def create_fresh_accounts(count: int = 1) -> list[str]:
    """Tài khoản mới tinh (chưa có lịch sử đăng nhập) trong DB mà server đang dùng — cùng mật khẩu `BENCH_PASSWORD`."""
    from app.database import SessionLocal
    from app.models import User
    from app.security import hash_password

    stamp = datetime.now().strftime('%Y%m%d%H%M%S')
    usernames = [f"bench_{stamp}" + (f"_{i:02d}" if count > 1 else "") for i in range(count)]
    password_hash = hash_password(BENCH_PASSWORD)
    db = SessionLocal()
    try:
        db.add_all(User(username=name, password_hash=password_hash) for name in usernames)
        db.commit()
    finally:
        db.close()
    return usernames


def _percentile(sorted_values: list[float], q: float) -> float:
    idx = min(len(sorted_values) - 1, int(len(sorted_values) * q))
    return sorted_values[idx]


def _outcome(response: httpx.Response) -> str:
    if response.status_code == 200:
        body = response.json()
        return "step_up (OTP)" if body.get("step_up_required") else ("thành công" if body.get("success") else "200 khác")
    return {401: "sai mật khẩu (401)", 423: "bị khoá (423)"}.get(response.status_code, f"HTTP {response.status_code}")


def _one_request(client: httpx.Client, payload: dict, headers: dict) -> tuple[float, str]:
    start = time.perf_counter()
    try:
        response = client.post(URL, json=payload, headers=headers)
        outcome = _outcome(response)
    except httpx.TimeoutException:
        outcome = "timeout"
    return (time.perf_counter() - start) * 1000, outcome


def run(n: int, concurrency: int, payloads: list[dict], headers: dict, timeout_s: float) -> list[tuple[float, str]]:
    """Request thứ i dùng `payloads[i % len(payloads)]` (xoay vòng tài khoản)."""
    with httpx.Client(timeout=timeout_s) as client:
        if concurrency <= 1:
            return [_one_request(client, payloads[i % len(payloads)], headers) for i in range(n)]
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            return list(pool.map(lambda i: _one_request(client, payloads[i % len(payloads)], headers), range(n)))


def report(results: list[tuple[float, str]], n: int, concurrency: int, username: str, ip: str | None) -> None:
    durations_ms = sorted(ms for ms, _ in results)
    source = f", IP {ip}" if ip else ""
    label = f"N = {n} request tới {URL} (tài khoản {username}{source})" + (f", {concurrency} request đồng thời (tải)" if concurrency > 1 else " (tuần tự)")
    print(label)
    print(f"  min    = {durations_ms[0]:.1f} ms")
    print(f"  avg    = {statistics.mean(durations_ms):.1f} ms")
    print(f"  median = {statistics.median(durations_ms):.1f} ms")
    print(f"  p95    = {_percentile(durations_ms, 0.95):.1f} ms")
    print(f"  p99    = {_percentile(durations_ms, 0.99):.1f} ms")
    print(f"  max    = {durations_ms[-1]:.1f} ms")
    print("  kết quả: " + ", ".join(f"{outcome} {count}" for outcome, count in Counter(o for _, o in results).most_common()))


def main(
    n: int, concurrency: int, show_pipeline: bool, username: str | None, password: str | None, user_agent: str, timeout_s: float, ip: str | None,
    accounts: int = 1,
) -> None:
    if username is None:
        names = create_fresh_accounts(accounts)
        payloads = [{"username": name, "password": BENCH_PASSWORD} for name in names]
        username = names[0] if accounts == 1 else f"{names[0]}…{names[-1]} ({accounts} tài khoản xoay vòng)"
        print(f"(đã tạo {accounts} tài khoản mới cho lần chạy này: {username})")
    else:
        payloads = [{"username": username, "password": password}]
    headers = {"user-agent": user_agent, **({"x-forwarded-for": ip} if ip else {})}
    report(run(n, concurrency, payloads, headers, timeout_s), n, concurrency, username, ip)

    if show_pipeline:
        try:
            from app.detection import perf

            snapshot = perf.snapshot()
        except Exception as exc:  # noqa: BLE001 — script chẩn đoán, không được sập vì lý do phụ
            print(f"\n(không đọc được độ trễ pipeline nền: {exc})")
            return
        if not snapshot:
            print("\n(chưa có số đo pipeline nền trong tiến trình này — --pipeline chỉ có ý nghĩa khi chạy CÙNG tiến trình server, xem docstring)")
            return
        print("\nĐộ trễ pipeline nền đo được TRONG TIẾN TRÌNH NÀY (app.detection.perf, không phải của riêng lần chạy benchmark này):")
        for stage, stats in snapshot.items():
            print(f"  {stage:12} n={stats['count']:>5}  mean={stats['mean_ms']:>7.2f}ms  p50={stats['p50_ms']:>7.2f}ms  p95={stats['p95_ms']:>7.2f}ms  p99={stats['p99_ms']:>7.2f}ms  max={stats['max_ms']:>7.2f}ms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=50)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", dest="base_url", help="địa chỉ backend (MR34: đo trên server tạm ở cổng khác)")
    parser.add_argument("--concurrency", type=int, default=1, help="số request gửi đồng thời (1 = tuần tự, mặc định)")
    parser.add_argument(
        "--accounts", type=int, default=1,
        help="số tài khoản MỚI xoay vòng (MR34: >= 8 lần thành công/10 phút vào MỘT tài khoản khớp luật success_burst — benchmark phải "
             "chia đều, vd --n 50 --accounts 10)",
    )
    parser.add_argument("--username", default=None, help="đo tài khoản CÓ SẴN (mặc định: tạo tài khoản mới cho lần chạy này)")
    parser.add_argument("--password", default=None, help="mật khẩu của --username")
    parser.add_argument("--user-agent", default=CHROME_UA, dest="user_agent", help="User-Agent gửi kèm (mặc định: Chrome trên Windows)")
    parser.add_argument("--timeout", type=float, default=10.0, dest="timeout_s", help="giây chờ tối đa mỗi request; quá thì tính là timeout")
    parser.add_argument("--ip", default=None, help="IP nguồn giả lập qua X-Forwarded-For (cần TRUST_FORWARDED_FOR=true ở .env)")
    parser.add_argument("--pipeline", action="store_true", dest="show_pipeline", help="in kèm độ trễ pipeline nền (chỉ có ý nghĩa khi import được app.detection.perf của CÙNG tiến trình)")
    args = parser.parse_args()
    URL = args.base_url.rstrip("/") + "/login"
    if (args.username is None) != (args.password is None):
        parser.error("--username và --password phải đi cùng nhau")
    main(
        n=args.n, concurrency=args.concurrency, show_pipeline=args.show_pipeline, username=args.username, password=args.password,
        user_agent=args.user_agent, timeout_s=args.timeout_s, ip=args.ip, accounts=args.accounts,
    )
