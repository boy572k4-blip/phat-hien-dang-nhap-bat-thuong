"""Chỉ mục cửa sổ thời gian: engine GHI cho mỗi lần thử, các luật ĐỌC — tên khoá nằm ở một chỗ để hai phía không lệch nhau.

Quy ước tên khoá: `<loại>:<đối tượng>:<giá trị>`. Loại nhật ký (`log`) đếm số lần; loại tập (`set`) đếm giá trị khác nhau.

| Khoá                 | Loại | Nội dung                                              | Ghi khi           |
|----------------------|------|-------------------------------------------------------|-------------------|
| `fail:u:<tên>`       | log  | mỗi lần THẤT BẠI vào tên đăng nhập                    | thất bại          |
| `fi:u:<tên>`         | set  | IP đã thất bại vào tên đăng nhập                      | thất bại          |
| `fail:ip:<ip>`       | log  | mỗi lần thất bại từ IP                                | thất bại          |
| `fu:ip:<ip>`         | set  | tên đăng nhập đã thất bại từ IP                       | thất bại          |
| `fua:ip:<ip>`        | set  | User-Agent (băm) đã thất bại từ IP                    | thất bại, có UA   |
| `nx:ip:<ip>`         | set  | tên KHÔNG tồn tại đã thử từ IP                        | thất bại, tên bịa |
| `fail:asn:<asn>`     | log  | mỗi lần thất bại từ ASN                               | thất bại, có ASN  |
| `fu:asn:<asn>`       | set  | tên đăng nhập đã thất bại từ ASN                      | thất bại, có ASN  |
| `ok:ip:<ip>`         | log  | mỗi lần THÀNH CÔNG từ IP                              | thành công        |
| `ok:asn:<asn>`       | log  | mỗi lần thành công từ ASN                             | thành công, có ASN|
| `ok:u:<tài khoản>`   | log  | mỗi lần thành công vào tài khoản (MR27)               | thành công, có TK |
| `nn:ip:<ip>`         | set  | tài khoản đăng nhập thành công từ IP mà cả IP lẫn thiết bị đều LẠ với tài khoản đó (MR28) | thành công, có TK |
| `otpf:u:<tài khoản>` | log  | mỗi lần nhập sai mã OTP (MR28, ghi từ `POST /login/verify-otp`) | ngoài `record` |
| `blk:u:<tên>`        | log  | mỗi lần thử bị từ chối vì tài khoản/IP đang bị khoá (MR28, ghi từ `POST /login`) | ngoài `record` |
| `blk:ip:<ip>`        | log  | như trên, theo IP                                     | ngoài `record`    |
| `ctx:u:<tài khoản>`  | set  | `quốc gia|ip` của đăng nhập thành công                | thành công, có TK |
| `cc:u:<tên>`         | set  | quốc gia của MỌI lần thử vào tên đăng nhập            | có quốc gia       |

Giữ 24 giờ (`RETENTION_SHORT`); riêng `cc:u` giữ 7 ngày (`RETENTION_LONG`). Tham số cửa sổ của luật bị chặn ở đúng hai mức này (`Param.maximum`).
"""

from __future__ import annotations

from app.detection.engine.state import WindowStore
from app.detection.engine.types import AccountHistory, LoginAttempt

RETENTION_SHORT = 24 * 3600.0
RETENTION_LONG = 7 * 24 * 3600.0
CAP = 200  # chặn chi phí đếm giá trị khác nhau ở MemoryStore: luật chỉ cần biết "≥ ngưỡng" (ngưỡng luôn nhỏ hơn CAP)


def fail_user(username: str) -> str:
    return f"fail:u:{username}"


def fail_ips_of_user(username: str) -> str:
    return f"fi:u:{username}"


def fail_ip(ip: str) -> str:
    return f"fail:ip:{ip}"


def fail_users_of_ip(ip: str) -> str:
    return f"fu:ip:{ip}"


def fail_agents_of_ip(ip: str) -> str:
    return f"fua:ip:{ip}"


def unknown_users_of_ip(ip: str) -> str:
    return f"nx:ip:{ip}"


def fail_asn(asn: int) -> str:
    return f"fail:asn:{asn}"


def fail_users_of_asn(asn: int) -> str:
    return f"fu:asn:{asn}"


def ok_ip(ip: str) -> str:
    return f"ok:ip:{ip}"


def ok_asn(asn: int) -> str:
    return f"ok:asn:{asn}"


def ok_user(user_key: str) -> str:
    return f"ok:u:{user_key}"


def new_context_users_of_ip(ip: str) -> str:
    return f"nn:ip:{ip}"


def otp_fail_user(user_key: str) -> str:
    return f"otpf:u:{user_key}"


def blocked_user(username: str) -> str:
    return f"blk:u:{username.lower()}"  # khoá theo tên đăng nhập đã chuẩn hoá (`Blocklist` so khớp chữ thường)


def blocked_ip(ip: str) -> str:
    return f"blk:ip:{ip}"


def contexts_of_user(user_key: str) -> str:
    return f"ctx:u:{user_key}"


def countries_of_username(username: str) -> str:
    return f"cc:u:{username}"


def context_value(country: str | None, ip: str) -> str:
    return f"{country or '?'}|{ip}"


def record(store: WindowStore, a: LoginAttempt, history: AccountHistory | None = None) -> None:
    """Ghi MỘT lần thử vào mọi chỉ mục liên quan. Gọi TRƯỚC khi chấm luật, nên số đếm đã gồm chính lần thử này. `history`: lịch sử của
    tài khoản TRƯỚC lần thử này (để biết IP/thiết bị có lạ với tài khoản không — `nn:ip`)."""
    if a.success:
        store.log_add(ok_ip(a.ip), a.ts, RETENTION_SHORT)
        if a.asn is not None:
            store.log_add(ok_asn(a.asn), a.ts, RETENTION_SHORT)
        if a.user_key is not None:
            store.log_add(ok_user(a.user_key), a.ts, RETENTION_SHORT)
            store.set_add(contexts_of_user(a.user_key), a.ts, context_value(a.country, a.ip), RETENTION_SHORT)
            if is_new_context(a, history):
                store.set_add(new_context_users_of_ip(a.ip), a.ts, a.user_key, RETENTION_SHORT)
    else:
        store.log_add(fail_user(a.username), a.ts, RETENTION_SHORT)
        store.set_add(fail_ips_of_user(a.username), a.ts, a.ip, RETENTION_SHORT)
        store.log_add(fail_ip(a.ip), a.ts, RETENTION_SHORT)
        store.set_add(fail_users_of_ip(a.ip), a.ts, a.username, RETENTION_SHORT)
        if a.ua_hash:
            store.set_add(fail_agents_of_ip(a.ip), a.ts, a.ua_hash, RETENTION_SHORT)
        if a.user_key is None:
            store.set_add(unknown_users_of_ip(a.ip), a.ts, a.username, RETENTION_SHORT)
        if a.asn is not None:
            store.log_add(fail_asn(a.asn), a.ts, RETENTION_SHORT)
            store.set_add(fail_users_of_asn(a.asn), a.ts, a.username, RETENTION_SHORT)
    if a.country:
        store.set_add(countries_of_username(a.username), a.ts, a.country, RETENTION_LONG)


def is_new_context(a: LoginAttempt, history: AccountHistory | None) -> bool:
    """MR28: lần THÀNH CÔNG này đến từ IP VÀ thiết bị đều chưa từng đăng nhập thành công vào tài khoản (tài khoản chưa có lịch sử thành
    công thì không tính — lần đầu của mọi tài khoản đều "lạ"). Người dùng sau NAT văn phòng (IP quen) hay ở wifi hội nghị bằng máy của mình
    (thiết bị quen) không lạ cả hai."""
    if history is None or history.n_success == 0:
        return False
    return a.ip not in history.known_ips and (not a.ua_hash or a.ua_hash not in history.known_devices)


def record_otp_failure(store: WindowStore, user_key: str, ts: float) -> None:
    """MR28: một lần nhập sai mã OTP của tài khoản (`POST /login/verify-otp`) — luật `otp_guessing` đọc ở lần đăng nhập kế tiếp."""
    store.log_add(otp_fail_user(user_key), ts, RETENTION_SHORT)


def record_blocked(store: WindowStore, username: str, ip: str, ts: float) -> None:
    """MR28: một lần thử bị `POST /login` từ chối ngay vì tài khoản/IP đang bị khoá (không qua pipeline) — luật `blocked_retry` đọc khi
    khoá hết hạn."""
    store.log_add(blocked_user(username), ts, RETENTION_SHORT)
    store.log_add(blocked_ip(ip), ts, RETENTION_SHORT)
