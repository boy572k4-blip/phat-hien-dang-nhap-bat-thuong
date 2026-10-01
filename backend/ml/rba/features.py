"""Đặc trưng v2 (MR3) — ĐẶC TẢ bằng Python thuần.

Đây là định nghĩa gốc của mọi đặc trưng. Hai nơi dùng nó:
  - luồng realtime (MR12): dựng `HistorySummary` từ DB rồi gọi `features_from_summary`;
  - kiểm chứng: `features_sql.py` tính cùng các đặc trưng bằng DuckDB trên toàn bộ dữ liệu
    (nhanh gấp hàng nghìn lần) và test chứng minh hai bên cho kết quả bằng nhau.

Quy ước "trước đó" (chống rò rỉ): chỉ sự kiện có `ts_us` NHỎ HƠN HẲN sự kiện hiện tại mới được
tính (sự kiện cùng micro-giây loại trừ lẫn nhau). Cửa sổ thời gian là (t - W, t), mở ở đầu cũ.
Đặc trưng không bao giờ dùng nhãn (`Is Attack IP`, `Is Account Takeover`).

Tài khoản không tồn tại (`user_id = None`; trong RBA là "thùng chứa" -4324475583306591935):
đặc trưng theo user = NaN, đặc trưng cấp IP/ASN và độ hiếm toàn cục vẫn tính.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence

US_PER_SECOND = 1_000_000
W_1H = 3_600 * US_PER_SECOND
W_24H = 24 * W_1H
W_7D = 7 * W_24H
DAY_US = W_24H

ALPHA = 1.0  # độ mạnh của prior toàn cục khi làm mịn p_user (Freeman)
NULL_KEY = "∅"  # giá trị thay cho thiếu dữ liệu khi so sánh/đếm
RBA_CATCHALL_USER_ID = -4324475583306591935  # "thùng chứa" tài khoản không tồn tại trong RBA

NOVELTY_ATTRS = ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")
FREEMAN_ATTRS = ("ip", "country", "asn", "ua", "browser", "os", "device")

DEVICE_CODES = {"mobile": 0, "desktop": 1, "tablet": 2, "bot": 3, "unknown": 4}
DEVICE_CODE_MISSING = 5

_VERSION_SUFFIX = re.compile(r" +[0-9][0-9.]*$")

FEATURE_GROUPS: dict[str, list[str]] = {
    "cur": ["cur_success", "cur_device_code"],
    "novelty": [f"new_{a}" for a in NOVELTY_ATTRS],
    "history": ["u_n_attempts", "u_n_success", "u_age_days"],
    "rhythm": [
        "u_secs_since_last", "u_secs_since_last_success", "u_fail_streak", "u_attempts_1h",
        "u_attempts_24h", "u_fails_24h", "u_distinct_ips_24h", "u_distinct_countries_7d",
    ],
    "freeman": [f"llr_{a}" for a in FREEMAN_ATTRS] + ["llr_sum"],
    "rarity": [f"rare_{a}" for a in FREEMAN_ATTRS],
    "infra_ip": [
        "ip_attempts_1h", "ip_attempts_24h", "ip_fail_ratio_24h", "ip_distinct_users_24h",
        "ip_unknown_attempts_24h", "ip_distinct_ua_24h", "ip_prior_attempts_all",
    ],
    "infra_asn": [
        "asn_attempts_1h", "asn_attempts_24h", "asn_fail_ratio_24h", "asn_distinct_users_24h",
        "asn_distinct_ips_24h", "asn_unknown_share_24h",
    ],
}
FEATURE_NAMES: list[str] = [name for names in FEATURE_GROUPS.values() for name in names]
FEATURE_VERSION = "v2"


def feature_signature() -> str:
    """Dấu vân tay của danh sách + thứ tự đặc trưng: đổi tên/thêm/bớt/đổi thứ tự thì đổi. Mô hình và bảng "thường thấy"
    lưu chữ ký lúc huấn luyện để phát hiện lệch phiên bản đặc trưng khi nạp."""
    return hashlib.sha1(",".join(FEATURE_NAMES).encode("utf-8")).hexdigest()[:12]


def strip_version(name: str) -> str:
    """'Chrome Mobile 46.0.2490' -> 'Chrome Mobile'. Không có hậu tố phiên bản thì giữ nguyên."""
    return _VERSION_SUFFIX.sub("", name)


@dataclass(frozen=True)
class EventRecord:
    ts_us: int
    user_id: int | None
    ip: str
    asn: int | None
    country: str | None
    ua: str | None
    browser: str | None
    os: str | None
    device_type: str | None
    success: bool


def attr_key(event: EventRecord, attr: str) -> str:
    """Giá trị so sánh của một thuộc tính (thiếu dữ liệu -> NULL_KEY)."""
    if attr == "ip":
        return event.ip
    if attr == "asn":
        return NULL_KEY if event.asn is None else str(event.asn)
    if attr == "browser_family":
        return strip_version(event.browser if event.browser is not None else NULL_KEY)
    if attr == "os_family":
        return strip_version(event.os if event.os is not None else NULL_KEY)
    value = {
        "country": event.country, "ua": event.ua, "browser": event.browser, "os": event.os,
        "device": event.device_type,
    }[attr]
    return NULL_KEY if value is None else value


@dataclass
class GlobalCounts:
    """Đếm toàn cục các lần đăng nhập THÀNH CÔNG của tài khoản thật đã xảy ra trước đó."""

    total: int = 0
    by_attr: dict[str, Counter] = field(default_factory=lambda: {a: Counter() for a in FREEMAN_ATTRS})

    @classmethod
    def from_events(cls, events: Iterable[EventRecord]) -> "GlobalCounts":
        counts = cls()
        for e in events:
            counts.total += 1
            for a in FREEMAN_ATTRS:
                counts.by_attr[a][attr_key(e, a)] += 1
        return counts


@dataclass(frozen=True)
class UserHistory:
    """Quá khứ của MỘT tài khoản (mọi lần thử TRƯỚC sự kiện đang tính) ở dạng TỔNG HỢP — đủ cho mọi đặc trưng theo user
    mà không phải giữ cả danh sách sự kiện. MR20: luồng thật dựng bản này bằng vài truy vấn gộp trong DB
    (`app/detection/login_context.py`) thay vì nạp toàn bộ lịch sử tài khoản; `from_events` dựng cùng nội dung từ một
    danh sách sự kiện (đặc tả, kiểm chứng) — test chứng minh hai cách cho ra cùng đặc trưng."""

    n_attempts: int
    n_success: int
    first_ts_us: int | None  # lần thử đầu tiên (None nếu chưa có lần nào)
    last_ts_us: int | None
    last_success_ts_us: int | None
    fail_streak: int  # số lần thử SAU lần thành công gần nhất; chưa thành công lần nào thì là mọi lần thử
    success_counts: dict[str, Counter]  # FREEMAN_ATTRS -> Counter(attr_key -> số lần THÀNH CÔNG), chèn theo thứ tự xuất hiện
    attempts_1h: int  # cửa sổ (t - W, t) như mọi cửa sổ khác của đặc tả
    attempts_24h: int
    fails_24h: int
    distinct_ips_24h: int
    distinct_countries_7d: int  # quốc gia khác nhau (thiếu GeoIP tính là một giá trị, như `attr_key`)

    @classmethod
    def from_events(cls, t_us: int, events: Sequence[EventRecord]) -> "UserHistory":
        """`events`: mọi lần thử của tài khoản TRƯỚC thời điểm `t_us`, theo thứ tự thời gian."""
        successes = [e for e in events if e.success]
        last_success = max((e.ts_us for e in successes), default=None)
        counts: dict[str, Counter] = {a: Counter() for a in FREEMAN_ATTRS}
        for e in successes:
            for a in FREEMAN_ATTRS:
                counts[a][attr_key(e, a)] += 1
        in_24h = [e for e in events if e.ts_us > t_us - W_24H]
        return cls(
            n_attempts=len(events),
            n_success=len(successes),
            first_ts_us=min((e.ts_us for e in events), default=None),
            last_ts_us=max((e.ts_us for e in events), default=None),
            last_success_ts_us=last_success,
            fail_streak=len(events) if last_success is None else sum(1 for e in events if e.ts_us > last_success),
            success_counts=counts,
            attempts_1h=sum(1 for e in events if e.ts_us > t_us - W_1H),
            attempts_24h=len(in_24h),
            fails_24h=sum(1 for e in in_24h if not e.success),
            distinct_ips_24h=len({e.ip for e in in_24h}),
            distinct_countries_7d=len({attr_key(e, "country") for e in events if e.ts_us > t_us - W_7D}),
        )

    def seen(self, attr: str, key: str) -> int:
        """Số lần THÀNH CÔNG trước đó có thuộc tính `attr` (NOVELTY_ATTRS hoặc FREEMAN_ATTRS) mang giá trị `key` (đã qua
        `attr_key`). Họ trình duyệt/hệ điều hành suy ra từ bộ đếm trình duyệt/hệ điều hành đầy đủ phiên bản."""
        if attr in ("browser_family", "os_family"):
            full = self.success_counts["browser" if attr == "browser_family" else "os"]
            return sum(n for value, n in full.items() if strip_version(value) == key)
        return self.success_counts[attr][key]


@dataclass(frozen=True)
class InfraStats:
    """Hành vi gần đây của MỘT IP hoặc MỘT ASN (mọi lần thử TRƯỚC sự kiện, mọi tài khoản), dạng tổng hợp — đủ cho các đặc
    trưng `infra_ip`/`infra_asn`. MR20: luồng thật để DB tự đếm, nên chi phí mỗi lần đăng nhập không tăng theo số lần thử
    dồn dập từ chính IP/ASN đó (trước đó nạp từng dòng trong 24 giờ — một đợt credential stuffing làm MỌI lần chấm sau chậm dần)."""

    attempts_1h: int
    attempts_24h: int
    fails_24h: int
    distinct_users_24h: int  # tài khoản có thật khác nhau
    unknown_attempts_24h: int  # lần thử vào tên đăng nhập không tồn tại
    distinct_uas_24h: int  # User-Agent khác nhau (thiếu UA tính là một giá trị, như `attr_key`)
    distinct_ips_24h: int
    attempts_all: int | None  # mọi thời điểm; chỉ đặc trưng IP cần (`ip_prior_attempts_all`), ASN để None

    @classmethod
    def from_events(cls, t_us: int, events: Sequence[EventRecord], *, with_all_time: bool = True) -> "InfraStats":
        """`events`: mọi lần thử cùng IP (hoặc cùng ASN) TRƯỚC thời điểm `t_us`, mọi thời điểm."""
        in_24h = [e for e in events if e.ts_us > t_us - W_24H]
        return cls(
            attempts_1h=sum(1 for e in in_24h if e.ts_us > t_us - W_1H),
            attempts_24h=len(in_24h),
            fails_24h=sum(1 for e in in_24h if not e.success),
            distinct_users_24h=len({e.user_id for e in in_24h if e.user_id is not None}),
            unknown_attempts_24h=sum(1 for e in in_24h if e.user_id is None),
            distinct_uas_24h=len({attr_key(e, "ua") for e in in_24h}),
            distinct_ips_24h=len({e.ip for e in in_24h}),
            attempts_all=len(events) if with_all_time else None,
        )


@dataclass
class HistorySummary:
    """Mọi thứ cần biết về quá khứ để tính đặc trưng của một sự kiện (đều strictly trước sự kiện)."""

    user: UserHistory | None  # cùng tài khoản, dạng tổng hợp (None nếu tài khoản không tồn tại)
    ip: InfraStats  # cùng IP
    asn: InfraStats | None  # cùng ASN (None nếu ASN không rõ)
    global_counts: GlobalCounts


def summarize_history(event: EventRecord, prior: Sequence[EventRecord]) -> HistorySummary:
    """Dựng HistorySummary bằng cách lọc thô toàn bộ sự kiện trước đó (chậm, chính xác — dùng cho test)."""
    t = event.ts_us
    before = [e for e in prior if e.ts_us < t]
    user = None
    if event.user_id is not None:
        user = UserHistory.from_events(t, [e for e in before if e.user_id == event.user_id])
    asn = None
    if event.asn is not None:
        asn = InfraStats.from_events(t, [e for e in before if e.asn == event.asn], with_all_time=False)
    return HistorySummary(
        user=user,
        ip=InfraStats.from_events(t, [e for e in before if e.ip == event.ip]),
        asn=asn,
        global_counts=GlobalCounts.from_events(e for e in before if e.success and e.user_id is not None),
    )


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator > 0 else math.nan


def features_from_summary(event: EventRecord, summary: HistorySummary) -> dict[str, float]:
    t = event.ts_us
    nan = math.nan
    f: dict[str, float] = {name: nan for name in FEATURE_NAMES}

    f["cur_success"] = 1.0 if event.success else 0.0
    f["cur_device_code"] = float(DEVICE_CODES.get(event.device_type, DEVICE_CODE_MISSING))

    gc = summary.global_counts
    p_global = {a: (gc.by_attr[a][attr_key(event, a)] + 1.0) / (gc.total + 1.0) for a in FREEMAN_ATTRS}
    for a in FREEMAN_ATTRS:
        f[f"rare_{a}"] = -math.log(p_global[a])

    uh = summary.user
    if uh is not None:
        n_success = uh.n_success
        f["u_n_attempts"] = float(uh.n_attempts)
        f["u_n_success"] = float(n_success)

        for a in NOVELTY_ATTRS:
            f[f"new_{a}"] = 1.0 if uh.seen(a, attr_key(event, a)) == 0 else 0.0

        llr_total = 0.0
        for a in FREEMAN_ATTRS:
            seen = uh.seen(a, attr_key(event, a))
            p_user = (seen + ALPHA * p_global[a]) / (n_success + ALPHA)
            llr = math.log(p_global[a]) - math.log(p_user)
            f[f"llr_{a}"] = llr
            llr_total += llr
        f["llr_sum"] = llr_total

        if uh.n_attempts:
            f["u_age_days"] = (t - uh.first_ts_us) / DAY_US
            f["u_secs_since_last"] = (t - uh.last_ts_us) / US_PER_SECOND
        if n_success:
            f["u_secs_since_last_success"] = (t - uh.last_success_ts_us) / US_PER_SECOND
        f["u_fail_streak"] = float(uh.fail_streak)

        f["u_attempts_1h"] = float(uh.attempts_1h)
        f["u_attempts_24h"] = float(uh.attempts_24h)
        f["u_fails_24h"] = float(uh.fails_24h)
        f["u_distinct_ips_24h"] = float(uh.distinct_ips_24h)
        f["u_distinct_countries_7d"] = float(uh.distinct_countries_7d)

    ip = summary.ip
    f["ip_attempts_24h"] = float(ip.attempts_24h)
    f["ip_attempts_1h"] = float(ip.attempts_1h)
    f["ip_fail_ratio_24h"] = _ratio(ip.fails_24h, ip.attempts_24h)
    f["ip_distinct_users_24h"] = float(ip.distinct_users_24h)
    f["ip_unknown_attempts_24h"] = float(ip.unknown_attempts_24h)
    f["ip_distinct_ua_24h"] = float(ip.distinct_uas_24h)
    f["ip_prior_attempts_all"] = float(ip.attempts_all)

    if event.asn is not None:
        asn = summary.asn
        f["asn_attempts_24h"] = float(asn.attempts_24h)
        f["asn_attempts_1h"] = float(asn.attempts_1h)
        f["asn_fail_ratio_24h"] = _ratio(asn.fails_24h, asn.attempts_24h)
        f["asn_distinct_users_24h"] = float(asn.distinct_users_24h)
        f["asn_distinct_ips_24h"] = float(asn.distinct_ips_24h)
        f["asn_unknown_share_24h"] = _ratio(asn.unknown_attempts_24h, asn.attempts_24h)

    return f


def compute_features_spec(event: EventRecord, prior: Sequence[EventRecord]) -> dict[str, float]:
    return features_from_summary(event, summarize_history(event, prior))
