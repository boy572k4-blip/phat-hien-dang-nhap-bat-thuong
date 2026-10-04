"""MR20 — Ngữ cảnh đăng nhập dùng chung: mọi lịch sử mà các bộ phát hiện cần cho MỘT lần đăng nhập, dựng MỘT lần.

Trước MR20, cùng một lần đăng nhập bị đọc lịch sử nhiều lần, mỗi bộ một kiểu: rule engine v2 (`DbAccountHistory`) và
đặc trưng RBA (`_user_events`) đều nạp TOÀN BỘ lịch sử tài khoản (không giới hạn dòng) vào Python rồi tự đếm; đặc trưng
IP/ASN nạp từng lần thử trong 24 giờ của IP/ASN đó (một đợt tấn công dồn dập làm mọi lần chấm sau chậm dần); hai bộ đếm
toàn cục (`GlobalCountsCache` của đặc trưng, `DbGlobalStats` của luật nhà mạng hiếm) cùng quét toàn bảng — bộ sau còn
quét lại ở MỖI lần đăng nhập có ASN vì được dựng mới mỗi lần. Số đo trước/sau ở `docs/performance.md` (mục MR20).

Giờ mọi phép đếm do DB làm, Python chỉ nhận vài con số. Ba mảnh, dùng chung cho rule engine v2, đặc trưng RBA của mô
hình `hybrid_cp2` và novelty của cảnh báo (MR13):
  - `AccountSnapshot` — lịch sử MỘT tài khoản TRƯỚC lần thử: một truy vấn đếm (số lần thử/thành công, các mốc thời gian,
    chuỗi thất bại, cửa sổ 1 giờ/24 giờ/7 ngày, toạ độ lần gần nhất) và một truy vấn gom các lần THÀNH CÔNG theo 7
    thuộc tính (tài khoản bình thường chỉ có vài nhóm), đều qua chỉ mục `ix_login_events_user_created`.
    `InfraStats` của IP và của ASN — mỗi bên một truy vấn đếm.
  - `GlobalCountsCache` — MỘT bộ đếm toàn cục cho cả đặc trưng lẫn luật, có khoá: khi hết hạn chỉ MỘT request tính lại,
    các request đến cùng lúc chờ rồi dùng chung kết quả. DB cũng gom nhóm sẵn nên mỗi lần tính lại chỉ còn vài trăm dòng.
  - `LoginContext` — lần thử đã chuẩn hoá (`LoginAttempt` cho luật, `EventRecord` cho đặc trưng) + các mảnh trên. GeoIP,
    ASN và phân tích UA đã được tra MỘT lần trước khi ghi `LoginEvent` (app/detection/pipeline.py) và nằm sẵn trong các
    cột của dòng đó — ngữ cảnh đọc lại từ đây, không tra lại.

Đặc trưng tính ra GIỐNG HỆT cách cũ: `tests/test_login_context.py` so từng lần đăng nhập trên dữ liệu ngẫu nhiên với đặc
tả `ml/rba/features.py` (chính đặc tả đã được so với DuckDB ở MR3) và với mã cũ của rule engine/novelty. Quy ước "chỉ
nhìn quá khứ" giữ nguyên như MR3: mọi truy vấn lấy `created_at < before`, cửa sổ là (before − W, before).
"""

from __future__ import annotations

import logging
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import bindparam, distinct, func, select
from sqlalchemy.orm import Session, aliased

from app.detection.engine.types import AccountHistory, LoginAttempt, ua_hash
from app.models import LoginEvent
from app.utils.time import ensure_utc
from ml.rba.features import (
    FREEMAN_ATTRS,
    NULL_KEY,
    EventRecord,
    GlobalCounts,
    HistorySummary,
    InfraStats,
    UserHistory,
    attr_key,
    features_from_summary,
)

logger = logging.getLogger("login_context")

WINDOW_1H = timedelta(hours=1)
WINDOW_24H = timedelta(hours=24)
WINDOW_7D = timedelta(days=7)
GLOBAL_COUNTS_CACHE_TTL_SECONDS = 30.0
# Request đồng thời đến pipeline KHÔNG theo đúng thứ tự thời điểm đăng nhập (bcrypt mỗi request nhanh chậm khác nhau):
# khi làm mới, mốc cắt lùi lại chừng này giây để các lần thử "đến muộn" trong khoảng đó vẫn dùng chung được bản đếm.
GLOBAL_COUNTS_OUT_OF_ORDER_SECONDS = 5.0

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_US = timedelta(microseconds=1)


def to_us(moment: datetime) -> int:
    """Epoch micro-giây UTC, tính bằng số nguyên (không qua số thực) — so sánh cửa sổ trong DB (`created_at > before − W`)
    và trong đặc tả (`ts_us > t − W`) khớp nhau theo đúng định nghĩa, không phụ thuộc làm tròn."""
    return (ensure_utc(moment) - _EPOCH) // _ONE_US


def before_of(record: EventRecord) -> datetime:
    """Mốc "trước" (datetime UTC) của một `EventRecord`, so được với `LoginEvent.created_at` (timezone=True, lưu UTC)."""
    return _EPOCH + timedelta(microseconds=record.ts_us)


def event_record_for(event: LoginEvent) -> EventRecord:
    """`EventRecord` của chính lần thử đang chấm (đã `db.flush()`, có `created_at`)."""
    return EventRecord(
        ts_us=to_us(event.created_at), user_id=event.user_id, ip=event.ip_address, asn=event.asn, country=event.country,
        ua=event.user_agent, browser=event.browser_name, os=event.os_name, device_type=event.device_type, success=event.success,
    )


# 7 thuộc tính mà đặc trưng Freeman/độ hiếm, novelty và luật v2 so sánh — DB gom các lần thành công theo đúng bộ này.
_PROFILE_COLUMNS = (
    LoginEvent.ip_address, LoginEvent.country, LoginEvent.asn, LoginEvent.user_agent, LoginEvent.browser_name,
    LoginEvent.os_name, LoginEvent.device_type,
)


@dataclass(frozen=True)
class SuccessGroup:
    """Các lần đăng nhập THÀNH CÔNG giống hệt nhau ở cả 7 thuộc tính của `_PROFILE_COLUMNS` — đơn vị mà DB gom sẵn
    (`GROUP BY`) thay cho từng dòng lịch sử. Tài khoản bình thường chỉ có vài nhóm (vài thiết bị, vài mạng quen)."""

    ip: str
    country: str | None
    asn: int | None
    user_agent: str | None
    browser: str | None
    os: str | None
    device_type: str | None
    count: int

    def as_record(self) -> EventRecord:
        """`EventRecord` đại diện cho cả nhóm (thời điểm không dùng tới) — để lấy `attr_key` đúng như đặc tả."""
        return EventRecord(
            ts_us=0, user_id=None, ip=self.ip, asn=self.asn, country=self.country, ua=self.user_agent, browser=self.browser,
            os=self.os, device_type=self.device_type, success=True,
        )


def _counts_by_attr(groups: Iterable[SuccessGroup]) -> tuple[int, dict[str, Counter]]:
    """(tổng số lần, FREEMAN_ATTRS -> Counter(attr_key -> số lần)). Thứ tự chèn của mỗi Counter theo thứ tự `groups`."""
    total = 0
    counts: dict[str, Counter] = {a: Counter() for a in FREEMAN_ATTRS}
    for group in groups:
        record = group.as_record()
        total += group.count
        for a in FREEMAN_ATTRS:
            counts[a][attr_key(record, a)] += group.count
    return total, counts


def _distinct_count(column, *window):
    """`count(DISTINCT coalesce(column, '∅')) FILTER (WHERE window)` — thiếu dữ liệu tính là MỘT giá trị, đúng như
    `attr_key` của đặc tả; cột không bao giờ NULL (ip_address) thì coalesce không đổi gì."""
    return func.count(distinct(func.coalesce(column, NULL_KEY))).filter(*window)


# --------------------------------------------------------------------------------------------- lịch sử MỘT tài khoản


@dataclass(frozen=True)
class AccountSnapshot:
    """Lịch sử MỘT tài khoản TRƯỚC lần thử đang chấm, dạng tổng hợp — nguồn DUY NHẤT cho mọi bộ phát hiện cần lịch sử tài
    khoản: đặc trưng RBA (`user_history`), rule engine v2 (`account_history`), novelty của cảnh báo MR13 (đọc qua
    `HistorySummary.user`)."""

    n_attempts: int
    n_success: int
    first_at: datetime | None
    last_at: datetime | None
    last_success_at: datetime | None
    attempts_after_last_success: int  # chỉ có nghĩa khi đã từng thành công
    attempts_1h: int
    attempts_24h: int
    fails_24h: int
    distinct_ips_24h: int
    distinct_countries_7d: int
    last_latitude: float | None  # toạ độ của lần thử gần nhất (mọi kết quả) — cho impossible travel
    last_longitude: float | None
    success_groups: tuple[SuccessGroup, ...]  # theo thứ tự xuất hiện lần đầu

    def user_history(self) -> UserHistory:
        """Dạng mà đặc trưng RBA (`ml/rba/features.py`) đọc."""
        _total, counts = _counts_by_attr(self.success_groups)
        return UserHistory(
            n_attempts=self.n_attempts,
            n_success=self.n_success,
            first_ts_us=None if self.first_at is None else to_us(self.first_at),
            last_ts_us=None if self.last_at is None else to_us(self.last_at),
            last_success_ts_us=None if self.last_success_at is None else to_us(self.last_success_at),
            fail_streak=self.n_attempts if self.last_success_at is None else self.attempts_after_last_success,
            success_counts=counts,
            attempts_1h=self.attempts_1h,
            attempts_24h=self.attempts_24h,
            fails_24h=self.fails_24h,
            distinct_ips_24h=self.distinct_ips_24h,
            distinct_countries_7d=self.distinct_countries_7d,
        )

    def account_history(self) -> AccountHistory | None:
        """Dạng mà rule engine v2 (`app/detection/engine`) đọc; `None` nếu tài khoản chưa có lần thử nào trước đó."""
        if self.n_attempts == 0:
            return None
        countries: list[str] = []
        devices: list[str] = []
        ips: list[str] = []
        for group in self.success_groups:
            if group.country and group.country not in countries:
                countries.append(group.country)
            hashed = ua_hash(group.user_agent)
            if hashed and hashed not in devices:
                devices.append(hashed)
            if group.ip and group.ip not in ips:
                ips.append(group.ip)
        return AccountHistory(
            last_event_ts=ensure_utc(self.last_at).timestamp(),
            last_event_lat=self.last_latitude,
            last_event_lon=self.last_longitude,
            last_success_ts=None if self.last_success_at is None else ensure_utc(self.last_success_at).timestamp(),
            n_success=self.n_success,
            known_countries=tuple(countries),
            known_devices=tuple(devices),
            known_ips=tuple(ips),
        )


# Các câu truy vấn được DỰNG MỘT LẦN khi nạp module, mỗi lần đăng nhập chỉ truyền tham số (`bindparam`): dựng lại cây
# biểu thức SQLAlchemy (bí danh, truy vấn con) ở mỗi lần gọi tốn nhiều thời gian hơn chính DB thực thi — đo được ~5 ms
# so với ~1,5 ms (docs/performance.md, mục MR20). Tham số chung: `before` và các mốc đầu cửa sổ `since_*` (= before − W).
_IN_1H = LoginEvent.created_at > bindparam("since_1h")
_IN_24H = LoginEvent.created_at > bindparam("since_24h")
_IN_7D = LoginEvent.created_at > bindparam("since_7d")
_SUCCEEDED = LoginEvent.success.is_(True)
_FAILED = LoginEvent.success.is_(False)


def _build_account_statements():
    in_past = (LoginEvent.user_id == bindparam("user_id"), LoginEvent.created_at < bindparam("before"))

    # Truy vấn con dùng BÍ DANH riêng: nếu dùng chính bảng `login_events` của truy vấn ngoài, SQLAlchemy tự tương quan
    # (correlate) hai bên và truy vấn con chỉ còn thấy đúng MỘT dòng đang xét.
    def past_rows():
        past = aliased(LoginEvent)
        return past, (past.user_id == bindparam("user_id"), past.created_at < bindparam("before"))

    def latest(column: str):
        """Giá trị `column` của lần thử gần nhất (trùng thời điểm thì lấy dòng ghi sau)."""
        past, condition = past_rows()
        return select(getattr(past, column)).where(*condition).order_by(past.created_at.desc(), past.id.desc()).limit(1).scalar_subquery()

    past, condition = past_rows()
    last_success_at = select(func.max(past.created_at)).where(*condition, past.success.is_(True)).scalar_subquery()
    counts = select(
        func.count().label("n_attempts"),
        func.count().filter(_SUCCEEDED).label("n_success"),
        func.min(LoginEvent.created_at).label("first_at"),
        func.max(LoginEvent.created_at).label("last_at"),
        func.max(LoginEvent.created_at).filter(_SUCCEEDED).label("last_success_at"),
        func.count().filter(LoginEvent.created_at > last_success_at).label("attempts_after_last_success"),
        func.count().filter(_IN_1H).label("attempts_1h"),
        func.count().filter(_IN_24H).label("attempts_24h"),
        func.count().filter(_IN_24H, _FAILED).label("fails_24h"),
        _distinct_count(LoginEvent.ip_address, _IN_24H).label("distinct_ips_24h"),
        _distinct_count(LoginEvent.country, _IN_7D).label("distinct_countries_7d"),
        latest("latitude").label("last_latitude"),
        latest("longitude").label("last_longitude"),
    ).where(*in_past)
    groups = select(*_PROFILE_COLUMNS, func.count(), func.min(LoginEvent.created_at)).where(*in_past, _SUCCEEDED).group_by(*_PROFILE_COLUMNS)
    return counts, groups


_ACCOUNT_COUNTS, _ACCOUNT_SUCCESS_GROUPS = _build_account_statements()


def _window_params(before: datetime) -> dict[str, datetime]:
    return {"before": before, "since_1h": before - WINDOW_1H, "since_24h": before - WINDOW_24H, "since_7d": before - WINDOW_7D}


def fetch_account_snapshot(db: Session, user_id: int, before: datetime) -> AccountSnapshot:
    """`AccountSnapshot` của tài khoản `user_id` từ mọi lần thử có `created_at < before`: một truy vấn đếm, thêm một truy
    vấn gom nhóm khi tài khoản đã từng đăng nhập thành công. Số dòng chuyển sang Python không phụ thuộc độ dài lịch sử."""
    params = {"user_id": user_id, **_window_params(ensure_utc(before))}
    connection = db.connection()
    row = connection.execute(_ACCOUNT_COUNTS, params).one()
    groups: tuple[SuccessGroup, ...] = ()
    if row.n_success:
        rows = connection.execute(_ACCOUNT_SUCCESS_GROUPS, params).all()
        groups = tuple(SuccessGroup(*r[:-1]) for r in sorted(rows, key=lambda r: ensure_utc(r[-1])))
    return AccountSnapshot(**row._asdict(), success_groups=groups)


# --------------------------------------------------------------------------------------------- IP / ASN gần đây


def _build_infra_statement(column, *, with_all_time: bool):
    """Một truy vấn đếm cho mọi lần thử có `column == value` và `created_at < before`. Không cần số "mọi thời điểm" (ASN)
    thì chỉ đọc 24 giờ gần nhất — không đếm toàn bộ lịch sử của một nhà mạng (có thể là phần lớn bảng)."""
    where = [column == bindparam("value"), LoginEvent.created_at < bindparam("before")]
    if not with_all_time:
        where.append(_IN_24H)
    return select(
        func.count().filter(_IN_1H).label("attempts_1h"),
        func.count().filter(_IN_24H).label("attempts_24h"),
        func.count().filter(_IN_24H, _FAILED).label("fails_24h"),
        func.count(distinct(LoginEvent.user_id)).filter(_IN_24H).label("distinct_users_24h"),  # count(DISTINCT) bỏ qua NULL = tên không tồn tại
        func.count().filter(_IN_24H, LoginEvent.user_id.is_(None)).label("unknown_attempts_24h"),
        _distinct_count(LoginEvent.user_agent, _IN_24H).label("distinct_uas_24h"),
        _distinct_count(LoginEvent.ip_address, _IN_24H).label("distinct_ips_24h"),
        func.count().label("attempts_all"),
    ).where(*where)


_IP_STATS = _build_infra_statement(LoginEvent.ip_address, with_all_time=True)
_ASN_STATS = _build_infra_statement(LoginEvent.asn, with_all_time=False)


def fetch_ip_stats(db: Session, ip: str, before: datetime) -> InfraStats:
    """`InfraStats` của IP `ip` từ mọi lần thử trước `before` (mọi tài khoản) — một truy vấn đếm, trả MỘT dòng."""
    return InfraStats(**db.connection().execute(_IP_STATS, {"value": ip, **_window_params(ensure_utc(before))}).one()._asdict())


def fetch_asn_stats(db: Session, asn: int, before: datetime) -> InfraStats:
    """Như `fetch_ip_stats` cho ASN, chỉ 24 giờ gần nhất (`attempts_all` là None)."""
    stats = db.connection().execute(_ASN_STATS, {"value": asn, **_window_params(ensure_utc(before))}).one()._asdict()
    return InfraStats(**{**stats, "attempts_all": None})


# ------------------------------------------------------------------------------------------------ đếm toàn cục, dùng chung


class GlobalCountsCache:
    """`GlobalCounts` (MR3) của MỌI đăng nhập thành công vào tài khoản có thật, TOÀN BẢNG — dùng chung cho độ hiếm/Freeman
    của đặc trưng RBA VÀ luật `rare_network_login` (trước MR20 là hai bộ đếm riêng, xem docstring module).

    Bảo đảm: (1) KHÔNG BAO GIỜ THỪA — bản đếm chỉ gồm dòng có `created_at` trước mốc cắt, và chỉ được dùng cho lần thử có
    `before` không sớm hơn mốc cắt, nên không thể lẫn chính lần thử đang chấm hay lần thử sau nó; (2) có thể THIẾU các dòng
    gần nhất — tối đa `ttl_seconds` tính theo THỜI GIAN SỰ KIỆN (không phải giờ hệ thống, nên kịch bản mô phỏng nhảy nhiều
    ngày vẫn đúng), ảnh hưởng không đáng kể tới độ hiếm của vài nghìn lượt; (3) khi hết hạn chỉ MỘT luồng tính lại (khoá),
    luồng khác chờ rồi dùng chung kết quả. Mốc cắt khi làm mới lùi `out_of_order_seconds` so với lần thử kích hoạt, để lần
    thử đến pipeline muộn hơn một chút (request đồng thời) vẫn dùng chung được thay vì bắt tính lại."""

    def __init__(self, ttl_seconds: float = GLOBAL_COUNTS_CACHE_TTL_SECONDS, out_of_order_seconds: float = GLOBAL_COUNTS_OUT_OF_ORDER_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self.out_of_order_seconds = out_of_order_seconds
        self.refreshes = 0  # số lần đã thực sự quét lại bảng (chẩn đoán, test)
        self._lock = threading.Lock()
        self._snapshot: tuple[GlobalCounts, datetime] | None = None  # (bản đếm, mốc cắt) — gán cả cặp một lần, luồng khác không đọc lệch

    def _usable(self, snapshot: tuple[GlobalCounts, datetime] | None, before: datetime) -> bool:
        if snapshot is None:
            return False
        cutoff = snapshot[1]
        return cutoff <= before and (before - cutoff).total_seconds() <= self.ttl_seconds

    def get(self, db: Session, before: datetime) -> GlobalCounts:
        """Bản đếm dùng được cho lần thử tại `before` (xem bảo đảm ở docstring lớp)."""
        before = ensure_utc(before)
        snapshot = self._snapshot
        if self._usable(snapshot, before):
            return snapshot[0]
        with self._lock:
            snapshot = self._snapshot  # một luồng khác có thể vừa làm mới trong lúc chờ khoá
            if self._usable(snapshot, before):
                return snapshot[0]
            cutoff = before - timedelta(seconds=self.out_of_order_seconds)
            counts = self._compute(db, cutoff)
            self._snapshot = (counts, cutoff)
            self.refreshes += 1
            return counts

    def invalidate(self) -> None:
        with self._lock:
            self._snapshot = None

    @staticmethod
    def _compute(db: Session, cutoff: datetime) -> GlobalCounts:
        rows = db.connection().execute(_GLOBAL_SUCCESS_GROUPS, {"cutoff": cutoff}).all()
        total, counts = _counts_by_attr(SuccessGroup(*row) for row in rows)
        return GlobalCounts(total=total, by_attr=counts)


# Mọi lần THÀNH CÔNG vào tài khoản có thật trước mốc cắt, DB gom sẵn theo 7 thuộc tính (vài trăm nhóm thay vì hàng nghìn dòng).
_GLOBAL_SUCCESS_GROUPS = (
    select(*_PROFILE_COLUMNS, func.count())
    .where(_SUCCEEDED, LoginEvent.user_id.isnot(None), LoginEvent.created_at < bindparam("cutoff"))
    .group_by(*_PROFILE_COLUMNS)
)


_global_counts_cache = GlobalCountsCache()


def shared_global_counts(db: Session, before: datetime) -> GlobalCounts:
    return _global_counts_cache.get(db, before)


def invalidate_global_counts() -> None:
    """Bỏ bản đếm toàn cục dùng chung (test dùng giữa các DB khác nhau; luồng thật không cần — đã có TTL)."""
    _global_counts_cache.invalidate()


# ------------------------------------------------------------------------------------------------ tổng hợp + ngữ cảnh


def build_history_summary(
    db: Session, record: EventRecord, *, account: AccountSnapshot | None = None, cache: GlobalCountsCache | None = None
) -> HistorySummary:
    """`HistorySummary` (MR3) cho `record`. `account`: lịch sử tài khoản đã dựng sẵn (bỏ qua thì tự truy vấn); `cache`:
    bộ đếm toàn cục riêng (bỏ qua thì dùng bộ dùng chung của tiến trình)."""
    before = before_of(record)
    if record.user_id is not None and account is None:
        account = fetch_account_snapshot(db, record.user_id, before)
    return HistorySummary(
        user=None if record.user_id is None else account.user_history(),
        ip=fetch_ip_stats(db, record.ip, before),
        asn=None if record.asn is None else fetch_asn_stats(db, record.asn, before),
        global_counts=(_global_counts_cache if cache is None else cache).get(db, before),
    )


@dataclass(frozen=True)
class LoginContext:
    """MỘT lần đăng nhập đã chuẩn hoá + mọi lịch sử liên quan, dựng một lần bởi `build_login_context` rồi đưa cho rule
    engine v2 (`attempt`, `account_history`, `summary.global_counts`), đặc trưng RBA của mô hình (`rba_features`) và
    novelty của cảnh báo MR13 (`record`, `summary`)."""

    attempt: LoginAttempt
    record: EventRecord
    account: AccountSnapshot | None  # None: tên đăng nhập không tồn tại
    account_history: AccountHistory | None
    summary: HistorySummary

    def rba_features(self) -> dict[str, float] | None:
        """50 đặc trưng RBA, `None` nếu lỗi (không bao giờ raise — thiếu đặc trưng chỉ tắt thành phần ML, luật vẫn chạy)."""
        try:
            return features_from_summary(self.record, self.summary)
        except Exception:  # noqa: BLE001
            logger.exception("lỗi khi tính đặc trưng RBA cho user_id=%s ip=%s — bỏ qua thành phần ML", self.record.user_id, self.record.ip)
            return None


def build_login_context(db: Session, event: LoginEvent, *, username: str, cache: GlobalCountsCache | None = None) -> LoginContext:
    """`event`: lần thử vừa ghi (đã `flush`); `username`: tên người dùng gõ (kể cả tên không tồn tại)."""
    record = event_record_for(event)
    account = None if event.user_id is None else fetch_account_snapshot(db, event.user_id, before_of(record))
    attempt = LoginAttempt(
        ts=ensure_utc(event.created_at).timestamp(), username=username, success=event.success, ip=event.ip_address,
        user_key=None if event.user_id is None else str(event.user_id), asn=event.asn, country=event.country, city=event.city,
        latitude=event.latitude, longitude=event.longitude, user_agent=event.user_agent, browser=event.browser_name,
        os=event.os_name, device_type=event.device_type,
    )
    return LoginContext(
        attempt=attempt,
        record=record,
        account=account,
        account_history=None if account is None else account.account_history(),
        summary=build_history_summary(db, record, account=account, cache=cache),
    )
