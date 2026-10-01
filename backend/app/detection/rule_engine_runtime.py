"""Dựng `RuleEngine` (MR9-10) cho luồng thật /login (MR12): trạng thái cửa sổ trong Redis (bền qua restart, dùng chung
kết nối với `rate_counter.py`), lịch sử tài khoản DỰNG LẠI TỪ DB mỗi lần (không giữ trong bộ nhớ tiến trình) — luôn đúng
dù ứng dụng chạy nhiều tiến trình/worker hay vừa khởi động lại. Từ MR20 lịch sử ở dạng tổng hợp do DB tự đếm và thống kê
toàn cục dùng chung với đặc trưng RBA (`app/detection/login_context.py`); pipeline truyền sẵn cả hai qua `LoginContext`.

    engine = build_rule_engine(db)
    evaluation = engine.evaluate(attempt)   # record=True: cũng ghi vào Redis cho lần sau

`ThreatIntel` (Tor/datacenter/VPN) nạp MỘT LẦN khi tiến trình khởi động (`load_threat_intel_at_startup`, đổi rất hiếm khi
chạy `scripts/update_threat_feeds.py`); `blocklist` DB-backed nhưng cache TTL ngắn (đổi khi quản trị viên thao tác, cần
thấy tương đối nhanh, không đáng để truy vấn DB cho mỗi lần đăng nhập)."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection import rate_counter
from app.detection.engine import Blocklist, RedisStore, RuleConfig, RuleEngine, ThreatIntel
from app.detection.engine.intel import BlockEntry
from app.detection.engine.types import AccountHistory, LoginAttempt
from app.detection.login_context import LoginContext, fetch_account_snapshot, shared_global_counts
from app.models import BlocklistEntry, RuleOverride
from app.utils.time import ensure_utc
from ml.rba.features import GlobalCounts

logger = logging.getLogger("rule_engine_runtime")

BLOCKLIST_CACHE_TTL_SECONDS = 15.0
RULE_CONFIG_CACHE_TTL_SECONDS = 15.0  # cùng lý do/độ dài với blocklist — đổi qua GET/PUT/DELETE /rules (MR17), cần thấy tương đối nhanh
_THREAT_INTEL: ThreatIntel | None = None


def load_threat_intel_at_startup() -> ThreatIntel:
    global _THREAT_INTEL
    try:
        _THREAT_INTEL = ThreatIntel.load()
        logger.info("đã nạp threat intel: %s", _THREAT_INTEL.status())
    except Exception:  # noqa: BLE001 — danh sách lỗi/thiếu không được chặn khởi động; luật liên quan tự bỏ qua (Evaluation.skipped)
        logger.exception("lỗi khi nạp threat intel — luật Tor/datacenter/VPN sẽ bị bỏ qua")
        _THREAT_INTEL = ThreatIntel()
    return _THREAT_INTEL


def _get_threat_intel() -> ThreatIntel:
    if _THREAT_INTEL is None:
        return load_threat_intel_at_startup()
    return _THREAT_INTEL


# ------------------------------------------------------------------------------------------------ lịch sử tài khoản từ DB


@dataclass
class DbAccountHistory:
    """`HistoryProvider` đọc lịch sử tài khoản TRƯỚC mốc `before` qua `AccountSnapshot` (MR20, dạng tổng hợp do DB tự
    đếm — không nạp toàn bộ lịch sử). `preloaded`: lịch sử đã dựng sẵn theo `user_key` (pipeline truyền từ
    `LoginContext`, không truy vấn lại); tài khoản khác thì truy vấn rồi nhớ trong phạm vi đối tượng này. `update()` là
    no-op: lần chấm sau dựng đối tượng mới, đọc DB mới nhất (đã thấy chính lần thử vừa ghi)."""

    db: Session
    before: datetime  # lấy lịch sử TRƯỚC mốc này (thời điểm của lần thử đang chấm)
    preloaded: dict[str, AccountHistory | None] = field(default_factory=dict)

    def get(self, user_key: str | None) -> AccountHistory | None:
        if user_key is None:
            return None
        if user_key not in self.preloaded:
            try:
                user_id = int(user_key)
            except ValueError:
                return None
            self.preloaded[user_key] = fetch_account_snapshot(self.db, user_id, self.before).account_history()
        return self.preloaded[user_key]

    def update(self, attempt: LoginAttempt) -> None:
        pass  # xem docstring lớp


# ------------------------------------------------------------------------------------------------ thống kê toàn cục (nhà mạng), dùng chung với đặc trưng RBA


@dataclass
class SharedGlobalStats:
    """`GlobalStats` (dùng bởi `rare_network_login`) — đếm đăng nhập THÀNH CÔNG vào tài khoản có thật theo ASN, đọc từ
    CHÍNH bộ đếm toàn cục mà đặc trưng RBA dùng (`login_context.GlobalCountsCache`, MR20). Trước MR20 là bộ `DbGlobalStats`
    riêng, dựng mới mỗi lần chấm nên quét toàn bảng ở MỌI lần đăng nhập có ASN, và đếm cả chính lần thử đang chấm (lệch
    với replay hiệu chỉnh, nơi thống kê chỉ cập nhật SAU khi chấm). `counts`: bản đếm đã có sẵn (pipeline truyền từ
    `LoginContext`); không có thì chỉ lấy khi luật thật sự cần."""

    db: Session
    before: datetime
    counts: GlobalCounts | None = None

    def _counts(self) -> GlobalCounts:
        if self.counts is None:
            self.counts = shared_global_counts(self.db, self.before)
        return self.counts

    @property
    def total_successes(self) -> int:
        return self._counts().total

    def asn_successes(self, asn: int) -> int:
        return self._counts().by_attr["asn"][str(asn)]  # khoá theo `attr_key` của đặc tả MR3: ASN dạng chuỗi

    def update(self, attempt: LoginAttempt) -> None:
        pass  # bộ đếm dùng chung tự làm mới theo TTL


# ------------------------------------------------------------------------------------------------ blocklist DB-backed, cache TTL ngắn

_blocklist_cache: Blocklist | None = None
_blocklist_cached_at = -1.0


def refresh_blocklist(db: Session, force: bool = False) -> Blocklist:
    """`Blocklist` (bộ nhớ) dựng lại từ bảng `blocklist` mỗi `BLOCKLIST_CACHE_TTL_SECONDS` giây — quản trị viên thêm/xoá
    mục chặn được áp dụng trong khoảng đó, không phải ngay lập tức (đổi lấy không phải truy vấn DB cho mỗi lần đăng nhập)."""
    global _blocklist_cache, _blocklist_cached_at
    now = time.monotonic()
    if not force and _blocklist_cache is not None and now - _blocklist_cached_at < BLOCKLIST_CACHE_TTL_SECONDS:
        return _blocklist_cache
    blocklist = Blocklist()
    for row in db.execute(select(BlocklistEntry)).scalars():
        expires_at = None if row.expires_at is None else ensure_utc(row.expires_at).timestamp()
        blocklist.add_entry(BlockEntry(kind=row.kind, value=row.value, reason=row.reason or "", expires_at=expires_at, added_by=row.added_by))
    _blocklist_cache, _blocklist_cached_at = blocklist, now
    return blocklist


def invalidate_blocklist_cache() -> None:
    """Gọi ngay sau khi quản trị viên thêm/xoá một mục chặn, để không phải chờ hết TTL (MR13+ sẽ có router gọi hàm này)."""
    global _blocklist_cached_at
    _blocklist_cached_at = -1.0


# ------------------------------------------------------------------------------------------------ rule config DB-backed, cache TTL ngắn

_rule_config_cache: RuleConfig | None = None
_rule_config_cached_at = -1.0


def refresh_rule_config(db: Session, force: bool = False) -> RuleConfig:
    """`RuleConfig` dựng lại từ bảng `rule_overrides` mỗi `RULE_CONFIG_CACHE_TTL_SECONDS` giây (MR17) — trước đó luồng
    thật LUÔN chấm bằng mặc định của sổ đăng ký (`build_rule_engine(db)` gọi không truyền `config`, tương đương
    `RuleConfig()` rỗng); giờ đọc đè từ DB, cùng cơ chế cache với `refresh_blocklist` ở trên."""
    global _rule_config_cache, _rule_config_cached_at
    now = time.monotonic()
    if not force and _rule_config_cache is not None and now - _rule_config_cached_at < RULE_CONFIG_CACHE_TTL_SECONDS:
        return _rule_config_cache
    config = RuleConfig()
    for row in db.execute(select(RuleOverride)).scalars():
        if row.mode is not None:
            config.modes[row.rule_id] = row.mode
        if row.params is not None:
            config.params[row.rule_id] = dict(row.params)
    _rule_config_cache, _rule_config_cached_at = config, now
    return config


def invalidate_rule_config_cache() -> None:
    """Gọi ngay sau khi quản trị viên đổi cấu hình một luật (`PUT`/`DELETE /rules/{id}`, MR17)."""
    global _rule_config_cached_at
    _rule_config_cached_at = -1.0


# ------------------------------------------------------------------------------------------------ dựng engine


def build_rule_engine(
    db: Session, config: RuleConfig | None = None, *, before: datetime | None = None, context: LoginContext | None = None
) -> RuleEngine:
    """`RuleEngine` cho MỘT lần chấm. `store`: `RedisStore` dựng MỖI LẦN gọi trên `rate_counter.redis_client` hiện tại
    (không giữ client thành singleton ở module này — test thay `rate_counter.redis_client` bằng fakeredis qua
    `monkeypatch`, giữ singleton sẽ lỡ mất bản thay đó; dựng lại object `RedisStore` không tốn kém, chỉ giữ tham chiếu).
    Tiền tố khoá "rule:" (state.py) không đụng khoá của `rate_counter`. `intel` dùng chung/singleton (nạp một lần lúc
    khởi động). `before`: mốc "trước đó" cho lịch sử, mặc định là hiện tại. `context` (MR20): ngữ cảnh đã dựng cho chính
    lần thử sắp chấm — lịch sử tài khoản và đếm toàn cục lấy thẳng từ đó, không truy vấn lại; không có thì đọc DB/bộ đếm
    dùng chung khi luật cần. `config=None` (mặc định): đọc `rule_overrides` qua `refresh_rule_config` (MR17) — truyền
    tay một `RuleConfig` khác (vd hiệu chỉnh/replay ngoại tuyến, MR9-10) để BỎ QUA ghi đè của quản trị viên."""
    before = ensure_utc(before) if before is not None else datetime.now(timezone.utc)
    store = RedisStore(rate_counter.redis_client)
    resolved_config = refresh_rule_config(db) if config is None else config
    history = DbAccountHistory(db, before)
    stats = SharedGlobalStats(db, before)
    if context is not None:
        if context.attempt.user_key is not None:
            history.preloaded[context.attempt.user_key] = context.account_history
        stats.counts = context.summary.global_counts
    return RuleEngine(resolved_config, store=store, history=history, intel=_get_threat_intel(), blocklist=refresh_blocklist(db), stats=stats)
