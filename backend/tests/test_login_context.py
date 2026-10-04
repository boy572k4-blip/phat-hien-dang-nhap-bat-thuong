"""MR20 — app/detection/login_context.py: lịch sử tài khoản ở dạng TỔNG HỢP (DB tự đếm) phải cho ra ĐÚNG những gì cách
cũ (nạp toàn bộ lịch sử tài khoản rồi đếm trong Python) cho ra — so trên dữ liệu ngẫu nhiên có hạt giống cố định, từng
lần đăng nhập một:
  - 50 đặc trưng RBA so với ĐẶC TẢ `compute_features_spec` (chính đặc tả đã được so với DuckDB ở các test MR3);
  - `AccountHistory` của rule engine so với mã `DbAccountHistory.get` trước MR20 (chép nguyên vào đây làm chuẩn);
  - novelty của cảnh báo MR13 so với `compute_novelty` trước MR20 (đếm trên danh sách sự kiện, chép nguyên vào đây).
Bằng nhau là bằng TUYỆT ĐỐI (kể cả NaN ở cùng chỗ), không phải gần đúng."""

import math
import random
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import select

from app.detection.alert_intelligence import _NOVELTY_PRIORITY, NoveltyFact, _attr_value, compute_novelty
from app.detection.engine.types import AccountHistory, ua_hash
from app.detection.login_context import (
    GlobalCountsCache,
    before_of,
    build_history_summary,
    build_login_context,
    event_record_for,
    fetch_account_snapshot,
)
from app.models import LoginEvent, User
from app.utils.time import ensure_utc
from ml.rba.features import FEATURE_NAMES, compute_features_spec, features_from_summary

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------------------------------------- mã TRƯỚC MR20, làm chuẩn


def _old_account_history(db, user_id, before):
    """Nguyên văn `DbAccountHistory.get` trước MR20: nạp MỌI dòng của tài khoản rồi duyệt trong Python (+ IP quen, MR28)."""
    rows = db.execute(
        select(LoginEvent.created_at, LoginEvent.latitude, LoginEvent.longitude, LoginEvent.success, LoginEvent.country, LoginEvent.user_agent, LoginEvent.ip_address)
        .where(LoginEvent.user_id == user_id, LoginEvent.created_at < before)
        .order_by(LoginEvent.created_at)
    ).all()
    if not rows:
        return None
    history = AccountHistory()
    for created_at, lat, lon, success, country, agent, ip in rows:
        history.last_event_ts = ensure_utc(created_at).timestamp()
        history.last_event_lat, history.last_event_lon = lat, lon
        if success:
            history.last_success_ts = ensure_utc(created_at).timestamp()
            history.n_success += 1
            if country and country not in history.known_countries:
                history.known_countries += (country,)
            hashed = ua_hash(agent)
            if hashed and hashed not in history.known_devices:
                history.known_devices += (hashed,)
            if ip and ip not in history.known_ips:
                history.known_ips += (ip,)
    return history


def _old_novelty(event, user_events):
    """Nguyên văn `compute_novelty` trước MR20: đếm trên danh sách sự kiện thành công theo thời gian."""
    successes = [e for e in (user_events or []) if e.success]
    if not successes:
        return []
    facts = []
    for attr in _NOVELTY_PRIORITY:
        current = _attr_value(event, attr)
        if current is None:
            continue
        counts = Counter(v for e in successes if (v := _attr_value(e, attr)) is not None)
        if counts.get(current, 0) > 0:
            continue
        usual_value, usual_count = counts.most_common(1)[0] if counts else (None, 0)
        facts.append(NoveltyFact(attr, current, usual_value, usual_count))
    return facts


def _same(a: float, b: float) -> bool:
    return (math.isnan(a) and math.isnan(b)) or a == b


# --------------------------------------------------------------------------------------------- dữ liệu ngẫu nhiên


@pytest.fixture()
def history(db_session):
    """~260 lần thử của 4 tài khoản + tên không tồn tại trong 12 ngày, có cả các đợt dồn dập (cửa sổ 1 giờ/24 giờ có
    dữ liệu), thuộc tính thiếu (None), phiên bản trình duyệt/hệ điều hành khác nhau cùng họ, thiết bị "unknown"."""
    rng = random.Random(20)
    users = [User(username=f"user{i}", password_hash="x") for i in range(4)]
    db_session.add_all(users)
    db_session.flush()

    offsets_ms = set(rng.sample(range(12 * 86_400_000), 160))
    for _ in range(5):  # đợt dồn dập: 20 lần thử trong 30 phút
        anchor = rng.randrange(12 * 86_400_000 - 1_800_000)
        offsets_ms.update(anchor + rng.randrange(1_800_000) for _ in range(20))

    ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    countries = ["VN", "VN", "US", "JP", None]
    asns = [7552, 7552, 45899, 15169, None]
    agents = ["Mozilla/5.0 A", "Mozilla/5.0 B", "Mozilla/5.0 C", None]
    browsers = ["Chrome 120.0", "Chrome 121.0.1", "Firefox 115", "Chrome Mobile 46.0.2490", None]
    systems = ["Windows 10", "Windows 11", "Mac OS X 14.1", "iOS 17", None]
    devices = ["desktop", "desktop", "mobile", "tablet", "unknown", None]
    for ms in sorted(offsets_ms):  # thời điểm KHÁC NHAU từng mili-giây: "lần gần nhất" không bao giờ mơ hồ
        user = rng.choice([*users, None])
        located = rng.random() < 0.7
        db_session.add(
            LoginEvent(
                user_id=None if user is None else user.id, attempted_username="ghost" if user is None else user.username,
                success=rng.random() < 0.6, ip_address=rng.choice(ips), country=rng.choice(countries), asn=rng.choice(asns),
                user_agent=rng.choice(agents), browser_name=rng.choice(browsers), os_name=rng.choice(systems), device_type=rng.choice(devices),
                latitude=rng.uniform(-60, 60) if located else None, longitude=rng.uniform(-170, 170) if located else None,
                is_synthetic=True, created_at=BASE + timedelta(milliseconds=ms),
            )
        )
    db_session.flush()
    return db_session.query(LoginEvent).order_by(LoginEvent.created_at).all()


# --------------------------------------------------------------------------------------------- so khớp


def test_every_rba_feature_equals_the_spec_for_every_login(db_session, history):
    records = [event_record_for(e) for e in history]
    checked = Counter()
    for record in records:
        live = features_from_summary(record, build_history_summary(db_session, record, cache=GlobalCountsCache(out_of_order_seconds=0.0)))
        spec = compute_features_spec(record, records)
        mismatched = [name for name in FEATURE_NAMES if not _same(live[name], spec[name])]
        assert not mismatched, f"lệch đặc tả ở {mismatched} (ts_us={record.ts_us})"
        checked["u_n_success>0"] += spec["u_n_success"] > 0
        checked["fail_streak>0"] += spec["u_fail_streak"] > 0
        checked["attempts_1h>0"] += spec["u_attempts_1h"] > 0
        checked["same_family_new_version"] += spec["new_browser"] == 1.0 and spec["new_browser_family"] == 0.0
        checked["known_ip"] += spec["new_ip"] == 0.0
        checked["unknown_user"] += math.isnan(spec["u_n_attempts"])
    # Không để test "qua" vì dữ liệu không chạm tới nhánh nào: mỗi tình huống phải xuất hiện vài lần (hiếm nhất là
    # "cùng họ trình duyệt, khác phiên bản": chỉ xảy ra trước khi tài khoản đã dùng hết các phiên bản trong bộ mẫu).
    assert min(checked.values()) >= 5, checked


def test_account_history_for_the_rule_engine_equals_the_old_full_scan(db_session, history):
    compared = 0
    for event in history:
        if event.user_id is None:
            continue
        before = before_of(event_record_for(event))
        assert fetch_account_snapshot(db_session, event.user_id, before).account_history() == _old_account_history(db_session, event.user_id, ensure_utc(event.created_at))
        compared += 1
    assert compared > 150


def test_alert_novelty_equals_the_old_list_based_count(db_session, history):
    records = [event_record_for(e) for e in history]
    non_empty = 0
    for record in records:
        if record.user_id is None:
            continue
        summary = build_history_summary(db_session, record, cache=GlobalCountsCache(out_of_order_seconds=0.0))
        past = [r for r in records if r.user_id == record.user_id and r.ts_us < record.ts_us]
        new = compute_novelty(record, summary)
        assert new == _old_novelty(record, past)
        non_empty += bool(new)
    assert non_empty >= 10


# --------------------------------------------------------------------------------------------- ngữ cảnh + truy vấn


class _StatementLog:
    """Ghi lại mọi câu SQL gửi tới DB trong khối `with`."""

    def __init__(self, db):
        self.bind, self.statements = db.get_bind(), []

    def _before(self, conn, cursor, statement, *args):
        self.statements.append(statement)

    def __enter__(self):
        sa_event.listen(self.bind, "before_cursor_execute", self._before)
        return self

    def __exit__(self, *exc):
        sa_event.remove(self.bind, "before_cursor_execute", self._before)


def test_snapshot_lets_the_db_count_instead_of_loading_the_history(db_session):
    """500 lần thử cũ + 3 lần gần đây: đúng 2 câu truy vấn (đếm; gom các lần thành công) và chỉ MỘT nhóm thành công được
    chuyển sang Python — không phụ thuộc độ dài lịch sử."""
    user = User(username="heavy", password_hash="x")
    db_session.add(user)
    db_session.flush()
    now = BASE + timedelta(days=60)
    for i in range(500):
        db_session.add(LoginEvent(user_id=user.id, attempted_username="heavy", success=i % 5 != 0, ip_address="9.9.9.9", user_agent="ua", country="VN", latitude=21.0, longitude=105.8, is_synthetic=True, created_at=BASE + timedelta(minutes=i)))
    for hours in (30, 5, 0.5):
        db_session.add(LoginEvent(user_id=user.id, attempted_username="heavy", success=False, ip_address="8.8.8.8", user_agent="ua", country="US", latitude=40.7, longitude=-74.0, is_synthetic=True, created_at=now - timedelta(hours=hours)))
    db_session.flush()

    with _StatementLog(db_session) as log:
        snapshot = fetch_account_snapshot(db_session, user.id, now)

    assert len(log.statements) == 2
    assert snapshot.n_attempts == 503 and snapshot.n_success == 400
    assert snapshot.attempts_after_last_success == 3  # 3 lần thất bại gần đây sau lần thành công cuối
    assert (snapshot.attempts_1h, snapshot.attempts_24h, snapshot.fails_24h, snapshot.distinct_countries_7d) == (1, 2, 2, 1)
    assert (snapshot.last_latitude, snapshot.last_longitude) == (40.7, -74.0)  # lần thử gần nhất (30 phút trước)
    assert len(snapshot.success_groups) == 1 and snapshot.success_groups[0].count == 400


def test_infra_stats_cost_does_not_grow_with_an_attack_from_the_same_ip(db_session):
    """Credential stuffing: 2.000 lần thử từ MỘT IP trong 24 giờ. Trước MR20 mỗi lần chấm sau đó nạp cả 2.000 dòng vào
    Python; giờ vẫn đúng một câu truy vấn trả MỘT dòng đếm."""
    from app.detection.login_context import fetch_ip_stats

    now = BASE + timedelta(days=1)
    for i in range(2000):
        db_session.add(LoginEvent(user_id=None, attempted_username=f"victim{i % 400}", success=False, ip_address="6.6.6.6", user_agent=f"bot/{i % 3}", is_synthetic=True, created_at=now - timedelta(seconds=10 + i * 30)))
    db_session.flush()

    with _StatementLog(db_session) as log:
        stats = fetch_ip_stats(db_session, "6.6.6.6", now)
    assert len(log.statements) == 1
    assert (stats.attempts_1h, stats.attempts_24h, stats.fails_24h, stats.unknown_attempts_24h, stats.distinct_uas_24h, stats.attempts_all) == (120, 2000, 2000, 2000, 3, 2000)


def test_build_login_context_serves_rules_features_and_novelty_from_one_snapshot(db_session, history):
    event = next(e for e in reversed(history) if e.user_id is not None and e.success)
    context = build_login_context(db_session, event, username="user-x", cache=GlobalCountsCache(out_of_order_seconds=0.0))

    assert context.attempt.username == "user-x" and context.attempt.user_key == str(event.user_id)
    assert (context.attempt.ip, context.attempt.asn, context.attempt.country, context.attempt.browser, context.attempt.device_type) == (
        event.ip_address, event.asn, event.country, event.browser_name, event.device_type,
    )
    assert context.attempt.ts == ensure_utc(event.created_at).timestamp()
    assert context.account_history == context.account.account_history()
    assert context.summary.user == context.account.user_history()
    expected = compute_features_spec(context.record, [event_record_for(e) for e in history])
    assert all(_same(context.rba_features()[name], expected[name]) for name in FEATURE_NAMES)


def test_unknown_username_has_no_account_in_the_context(db_session, history):
    event = next(e for e in history if e.user_id is None)
    context = build_login_context(db_session, event, username="ghost")
    assert context.account is None and context.account_history is None and context.summary.user is None
    assert context.attempt.user_key is None


def test_rule_engine_reads_the_context_instead_of_querying_history_again(db_session, history, monkeypatch):
    from app.detection.rule_engine_runtime import build_rule_engine, load_threat_intel_at_startup

    def must_not_query(*args, **kwargs):
        raise AssertionError("rule engine không được truy vấn lại lịch sử đã có trong ngữ cảnh")

    load_threat_intel_at_startup()
    event = next(e for e in reversed(history) if e.user_id is not None)
    context = build_login_context(db_session, event, username="u")
    monkeypatch.setattr("app.detection.rule_engine_runtime.fetch_account_snapshot", must_not_query)
    monkeypatch.setattr("app.detection.rule_engine_runtime.shared_global_counts", must_not_query)
    evaluation = build_rule_engine(db_session, before=event.created_at, context=context).evaluate(context.attempt, record=False)
    assert evaluation.errors == {}


def test_rba_features_never_raise(db_session, history, monkeypatch):
    event = history[-1]
    context = build_login_context(db_session, event, username="u")

    def boom(*args, **kwargs):
        raise RuntimeError("lỗi giả lập")

    monkeypatch.setattr("app.detection.login_context.features_from_summary", boom)
    assert context.rba_features() is None
