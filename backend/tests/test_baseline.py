"""Kiểm tra nhiệm vụ 4.1 — baseline hành vi user & chế độ học."""

from datetime import datetime, timedelta, timezone

from app.detection.baseline import (
    LEARNING_MODE_MIN_DAYS,
    LEARNING_MODE_MIN_LOGINS,
    is_in_learning_mode,
    is_known_device,
    is_known_location,
    record_known_device_if_new,
    record_known_location_if_new,
    update_baseline_after_successful_login,
)
from app.models import LoginEvent, User, UserBaseline
from app.security import hash_password


def _make_user(db_session, username="alice"):
    user = User(username=username, password_hash=hash_password("x"))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_no_baseline_is_learning_mode(db_session):
    assert is_in_learning_mode(None) is True


def test_below_min_logins_is_learning_mode(db_session):
    baseline = UserBaseline(
        user_id=1,
        successful_login_count=LEARNING_MODE_MIN_LOGINS - 1,
        first_login_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    assert is_in_learning_mode(baseline) is True


def test_below_min_days_is_learning_mode(db_session):
    baseline = UserBaseline(
        user_id=1,
        successful_login_count=LEARNING_MODE_MIN_LOGINS + 5,
        first_login_at=datetime.now(timezone.utc) - timedelta(days=LEARNING_MODE_MIN_DAYS - 1),
    )
    assert is_in_learning_mode(baseline) is True


def test_enough_logins_and_days_not_learning_mode(db_session):
    baseline = UserBaseline(
        user_id=1,
        successful_login_count=LEARNING_MODE_MIN_LOGINS + 5,
        first_login_at=datetime.now(timezone.utc) - timedelta(days=LEARNING_MODE_MIN_DAYS + 1),
    )
    assert is_in_learning_mode(baseline) is False


def test_update_baseline_computes_avg_and_stddev(db_session):
    user = _make_user(db_session)
    now = datetime.now(timezone.utc)

    # 3 lần đăng nhập lúc 9h, 9h30, 10h -> mean ~9.5h, stddev nhỏ
    for i, hour in enumerate([9.0, 9.5, 10.0]):
        ts = now.replace(hour=int(hour), minute=int((hour % 1) * 60), second=0, microsecond=0) - timedelta(days=i)
        event = LoginEvent(
            user_id=user.id,
            attempted_username=user.username,
            success=True,
            ip_address="1.2.3.4",
            is_synthetic=False,
            created_at=ts,
        )
        db_session.add(event)
        db_session.flush()
        update_baseline_after_successful_login(db_session, user, event)

    db_session.commit()
    baseline = db_session.query(UserBaseline).filter(UserBaseline.user_id == user.id).first()

    assert baseline is not None
    assert baseline.successful_login_count == 3
    assert 9.0 <= baseline.avg_login_hour <= 10.0
    assert baseline.stddev_login_hour is not None
    assert baseline.first_login_at is not None


def test_update_baseline_survives_a_concurrent_first_login(db_session, monkeypatch):
    """MR20: hai lần đăng nhập thành công ĐẦU TIÊN của cùng tài khoản đến đồng thời — request này vừa thấy "chưa có
    baseline" thì request kia đã ghi xong. Trước MR20: trùng khoá chính, request lỗi 500 (đo thật: 9/10 request đồng thời
    vào một tài khoản mới). Giờ phải dùng lại dòng của request kia và cộng tiếp, không lỗi."""
    from sqlalchemy import false

    user_id = _make_user(db_session).id
    first_login = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.add(UserBaseline(user_id=user_id, successful_login_count=1, first_login_at=first_login))  # dòng của request kia
    db_session.commit()
    db_session.expunge_all()  # phiên của request này chưa từng thấy dòng đó

    real_query, lookups = db_session.query, []

    def first_lookup_misses(*entities):
        query = real_query(*entities)
        if len(entities) == 1 and entities[0] is UserBaseline and not lookups:  # `is`: `==` trên cột SQLAlchemy dựng biểu thức SQL
            lookups.append(1)
            return query.filter(false())  # đúng khe hở tranh chấp: lần đọc đầu chưa thấy dòng vừa được ghi
        return query

    monkeypatch.setattr(db_session, "query", first_lookup_misses)
    user = db_session.get(User, user_id)
    event = LoginEvent(user_id=user.id, attempted_username=user.username, success=True, ip_address="1.2.3.4", is_synthetic=False, created_at=datetime.now(timezone.utc))
    db_session.add(event)
    db_session.flush()

    baseline = update_baseline_after_successful_login(db_session, user, event)
    db_session.commit()
    assert lookups == [1]
    assert baseline.successful_login_count == 2  # dòng cũ được dùng lại và cộng tiếp, không tạo trùng
    assert db_session.query(UserBaseline).count() == 1


def test_known_device_and_location_round_trip(db_session):
    user = _make_user(db_session)

    assert is_known_device(db_session, user.id, "fp-abc") is False  # chưa từng ghi nhận
    assert is_known_device(db_session, user.id, None) is True  # thiếu fingerprint -> không kết luận được, coi như "không lạ"

    record_known_device_if_new(db_session, user, "fp-abc", "UA-test")
    db_session.commit()
    assert is_known_device(db_session, user.id, "fp-abc") is True  # đã ghi nhận -> giờ là thiết bị quen

    assert is_known_location(db_session, user.id, "VN", "Hanoi") is False  # chưa từng ghi nhận
    record_known_location_if_new(db_session, user, "VN", "Hanoi")
    db_session.commit()
    assert is_known_location(db_session, user.id, "VN", "Hanoi") is True
    assert is_known_location(db_session, user.id, "US", "New York") is False
