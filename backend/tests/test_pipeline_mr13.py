"""MR13 — "Cảnh báo thông minh v2" tích hợp vào pipeline thật (SQLite test + fakeredis + mô hình hybrid_cp2 thật, cùng
hạ tầng `client`/`db_session` của test_pipeline_mr12.py): chống trùng lặp thực sự GIẢM số hàng `Alert`, novelty/họ tấn
công gợi ý xuất hiện trong message, ưu tiên được tính. Đo trên diện rộng (nhiều kịch bản, độ chính xác gán họ, phần
trăm giảm alert) ở backend/scripts/alert_intelligence_sim.py — file này chỉ kiểm chứng CƠ CHẾ, không phải số đo cuối."""

import asyncio
from datetime import datetime, timedelta, timezone

from app.detection.pipeline import run_detection_pipeline
from app.models import Alert, AuditLog, BlocklistEntry, LoginEvent, ResponseAction, User
from app.security import hash_password
from app.utils.time import ensure_utc

PASSWORD = "CorrectHorse123"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
GOOGLE_DNS = "8.8.8.8"  # ASN 15169, GeoIP thật trả country="US" (đã xác nhận ở MR12, docs/geoip-setup.md)
SEED_IP = "14.169.1.1"  # VNPT, ASN 45899 — GeoIP thật trả VN/Ho Chi Minh City


def _create_user(db_session, username="alice", importance=1.0):
    user = User(username=username, password_hash=hash_password(PASSWORD), importance=importance)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _seed_vn_history(db_session, user, *, count=10):
    """Lịch sử THÀNH CÔNG toàn từ VN, mỗi ngày một lần đúng giờ của lần đăng nhập trong test — để lần đăng nhập từ US
    (GOOGLE_DNS) sau đó là novelty thật, so được với lịch sử.

    MR22: ghi sổ y như pipeline làm cho một lần đăng nhập thành công thật (GeoIP, dấu vân tay thiết bị, thiết bị/vị trí
    quen, baseline giờ). Trước đây chỉ chèn `LoginEvent` dồn trong một ngày, 30 ngày trước — với mô hình địa lý-thời gian
    đó là "thiết bị mới, vị trí mới sau 30 ngày im lặng"; trước MR22 cảnh báo `ml_anomaly` riêng của nó không bị test đếm."""
    from app.detection.baseline import record_known_device_if_new, record_known_location_if_new, update_baseline_after_successful_login
    from app.detection.geoip import lookup_ip
    from app.utils.device import compute_device_fingerprint

    geo = lookup_ip(SEED_IP)
    for i in range(count):
        event = LoginEvent(
            user_id=user.id, attempted_username=user.username, success=True, ip_address=SEED_IP, user_agent=CHROME_UA,
            device_fingerprint=compute_device_fingerprint(CHROME_UA), country="VN", city=geo.city if geo else None,
            latitude=geo.latitude if geo else None, longitude=geo.longitude if geo else None,
            is_synthetic=True, created_at=BASE - timedelta(days=count - i),
        )
        db_session.add(event)
        db_session.flush()
        update_baseline_after_successful_login(db_session, user, event)
        record_known_device_if_new(db_session, user, event.device_fingerprint, CHROME_UA)
        record_known_location_if_new(db_session, user, event.country, event.city)
    db_session.commit()


def _run(*, username, user_id, success, ip, ts, user_agent=CHROME_UA):
    asyncio.run(run_detection_pipeline(username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=ts))


def test_a_burst_from_a_blocklisted_ip_is_deduped_into_one_alert_not_five(db_session):
    user = _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR13", added_by="test"))
    db_session.commit()

    for i in range(5):
        _run(username="alice", user_id=user.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(seconds=i * 30))

    events = db_session.query(LoginEvent).order_by(LoginEvent.id).all()
    assert len(events) == 5 and all(e.hybrid_action == "lock" for e in events)  # blocklist_hit ghi đè MỌI lần, không phụ thuộc hiệu chỉnh

    alerts = db_session.query(Alert).all()
    assert len(alerts) == 1, "5 lần cùng khớp blocklist_hit trong 15 phút phải GỘP thành 1 alert, không phải 5 (đúng mục tiêu 'giảm số cảnh báo' của MR13)"

    alert = alerts[0]
    assert alert.occurrence_count == 5
    assert alert.attack_family == "Danh tiếng hạ tầng" and alert.attack_family_confidence is not None
    assert alert.priority_score is not None and alert.priority_score >= 0
    # `created_at` (server_default=func.now(), giờ THẬT lúc chạy test) và `last_seen_at` (= event.created_at, giờ GIẢ
    # BASE của kịch bản) đến từ hai "đồng hồ" khác nhau — so `last_seen_at` với chính mốc thời gian kịch bản, không
    # phải với created_at (cùng bẫy đã ghi nhận ở MR12: "test boundary bug, không phải lỗi module").
    assert ensure_utc(alert.last_seen_at) == BASE + timedelta(seconds=4 * 30)
    assert "Sự cố gồm 5 lần thử" in alert.message

    # "action" không đổi (lock -> lock không phải leo thang) mỗi lần trùng -> chỉ 1 response_action/audit_log, không phải 5.
    assert db_session.query(ResponseAction).count() == 1
    # MR16: lock giờ được THỰC THI thật ngay ở lần đầu (không chỉ "recommend_lock" như MR12/13 ban đầu).
    assert db_session.query(AuditLog).filter(AuditLog.action == "execute_lock").count() == 1


def test_two_blocklist_hits_a_fake_day_apart_are_not_incorrectly_deduped_into_one_alert(db_session):
    """Bug thật tự phát hiện ở MR15 (feedback_loop_sim.py chạy nhiều "vòng" cách nhau vài ngày GIẢ trong khi cả script
    chạy thật chỉ mất vài giây): bộ lọc cửa sổ chống trùng lặp BAN ĐẦU so `Alert.created_at` (giờ hàng Alert được GHI,
    server_default=func.now() — giờ THẬT lúc chạy) với `event.created_at - DEDUP_WINDOW` (giờ ĐĂNG NHẬP, có thể là giờ
    giả) — hai "đồng hồ" khác nhau khiến MỌI alert trước đó trông như "trong cửa sổ 15 phút" bất kể cách nhau bao xa
    về mặt thời điểm đăng nhập, vì tất cả đều được GHI vào DB gần như cùng một thời điểm thật. Test này tái lập đúng
    điều kiện đó (hai lần khớp blocklist_hit cách nhau 1 NGÀY GIẢ, chạy cách nhau chỉ mili-giây thật) — PHẢI ra 2 alert
    riêng (occurrence_count=1 mỗi cái), không phải 1 alert gộp occurrence_count=2."""
    user = _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR15", added_by="test"))
    db_session.commit()

    _run(username="alice", user_id=user.id, success=True, ip=GOOGLE_DNS, ts=BASE)
    _run(username="alice", user_id=user.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(days=1))

    alerts = db_session.query(Alert).order_by(Alert.id).all()
    assert len(alerts) == 2, "cách nhau 1 ngày (giờ đăng nhập) phải là 2 alert riêng, không phải gộp thành 1 chỉ vì được GHI vào DB gần nhau về giờ thật"
    assert alerts[0].occurrence_count == 1 and alerts[1].occurrence_count == 1


def test_dedup_still_groups_by_ip_when_the_username_does_not_exist(db_session):
    """Kịch bản dò danh sách tài khoản: nhiều TÊN ĐĂNG NHẬP KHÔNG TỒN TẠI khác nhau, cùng một IP bị blocklist — user_id
    luôn None nên chống trùng lặp phải gộp theo IP, không phải theo user_id (None == None sẽ gộp NHẦM các IP khác nhau
    nếu chỉ lọc user_id, xem app/detection/pipeline.py)."""
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR13", added_by="test"))
    db_session.commit()
    for i, name in enumerate(["ghost1", "ghost2", "ghost3"]):
        _run(username=name, user_id=None, success=False, ip=GOOGLE_DNS, ts=BASE + timedelta(seconds=i * 10))

    alerts = db_session.query(Alert).all()
    assert len(alerts) == 1 and alerts[0].occurrence_count == 3 and alerts[0].user_id is None


def test_a_login_from_a_new_country_mentions_it_by_name_in_the_message_with_the_usual_country_and_count(db_session):
    user = _create_user(db_session, "alice")
    _seed_vn_history(db_session, user, count=10)
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR13", added_by="test"))
    db_session.commit()

    _run(username="alice", user_id=user.id, success=True, ip=GOOGLE_DNS, ts=BASE)

    alert = db_session.query(Alert).one()
    assert "Lần đầu quốc gia này (US), trước đó dùng VN 10 lần." in alert.message


def test_an_ordinary_login_matching_established_history_creates_no_novelty_clause_or_alert(db_session):
    """Kiểm chứng âm tính: lịch sử quen thuộc + đăng nhập bình thường (không blocklist, không sai mật khẩu, cùng nước/
    thiết bị) không được tự bịa ra sự "mới lạ" hay cảnh báo nào — hệ thống không được ồn ào với traffic hợp lệ.

    MR22: từ đây "không cảnh báo nào" bao gồm cả mô hình địa lý-thời gian (nguồn `ml_geo` trong cảnh báo hybrid, không
    còn alert `ml_anomaly` riêng) — đếm MỌI loại alert, không chỉ `hybrid_risk`. (Ghi chú cũ cho rằng IP này không tra
    được GeoIP là sai: GeoIP thật trả VN/Ho Chi Minh City.)"""
    user = _create_user(db_session, "alice")
    _seed_vn_history(db_session, user, count=10)

    _run(username="alice", user_id=user.id, success=True, ip=SEED_IP, ts=BASE, user_agent=CHROME_UA)

    event = db_session.query(LoginEvent).filter(LoginEvent.is_synthetic.is_(False)).one()
    assert event.hybrid_action == "allow"
    assert db_session.query(Alert).count() == 0
