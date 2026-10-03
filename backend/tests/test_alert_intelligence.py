"""MR13 — novelty, gán họ tấn công gợi ý, ưu tiên, chống trùng lặp: kiểm tra THUẦN (không DB), xem
app/detection/alert_intelligence.py. Tích hợp qua pipeline thật (dedup giảm số alert, message có novelty) ở
tests/test_pipeline_mr13.py."""

from app.detection.alert_intelligence import (
    DEDUP_WINDOW,
    GEO_FAMILY,
    ML_COMPONENT_FAMILY,
    Incident,
    NoveltyFact,
    action_escalated,
    build_alert_message,
    compute_novelty,
    evidence_of,
    json_safe,
    priority_score,
    suggest_attack_family,
)
from app.detection.engine.registry import CATEGORIES, REGISTRY
from app.detection.engine.types import RuleHit
from app.detection.hybrid import Contribution, RiskResult
from ml.rba.explain import COMPONENT_LABELS
from ml.rba.features import EventRecord, GlobalCounts, HistorySummary, InfraStats, UserHistory

US = 1_000_000
_FAR_FUTURE_US = 10**18  # mốc "hiện tại" của bản tóm tắt: sau mọi sự kiện test (novelty không dùng cửa sổ thời gian)


def _event(ts_us=0, user_id=1, ip="1.1.1.1", asn=100, country="VN", device_type="desktop", success=True) -> EventRecord:
    return EventRecord(
        ts_us=ts_us, user_id=user_id, ip=ip, asn=asn, country=country, ua="ua", browser="Chrome", os="Windows",
        device_type=device_type, success=success,
    )


def _summary(user_events) -> HistorySummary:
    user = None if user_events is None else UserHistory.from_events(_FAR_FUTURE_US, user_events)
    return HistorySummary(user=user, ip=InfraStats.from_events(_FAR_FUTURE_US, []), asn=None, global_counts=GlobalCounts())


def _risk_result(contributions) -> RiskResult:
    return RiskResult(
        score=90, action="lock", probability=0.9, ml_probability=None, rule_probability=0.9, reputation_probability=0.0,
        overridden_by=None, contributions=tuple(contributions),
    )


# --------------------------------------------------------------------------------------------------------- novelty


def test_no_novelty_when_current_event_matches_established_history():
    history = [_event(ts_us=i * US, country="VN", asn=100, device_type="desktop") for i in range(5)]
    current = _event(ts_us=10 * US, country="VN", asn=100, device_type="desktop")
    assert compute_novelty(current, _summary(history)) == []


def test_no_novelty_when_account_has_no_prior_success():
    current = _event(ts_us=0, country="RU")
    assert compute_novelty(current, _summary([_event(ts_us=-US, success=False)])) == []
    assert compute_novelty(current, _summary(None)) == []


def test_new_country_reports_the_usual_value_and_how_many_times_it_was_used():
    history = [_event(ts_us=i * US, country="VN", asn=100, device_type="desktop") for i in range(41)]
    current = _event(ts_us=100 * US, country="RU", asn=100, device_type="desktop")

    facts = compute_novelty(current, _summary(history))

    assert len(facts) == 1
    fact = facts[0]
    assert fact.attribute == "country" and fact.new_value == "RU" and fact.usual_value == "VN" and fact.usual_count == 41
    assert fact.text == "lần đầu quốc gia này (RU), trước đó dùng VN 41 lần"


def test_multiple_novel_attributes_are_reported_in_priority_order():
    history = [_event(ts_us=i * US, country="VN", asn=100, device_type="desktop") for i in range(3)]
    current = _event(ts_us=100 * US, country="RU", asn=999, device_type="mobile")

    facts = compute_novelty(current, _summary(history))

    assert [f.attribute for f in facts] == ["country", "asn", "device"]
    assert facts[1].new_value == "AS999" and facts[2].new_value == "di động"


def test_unknown_device_type_is_never_reported_as_a_novelty_fact():
    history = [_event(ts_us=0, country="VN", asn=100, device_type="desktop")]
    current = _event(ts_us=US, country="VN", asn=100, device_type="unknown")
    assert compute_novelty(current, _summary(history)) == []


# --------------------------------------------------------------------------------------------- gán họ tấn công


def test_family_is_none_when_there_is_no_contribution_at_all():
    assert suggest_attack_family(_risk_result([]), ml_component=None) == (None, None)


def test_every_registered_rule_maps_to_its_own_category_with_full_confidence_when_it_leads():
    """Vét cạn TOÀN BỘ luật đã đăng ký (không chỉ vài mẫu) — hồi quy nếu ai thêm luật mới mà quên nhóm nó đúng 4
    CATEGORIES hiện có."""
    assert len(REGISTRY) == 19  # đúng 19 luật của MR9 — đổi số này thì phải cập nhật kịch bản của alert_intelligence_sim.py
    for rule_id, spec in REGISTRY.items():
        group = "reputation" if spec.category == "Danh tiếng hạ tầng" else "rule"
        contribution = Contribution(rule_id, spec.title, 0.77, group)
        family, confidence = suggest_attack_family(_risk_result([contribution]), ml_component=None)
        assert family == spec.category and spec.category in CATEGORIES
        assert confidence == 0.77


def test_ml_component_leading_maps_to_its_own_vietnamese_label():
    assert set(ML_COMPONENT_FAMILY) == set(COMPONENT_LABELS)  # cùng 3 thành phần của HybridMinTail, không tự bịa thêm
    for component, label in COMPONENT_LABELS.items():
        contribution = Contribution("ml", "mô hình học máy", 0.5, "ml")
        family, confidence = suggest_attack_family(_risk_result([contribution]), ml_component=component)
        assert family == label and confidence == 0.5


def test_ml_component_unknown_still_returns_a_family_marked_as_ml_not_crash():
    contribution = Contribution("ml", "mô hình học máy", 0.5, "ml")
    family, confidence = suggest_attack_family(_risk_result([contribution]), ml_component=None)
    assert family is not None and "mô hình học máy" in family and confidence == 0.5


def test_family_comes_from_the_leading_contribution_not_a_later_one():
    contributions = [Contribution("blocklist_hit", "trong blocklist", 0.9, "reputation"), Contribution("brute_force", "dò mật khẩu", 0.3, "rule")]
    family, confidence = suggest_attack_family(_risk_result(contributions), ml_component=None)
    assert family == REGISTRY["blocklist_hit"].category and confidence == 0.9


def test_rule_evidence_wins_over_ml_even_when_ml_has_a_higher_weight():
    """Phát hiện THẬT qua backend/scripts/alert_intelligence_sim.py: trên hệ thống demo (IP Việt Nam thật), ML một
    mình có thể có trọng số CAO HƠN một luật cụ thể đã khớp (ASN/quốc gia hiếm so với RBA — đúng phát hiện PSI drift
    của MR12) — nếu không ưu tiên luật, alert do blocklist_hit sinh ra sẽ bị gán nhầm thành "đăng nhập bất thường"."""
    contributions = [Contribution("ml", "mô hình học máy", 0.95, "ml"), Contribution("blocklist_hit", "trong blocklist", 0.5, "reputation")]
    family, confidence = suggest_attack_family(_risk_result(contributions), ml_component="bat_thuong")
    assert family == REGISTRY["blocklist_hit"].category and confidence == 0.5  # luật thắng dù ML có trọng số cao hơn


def test_ml_is_used_only_when_there_is_no_rule_or_reputation_evidence_at_all():
    contributions = [Contribution("ml", "mô hình học máy", 0.4, "ml")]
    family, confidence = suggest_attack_family(_risk_result(contributions), ml_component="chiem_tai_khoan")
    assert family == COMPONENT_LABELS["chiem_tai_khoan"] and confidence == 0.4


def test_the_geo_model_leading_suggests_the_geo_family_not_a_hybrid_cp2_component():
    """MR22: khi chỉ có hai mô hình, mô hình dẫn đầu quyết định — `ml_component` là của hybrid_cp2, không áp cho `ml_geo`."""
    geo = Contribution("ml_geo", "mô hình địa lý-thời gian", 0.38, "ml")
    weaker_rba = Contribution("ml", "mô hình học máy", 0.2, "ml")
    assert suggest_attack_family(_risk_result([geo, weaker_rba]), ml_component="chiem_tai_khoan") == (GEO_FAMILY, 0.38)

    stronger_rba = Contribution("ml", "mô hình học máy", 0.5, "ml")  # hybrid_cp2 dẫn đầu thì vẫn dùng thành phần của nó
    assert suggest_attack_family(_risk_result([stronger_rba, geo]), ml_component="chiem_tai_khoan") == (COMPONENT_LABELS["chiem_tai_khoan"], 0.5)


def test_rule_evidence_still_wins_over_the_geo_model():
    contributions = [Contribution("ml_geo", "mô hình địa lý-thời gian", 0.38, "ml"), Contribution("impossible_travel", "di chuyển", 0.1, "rule")]
    family, _ = suggest_attack_family(_risk_result(contributions), ml_component=None)
    assert family == REGISTRY["impossible_travel"].category


# -------------------------------------------------------------------------------------------------------- ưu tiên


def test_priority_score_scales_with_novelty_count_confidence_and_importance():
    one_fact = [NoveltyFact("country", "RU", "VN", 10)]
    three_facts = [NoveltyFact("country", "RU", "VN", 10), NoveltyFact("asn", "AS1", None, 0), NoveltyFact("device", "di động", "máy tính", 5)]

    assert priority_score([], None, 1.0) == 0.0  # không bằng chứng, không novelty -> ưu tiên thấp nhất
    assert priority_score([], 0.8, 1.0) == 1 * 0.8 * 1.0
    assert priority_score(one_fact, 0.8, 1.0) == 2 * 0.8 * 1.0
    assert priority_score(three_facts, 0.8, 1.0) == 4 * 0.8 * 1.0
    assert priority_score(one_fact, 0.8, 2.0) == 2 * 0.8 * 2.0  # importance nhân thêm, đúng công thức


# -------------------------------------------------------------------------------------------------- chống trùng lặp


def test_action_escalated_only_when_the_new_action_ranks_strictly_higher():
    assert action_escalated("alert", "step_up") is True
    assert action_escalated("alert", "lock") is True
    assert action_escalated("lock", "alert") is False  # KHÔNG được coi tụt hạng là "leo thang"
    assert action_escalated("alert", "alert") is False
    assert DEDUP_WINDOW.total_seconds() == 15 * 60


# -------------------------------------------------------------------------------------------------------- message


def test_message_keeps_top_3_reasons_adds_one_novelty_fact_and_the_suggested_family():
    contributions = [
        Contribution("blocklist_hit", "trong blocklist", 0.9, "reputation"),
        Contribution("brute_force", "dò mật khẩu", 0.3, "rule"),
        Contribution("ml", "mô hình học máy", 0.2, "ml"),
        Contribution("bot_user_agent", "UA bot", 0.05, "rule"),  # lý do thứ 4 — KHÔNG được xuất hiện trong message (D4: top-3)
    ]
    message = build_alert_message(
        _risk_result(contributions), novelty_facts=[NoveltyFact("country", "RU", "VN", 41)], family="Danh tiếng hạ tầng", confidence=0.9,
    )
    assert "trong blocklist (90%)" in message and "dò mật khẩu (30%)" in message and "mô hình học máy (20%)" in message
    assert "UA bot" not in message
    assert "Lần đầu quốc gia này (RU), trước đó dùng VN 41 lần." in message
    assert "Họ tấn công gợi ý: Danh tiếng hạ tầng (90%)." in message


def test_message_mentions_repeat_count_only_when_deduped():
    message_first = build_alert_message(_risk_result([Contribution("blocklist_hit", "x", 0.9, "reputation")]), novelty_facts=[], family="Danh tiếng hạ tầng", confidence=0.9)
    message_repeat = build_alert_message(
        _risk_result([Contribution("blocklist_hit", "x", 0.9, "reputation")]), novelty_facts=[], family="Danh tiếng hạ tầng", confidence=0.9, occurrence_count=4,
    )
    assert "Sự cố gồm" not in message_first
    assert "Sự cố gồm 4 lần thử, mỗi lần cách lần trước không quá 15 phút." in message_repeat


# ------------------------------------------------------------------------------------------- sự cố (MR23)


def _risk(score, action, contributions, overridden_by=None) -> RiskResult:
    return RiskResult(
        score=score, action=action, probability=score / 100, ml_probability=None, rule_probability=score / 100,
        reputation_probability=0.0, overridden_by=overridden_by, contributions=tuple(contributions),
    )


def test_an_incident_keeps_the_peak_score_the_worst_action_and_every_piece_of_evidence():
    """MR23: dò mật khẩu (alert, do luật ép) rồi đăng nhập thành công sau chuỗi sai (step_up) = MỘT sự cố liệt kê đủ bằng chứng."""
    brute = _risk(32, "alert", [Contribution("brute_force", "dò mật khẩu", 0.10, "rule"), Contribution("ml", "mô hình học máy", 0.05, "ml")], "brute_force")
    success = _risk(58, "step_up", [Contribution("success_after_failures", "thành công sau chuỗi sai", 0.0, "rule"), Contribution("ml", "mô hình học máy", 0.30, "ml")], "success_after_failures")

    incident = Incident.start(brute, family="Đoán và dò mật khẩu", confidence=0.10, evidence={"brute_force": {"fails": 5}})
    incident = incident.extend(success, family="Đoán và dò mật khẩu", confidence=0.0, evidence={"success_after_failures": {"fails_before": 5}})

    assert (incident.score, incident.action, incident.overridden_by, incident.occurrences) == (58, "step_up", "success_after_failures", 2)
    assert [c.source for c in incident.contributions] == ["ml", "brute_force", "success_after_failures"]  # hợp, giảm dần
    assert dict((c.source, c.weight) for c in incident.contributions)["ml"] == 0.30  # mỗi nguồn giữ trọng số lớn nhất
    assert incident.evidence == {"brute_force": {"fails": 5}, "success_after_failures": {"fails_before": 5}}
    assert incident.rule_id == "success_after_failures"


def test_a_weaker_later_attempt_never_lowers_the_action_or_steals_the_family():
    lock = _risk(70, "lock", [Contribution("blocklist_hit", "blocklist", 0.05, "reputation")], "blocklist_hit")
    weak = _risk(32, "alert", [Contribution("brute_force", "dò mật khẩu", 0.10, "rule")], "brute_force")

    incident = Incident.start(lock, family="Danh tiếng hạ tầng", confidence=0.05, evidence={}).extend(weak, family="Đoán và dò mật khẩu", confidence=0.10, evidence={})

    assert (incident.action, incident.overridden_by, incident.score) == ("lock", "blocklist_hit", 70)
    assert (incident.family, incident.confidence) == ("Danh tiếng hạ tầng", 0.05)  # họ tấn công của lần thử điểm cao nhất
    assert incident.rule_id == "blocklist_hit"


def test_an_incident_round_trips_through_the_alert_row():
    from types import SimpleNamespace

    risk = _risk(40, "alert", [Contribution("ml_geo", "mô hình địa lý-thời gian", 0.38, "ml"), Contribution("datacenter_ip", "datacenter", 0.05, "reputation")])
    incident = Incident.start(risk, family="đăng nhập bất thường", confidence=0.38, evidence={"datacenter_ip": {"ip": "1.2.3.4", "list": "datacenter"}})
    row = SimpleNamespace(risk_score=incident.score, explanation=incident.explanation(), attack_family=incident.family,
                          attack_family_confidence=incident.confidence, occurrence_count=incident.occurrences)

    assert Incident.from_alert(row) == incident
    assert incident.rule_id == "datacenter_ip"  # bằng chứng luật/danh tiếng mạnh nhất khi không luật nào ép


def test_an_alert_from_before_mr23_still_reads_as_an_incident():
    from types import SimpleNamespace

    legacy = SimpleNamespace(risk_score=80, explanation={"legacy_alert_type": "brute_force"}, attack_family=None, attack_family_confidence=None, occurrence_count=1)
    incident = Incident.from_alert(legacy)
    assert (incident.score, incident.action, incident.contributions, incident.evidence) == (80, "alert", (), {})


def test_rule_evidence_is_stored_json_safe():
    hit = RuleHit("multi_context_simultaneous", "high", "x", {"countries": ("VN", "US"), "speed": float("inf"), "seen": {"b", "a"}}, "enforce", ())
    assert evidence_of([hit]) == {"multi_context_simultaneous": {"countries": ["VN", "US"], "speed": None, "seen": ["a", "b"]}}
    assert json_safe(list(range(50))) == list(range(20))  # danh sách dài bị cắt — cảnh báo không phải nơi lưu nhật ký


def test_the_rule_that_forced_the_action_decides_the_family_like_it_decides_rule_id():
    """MR23: trước đó họ tấn công lấy bằng chứng trọng số cao nhất (hoà nhau thì theo thứ tự sổ đăng ký) trong khi `rule_id`
    lấy luật đã ép hành động — một lần thử bị khoá vì blocklist có thể mang họ "dò mật khẩu"."""
    contributions = [Contribution("brute_force", "dò mật khẩu", 0.30, "rule"), Contribution("blocklist_hit", "blocklist", 0.05, "reputation")]
    forced = RiskResult(
        score=70, action="lock", probability=0.33, ml_probability=None, rule_probability=0.3, reputation_probability=0.05,
        overridden_by="blocklist_hit", contributions=tuple(contributions),
    )
    assert suggest_attack_family(forced, ml_component=None) == (REGISTRY["blocklist_hit"].category, 0.05)
    assert suggest_attack_family(_risk_result(contributions), ml_component=None) == (REGISTRY["brute_force"].category, 0.30)  # không ép: như cũ


def test_the_representative_rule_comes_from_the_decisive_attempt_not_the_heaviest_weight():
    """E2E TC1 với mô hình thật: lần đăng nhập được sau chuỗi sai lên `step_up` nhờ ĐIỂM (không luật nào ép) — luật đại
    diện là luật dẫn đầu của chính lần đó, không phải `brute_force` (trọng số lớn hơn) của các lần sai trước."""
    brute = _risk(32, "alert", [Contribution("brute_force", "dò mật khẩu", 0.10, "rule")], "brute_force")
    success = _risk(60, "step_up", [Contribution("ml", "mô hình học máy", 0.60, "ml"), Contribution("success_after_failures", "thành công sau chuỗi sai", 0.0, "rule")])

    incident = Incident.start(brute, family="Đoán và dò mật khẩu", confidence=0.10, evidence={}).extend(success, family="Đoán và dò mật khẩu", confidence=0.0, evidence={})

    assert incident.overridden_by is None and incident.lead_rule == "success_after_failures"
    assert incident.rule_id == "success_after_failures"
    assert max((c for c in incident.contributions if c.group != "ml"), key=lambda c: c.weight).source == "brute_force"  # trọng số lớn nhất là luật khác


def test_every_family_the_engine_can_suggest_fits_the_database_columns():
    """SQLite của test không kiểm độ dài VARCHAR, Postgres thì có: họ địa lý-thời gian của MR22 dài 67 ký tự > 64 làm Postgres
    từ chối ghi cảnh báo (MR22: hỏng cả giao dịch, lần đăng nhập thành công trả lỗi 500) — lộ ra khi đo độ trễ CP4."""
    from app.models import Alert, Campaign

    families = {GEO_FAMILY, "đăng nhập bất thường (mô hình học máy)", *CATEGORIES, *ML_COMPONENT_FAMILY.values()}
    limit = min(Alert.__table__.c.attack_family.type.length, Campaign.__table__.c.attack_family.type.length)
    assert all(len(f) <= limit for f in families), [f for f in families if len(f) > limit]
    assert max(len(rule_id) for rule_id in REGISTRY) <= Alert.__table__.c.rule_id.type.length
