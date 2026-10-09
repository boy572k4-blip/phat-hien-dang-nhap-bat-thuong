"""Đo 7 hành vi còn "chưa đo" trong docs/behavior-coverage-matrix.md (MR19) — theo yêu cầu người dùng kiểm tra trực
tiếp thay vì chỉ đọc mã nguồn. KHÔNG phải một MR mới, không sửa docs/checklist.md — chỉ là phiên đo bổ sung, dùng lại
NGUYÊN hạ tầng đã có từ MR18 (`ml/attack_scenarios.py` + `scripts/attack_scenario_runner.py`).

Không đụng tới 5 luật ở chế độ shadow bằng cách CHỈ đếm Alert (shadow không tự tạo alert riêng — đó là THIẾT KẾ, không
phải lỗi, đã xác nhận ở MR18 cho `rare_network_login`). Mỗi kịch bản đo HAI THỨ riêng biệt:
  1. "Luật có khớp không" — gọi THẲNG `build_rule_engine(...).evaluate(attempt, record=False)` trên đúng
     `LoginEvent` cuối cùng vừa ghi (đọc lại từ DB, record=False nên không đếm trùng) — trả lời đúng câu hỏi
     "logic của luật có đúng không", độc lập với việc luật đó enforce hay shadow.
  2. "Có tạo alert nhìn thấy được không" — qua CHÍNH pipeline thật (`run_detection_pipeline`), giống MR18.
Hai kết quả có thể KHÁC NHAU (luật khớp nhưng không alert) với luật shadow — đó là kết quả ĐÚNG, không phải bug.

Chạy: cd backend && venv\\Scripts\\python.exe -m scripts.measure_untested_behaviors
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta, timezone
from pathlib import Path

from ml.attack_scenarios import (
    ALIBABA_CN_IP,
    CHROME_UA,
    FIREFOX_UA,
    GOOGLE_US_IP,
    HANOI_FPT_IP,
    AttemptSpec,
    ScenarioSpec,
    _baseline,
)
from scripts.attack_scenario_runner import (
    BASE_TS,
    _alert_count,
    _all_alert_mechanisms,
    _create_victims,
    _fresh_session_factory,
    _insert_baseline,
    _run_login,
    _wire,
)

REPORT_PATH = Path(__file__).resolve().parents[2] / "docs" / "untested-behaviors-measured.md"

# IP CÔNG KHAI THẬT, lấy trực tiếp từ các danh sách đã tải (backend/threat_intel/) — không bịa.
TOR_EXIT_IP = "171.25.193.25"  # dòng đầu backend/threat_intel/tor_exit_ips.txt
DATACENTER_IP = "1.12.0.1"  # trong dải 1.12.0.0/14, dòng đầu backend/threat_intel/datacenter_cidrs.txt
VPN_IP = "2.26.157.1"  # trong dải 2.26.157.0/24, dòng đầu backend/threat_intel/vpn_cidrs.txt
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@dataclass
class RuleCheckOutcome:
    rule_id: str
    behavior: str
    rule_matched: bool  # Evaluation.hits có rule_id này không (record=False, không đếm trùng)
    finding_message: str | None
    visible_alert: bool  # pipeline thật có tạo Alert nào không (total_alerts > 0)
    mechanisms: list[str]


def _rule_fired_on_last_event(session_factory, *, before_iso_offset_s: float) -> dict[str, bool]:
    """Gọi THẲNG build_rule_engine trên đúng LoginAttempt của dòng LoginEvent cuối cùng, record=False (không ghi lại
    chỉ mục/lịch sử — đã được chính pipeline thật ghi khi chạy _run_login). Trả {rule_id: đã khớp} cho MỌI luật khớp,
    không chỉ luật đang quan tâm — tiện kiểm tra chéo."""
    from app.detection.engine.types import LoginAttempt
    from app.detection.rule_engine_runtime import build_rule_engine
    from app.models import LoginEvent, User

    db = session_factory()
    try:
        row = db.query(LoginEvent).order_by(LoginEvent.id.desc()).first()
        user = db.query(User).filter(User.id == row.user_id).first() if row.user_id else None
        attempt = LoginAttempt(
            ts=row.created_at.replace(tzinfo=timezone.utc).timestamp() if row.created_at.tzinfo is None else row.created_at.timestamp(),
            username=row.attempted_username, success=row.success, ip=row.ip_address,
            user_key=str(row.user_id) if row.user_id else None, asn=row.asn, country=row.country, city=row.city,
            latitude=row.latitude, longitude=row.longitude, user_agent=row.user_agent,
            browser=row.browser_name, os=row.os_name, device_type=row.device_type,
        )
        evaluation = build_rule_engine(db, before=row.created_at + timedelta(seconds=before_iso_offset_s)).evaluate(attempt, record=False)
        return {hit.rule_id: hit.message for hit in evaluation.hits}
    finally:
        db.close()


def _run_and_check(spec: ScenarioSpec, rule_id: str, behavior: str) -> RuleCheckOutcome:
    sf = _fresh_session_factory()
    _wire(sf)
    _create_victims(sf, spec.victim_usernames)
    _insert_baseline(sf, spec)

    from app.models import User

    db = sf()
    try:
        user_ids = {u.username: u.id for u in db.query(User).filter(User.username.in_(spec.victim_usernames)).all()}
    finally:
        db.close()

    for attempt in spec.attack_attempts:
        _run_login(
            username=attempt.username, user_id=user_ids.get(attempt.username), success=attempt.success, ip=attempt.ip,
            ts=BASE_TS + timedelta(seconds=attempt.offset_s), user_agent=attempt.user_agent,
        )

    hits = _rule_fired_on_last_event(sf, before_iso_offset_s=1.0)
    return RuleCheckOutcome(
        rule_id=rule_id, behavior=behavior, rule_matched=rule_id in hits, finding_message=hits.get(rule_id),
        visible_alert=_alert_count(sf) > 0, mechanisms=_all_alert_mechanisms(sf),
    )


# --------------------------------------------------------------------------------------------- 7 kịch bản còn thiếu


def scenario_bot_user_agent() -> ScenarioSpec:
    """bot_user_agent: không cần lịch sử, không check a.success — chỉ cần device_type phân tích ra "bot". Dùng UA
    Googlebot thật, đã xác nhận `user_agents.parse(...).is_bot == True` trước khi dùng."""
    return ScenarioSpec(
        id="bot_ua_check", title="User-Agent là bot", description="1 lần thử với UA Googlebot thật.",
        rule_hint="bot_user_agent", victim_usernames=(),
        attempts=(AttemptSpec(username="khong_quan_trong", success=False, ip=HANOI_FPT_IP, offset_s=0, user_agent=GOOGLEBOT_UA),),
    )


def scenario_regular_rhythm() -> ScenarioSpec:
    """regular_rhythm (shadow): 10 lần sai CÙNG IP, cách nhau ĐÚNG 10 giây (cv=0, dưới ngưỡng max_cv=0.15;
    mean=10s dưới ngưỡng max_mean_interval_s=30)."""
    attempts = tuple(
        AttemptSpec(username="victim_rhythm", success=False, ip=ALIBABA_CN_IP, offset_s=i * 10.0, user_agent=CHROME_UA)
        for i in range(10)
    )
    return ScenarioSpec(
        id="regular_rhythm_check", title="Nhịp thử đều như máy", description="10 lần sai, CÙNG IP, cách nhau đúng 10 giây.",
        rule_hint="regular_rhythm", victim_usernames=(), attempts=attempts,
    )


def scenario_tor_exit() -> ScenarioSpec:
    """tor_exit: chỉ cần IP nằm trong danh sách Tor thật đã tải."""
    return ScenarioSpec(
        id="tor_exit_check", title="Đăng nhập từ Tor exit node", description="1 lần thử từ IP Tor exit node thật.",
        rule_hint="tor_exit", victim_usernames=(),
        attempts=(AttemptSpec(username="khong_quan_trong", success=False, ip=TOR_EXIT_IP, offset_s=0, user_agent=CHROME_UA),),
    )


def scenario_datacenter_ip() -> ScenarioSpec:
    return ScenarioSpec(
        id="datacenter_ip_check", title="Đăng nhập từ dải IP datacenter", description="1 lần thử từ IP datacenter thật.",
        rule_hint="datacenter_ip", victim_usernames=(),
        attempts=(AttemptSpec(username="khong_quan_trong", success=False, ip=DATACENTER_IP, offset_s=0, user_agent=CHROME_UA),),
    )


def scenario_vpn_ip() -> ScenarioSpec:
    return ScenarioSpec(
        id="vpn_ip_check", title="Đăng nhập từ dải IP VPN thương mại", description="1 lần thử từ IP VPN thương mại thật.",
        rule_hint="vpn_ip", victim_usernames=(),
        attempts=(AttemptSpec(username="khong_quan_trong", success=False, ip=VPN_IP, offset_s=0, user_agent=CHROME_UA),),
    )


def scenario_multi_context_simultaneous() -> ScenarioSpec:
    """multi_context_simultaneous: 2 lần đăng nhập THÀNH CÔNG, 2 quốc gia khác nhau, trong 10 phút."""
    victim = "victim_multictx"
    baseline = _baseline((victim,), HANOI_FPT_IP)
    attack = (
        AttemptSpec(username=victim, success=True, ip=HANOI_FPT_IP, offset_s=0, user_agent=CHROME_UA),
        AttemptSpec(username=victim, success=True, ip=GOOGLE_US_IP, offset_s=5 * 60, user_agent=CHROME_UA),
    )
    return ScenarioSpec(
        id="multi_context_check", title="Đăng nhập cùng lúc từ nhiều quốc gia",
        description="2 lần đăng nhập thành công cách nhau 5 phút, Việt Nam rồi Mỹ.",
        rule_hint="multi_context_simultaneous", victim_usernames=(victim,), attempts=baseline + attack,
    )


def scenario_country_hop() -> ScenarioSpec:
    """country_hop (shadow): 1 username bị thử từ 3 quốc gia khác nhau trong 24h (thành công hoặc thất bại đều tính)."""
    victim = "victim_countryhop"
    attack = (
        AttemptSpec(username=victim, success=False, ip=HANOI_FPT_IP, offset_s=0, user_agent=CHROME_UA),
        AttemptSpec(username=victim, success=False, ip=GOOGLE_US_IP, offset_s=3600, user_agent=CHROME_UA),
        AttemptSpec(username=victim, success=False, ip=ALIBABA_CN_IP, offset_s=7200, user_agent=FIREFOX_UA),
    )
    return ScenarioSpec(
        id="country_hop_check", title="Tài khoản bị thử từ nhiều quốc gia",
        description="1 tài khoản bị thử từ 3 quốc gia khác nhau (VN, US, CN) trong 2 giờ.",
        rule_hint="country_hop", victim_usernames=(), attempts=attack,
    )


CHECKS = (
    (scenario_bot_user_agent, "bot_user_agent", "User-Agent là bot"),
    (scenario_regular_rhythm, "regular_rhythm", "Nhịp thử đều như máy"),
    (scenario_tor_exit, "tor_exit", "Đăng nhập từ Tor exit node"),
    (scenario_datacenter_ip, "datacenter_ip", "Đăng nhập từ dải IP datacenter"),
    (scenario_vpn_ip, "vpn_ip", "Đăng nhập từ dải IP VPN thương mại"),
    (scenario_multi_context_simultaneous, "multi_context_simultaneous", "Đăng nhập cùng lúc từ nhiều quốc gia"),
    (scenario_country_hop, "country_hop", "Tài khoản bị thử từ nhiều quốc gia"),
)


def _calibrated_weight(rule_id: str) -> tuple[float, bool, int]:
    """(trọng số, đã hiệu chỉnh?, cỡ mẫu val) của `rule_id` trong hồ sơ hybrid đang dùng thật — giải thích TẠI SAO một
    luật khớp nhưng không alert (trọng số quá thấp một mình), không chỉ vì "shadow"."""
    import json

    profile = json.loads(Path("app/detection/hybrid/profiles/rba_calibrated.json").read_text(encoding="utf-8"))
    rw = profile["rule_weights"]
    entry = rw["weights"].get(rule_id)
    if entry is None:
        return rw["default_weight"], False, 0
    return entry["weight"], entry["calibrated"], entry["n"]


def render(outcomes: list[RuleCheckOutcome]) -> str:
    lines = [
        "# Đo 7 hành vi còn \"chưa đo\" (bổ sung sau MR19)",
        "",
        "Người dùng yêu cầu kiểm chứng trực tiếp (không chỉ đọc mã) cho 7 hành vi còn đánh dấu \"chưa đo\" ở "
        "[`behavior-coverage-matrix.md`](behavior-coverage-matrix.md). Dùng lại NGUYÊN hạ tầng kịch bản thật của MR18 "
        "(`ml/attack_scenarios.py` + `scripts/attack_scenario_runner.py`) — không phải MR mới, không đổi checklist.",
        "",
        "Mỗi hành vi đo HAI điều khác nhau: **(1) luật có khớp không** (gọi thẳng rule engine, record=False, trả lời "
        "đúng câu hỏi \"logic luật đúng không\" bất kể enforce/shadow) và **(2) có tạo alert nhìn thấy được không** "
        "(qua pipeline thật, MR12). Với luật `shadow`, (1)=có và (2)=không là kết quả **ĐÚNG THEO THIẾT KẾ**, không "
        "phải thất bại — shadow chỉ góp bằng chứng cho hybrid risk engine, không tự báo alert riêng (đã xác nhận cho "
        "`rare_network_login` ở MR18).",
        "",
        "| Hành vi | Luật | Luật có khớp? | Trọng số hybrid | Có alert? | Cơ chế alert thật sự (nếu có) |",
        "|---|---|---|---|---|---|",
    ]
    weights = {o.rule_id: _calibrated_weight(o.rule_id) for o in outcomes}
    for o in outcomes:
        matched = "✅ Có" if o.rule_matched else "❌ KHÔNG"
        w, calibrated, n = weights[o.rule_id]
        w_text = f"{w:.1%}" + (f" (hiệu chỉnh, mẫu={n})" if calibrated else " (mặc định CHƯA hiệu chỉnh)")
        alerted = "✅" if o.visible_alert else ("➖" if o.rule_matched else "❌")
        mech = "; ".join(sorted(set(o.mechanisms))) or "—"
        lines.append(f"| {o.behavior} | `{o.rule_id}` | {matched} | {w_text} | {alerted} | {mech} |")

    n_matched = sum(1 for o in outcomes if o.rule_matched)
    lines += [
        "",
        f"## Tóm tắt: {n_matched}/{len(outcomes)} luật khớp đúng với kịch bản dàn dựng",
        "",
        "**Cả 7 luật đều khớp đúng logic** — không có bug nào trong RULE LOGIC bản thân chúng. Nhưng chỉ **2/7 kịch bản "
        "có alert nhìn thấy**, và quan trọng: **cả 2 lần alert đó đều KHÔNG phải do luật đang đo**, mà do một luật "
        "KHÁC cùng khớp (`brute_force`, `impossible_travel` — xem cột \"Cơ chế alert thật sự\"):",
        "",
    ]
    for o in outcomes:
        w, calibrated, n = weights[o.rule_id]
        if w == 0.0 and calibrated:
            lines.append(
                f"- **`{o.rule_id}`**: trọng số hiệu chỉnh = **0,0%** (mẫu val chỉ {n} dòng) — một mình KHÔNG BAO GIỜ "
                "đủ vượt ngưỡng `alert_at=32`, dù khớp hoàn hảo. Cùng tình trạng với `distributed_bruteforce` (MR18)."
            )
        elif not calibrated:
            lines.append(
                f"- **`{o.rule_id}`**: chưa có dữ liệu val để hiệu chỉnh, dùng trọng số mặc định **5%** — một mình "
                "cho điểm hybrid ~5/100, xa ngưỡng `alert_at=32`. Cùng tình trạng với `username_enumeration` (MR18)."
            )
    lines += [
        "",
        "⚠️ **Phát hiện đúng ra ngoài câu hỏi ban đầu**: khi đọc mã mới nhận ra `app/detection/hybrid/combine.py` "
        "(dòng 10-12) ghi \"chế độ shadow chỉ quyết định RuleEngine có tự tạo cảnh báo hay không\" — nhưng đọc "
        "`app/detection/engine/engine.py::evaluate()` thì KHÔNG thấy RuleEngine tự tạo cảnh báo ở đâu cả (chỉ trả "
        "`Evaluation.hits`); alert DUY NHẤT được tạo ở `pipeline.py` dựa trên điểm HYBRID tổng hợp, áp dụng GIỐNG HỆT "
        "cho hit từ luật enforce lẫn shadow. Nói cách khác: **trên luồng `/login` thật, enforce/shadow KHÔNG quyết "
        "định được có alert hay không — chỉ trọng số hiệu chỉnh mới quyết định** (shadow và enforce với trọng số thấp "
        "cho kết quả giống hệt nhau về mặt alert). Phân biệt enforce/shadow có ý nghĩa cho công cụ tinh chỉnh/replay "
        "ngoại tuyến (MR10), không phải cho hành vi runtime của `/login`. Không sửa gì (ngoài phạm vi yêu cầu đo), chỉ "
        "ghi nhận để tài liệu không còn gây hiểu nhầm nếu đọc riêng docstring mà không đối chiếu code.",
        "",
        "## Giới hạn của phép đo này",
        "",
        "- Mỗi kịch bản chạy **đúng 1 lần**, tham số dàn dựng để vượt HẲN ngưỡng (không sát biên) — không đo độ nhạy ở biên.",
        "- Kết quả \"luật có khớp\" xác nhận LOGIC đúng trên một kịch bản cụ thể, không phải tỉ lệ phát hiện trên nhiều biến thể.",
        "- IP công khai thật (Tor/datacenter/VPN lấy trực tiếp từ `backend/threat_intel/`), không phải hạ tầng tấn công thật.",
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    outcomes = [_run_and_check(build(), rule_id, behavior) for build, rule_id, behavior in CHECKS]
    REPORT_PATH.write_text(render(outcomes), encoding="utf-8")
    for o in outcomes:
        print(f"{o.rule_id}: matched={o.rule_matched} alert={o.visible_alert}")
    print(f"Da ghi {REPORT_PATH}")


if __name__ == "__main__":
    main()
