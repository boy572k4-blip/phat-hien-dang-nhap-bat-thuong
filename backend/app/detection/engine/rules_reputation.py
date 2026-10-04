"""Nhóm "Danh tiếng hạ tầng": Tor, datacenter, VPN thương mại và blocklist của quản trị viên.

Nguồn: danh sách công khai (backend/threat_intel/, tải bằng scripts/update_threat_feeds.py) và Blocklist trong bộ nhớ (MR12 lưu DB). Thiếu danh sách thì
luật bị BỎ QUA với lý do rõ ràng (engine ghi vào `Evaluation.skipped`), không báo động sai.
"""

from __future__ import annotations

from app.detection.engine.registry import RuleContext, rule
from app.detection.engine.types import Finding

CATEGORY = "Danh tiếng hạ tầng"


def _outcome(success: bool) -> str:
    return "thành công" if success else "thất bại"


@rule(
    id="tor_exit",
    title="Đăng nhập từ Tor exit node",
    category=CATEGORY,
    severity="medium",
    techniques=("T1090.003",),
    description="IP nguồn nằm trong danh sách exit node chính thức của Tor Project — lưu lượng bị ẩn nguồn gốc qua nhiều chặng.",
    needs=("tor_list",),
    notes="Tor có người dùng hợp lệ (riêng tư, kiểm duyệt) nên chỉ mức trung bình; danh sách là bản chụp, exit node đổi hằng ngày.",
)
def tor_exit(ctx: RuleContext) -> Finding | None:
    a = ctx.attempt
    if not ctx.intel.is_tor(a.ip):
        return None
    return Finding(f"IP {a.ip} là Tor exit node (đăng nhập {_outcome(a.success)}).", {"ip": a.ip, "list": "tor"})


@rule(
    id="datacenter_ip",
    title="Đăng nhập từ dải IP datacenter",
    category=CATEGORY,
    severity="low",
    techniques=("T1090.002",),
    description="IP nguồn thuộc dải của nhà cung cấp hosting/đám mây — người dùng thật hiếm khi đăng nhập từ máy chủ; kẻ tấn công thuê VPS/proxy thì thường.",
    needs=("datacenter_list",),
    default_mode="shadow",
    notes="Danh sách cộng đồng (X4BNet lists_vpn) KHÔNG đầy đủ và báo nhầm với VPN/đám mây của chính người dùng (làm việc từ xa); chế độ shadow đến khi đo được tỉ lệ báo nhầm trên log thật.",
)
def datacenter_ip(ctx: RuleContext) -> Finding | None:
    a = ctx.attempt
    if not ctx.intel.in_datacenter(a.ip):
        return None
    return Finding(f"IP {a.ip} thuộc dải datacenter/hosting (đăng nhập {_outcome(a.success)}).", {"ip": a.ip, "list": "datacenter"})


@rule(
    id="vpn_ip",
    title="Đăng nhập từ dải IP VPN thương mại",
    category=CATEGORY,
    severity="low",
    techniques=("T1090",),
    description="IP nguồn thuộc dải của dịch vụ VPN thương mại — che vị trí thật, thường thấy khi kẻ tấn công muốn 'ở cùng nước' với nạn nhân.",
    needs=("vpn_list",),
    default_mode="shadow",
    notes="Nhiều người dùng thật dùng VPN; chỉ có ý nghĩa khi kết hợp với tín hiệu khác (đổi quốc gia, thiết bị mới). Chế độ shadow mặc định.",
)
def vpn_ip(ctx: RuleContext) -> Finding | None:
    a = ctx.attempt
    if not ctx.intel.in_vpn(a.ip):
        return None
    return Finding(f"IP {a.ip} thuộc dải VPN thương mại (đăng nhập {_outcome(a.success)}).", {"ip": a.ip, "list": "vpn"})


@rule(
    id="blocklist_hit",
    title="Nguồn nằm trong blocklist",
    category=CATEGORY,
    severity="high",
    description="IP, dải CIDR, ASN hoặc tên đăng nhập của lần thử nằm trong blocklist do quản trị viên đặt (còn hiệu lực).",
    min_action="lock",
    notes=(
        "Quyết định của con người nên không ánh xạ kỹ thuật MITRE cụ thể. Hạn dùng của mục chặn so với thời gian của sự kiện. MR16 bổ sung hành động "
        "chặn thật. Hành động tối thiểu `lock` — trước MR21 là cơ chế \"luật ghi đè\" riêng của hybrid risk engine, giờ là trường hợp đặc biệt của `min_action`. Giữ ở MR25: bộ MR24 không có nguồn nào trong blocklist nên không đo được — đây là quyết định của quản trị viên, không phải ước lượng thống kê."
    ),
)
def blocklist_hit(ctx: RuleContext) -> Finding | None:
    entry = ctx.blocklist.match(ctx.attempt)
    if entry is None:
        return None
    reason = f" — {entry.reason}" if entry.reason else ""
    return Finding(
        f"Nguồn nằm trong blocklist ({entry.kind} {entry.value}){reason}.",
        {"kind": entry.kind, "value": entry.value, "reason": entry.reason, "added_by": entry.added_by},
    )


@rule(
    id="anonymizer_new_device",
    title="Đăng nhập qua Tor/VPN/datacenter bằng thiết bị lạ",
    category=CATEGORY,
    severity="medium",
    techniques=("T1090", "T1078"),
    description=(
        "IP nguồn thuộc Tor, VPN thương mại hoặc datacenter VÀ thiết bị (User-Agent) chưa từng đăng nhập thành công vào tài khoản (đã có lịch sử) "
        "— kẻ có mật khẩu giấu nguồn bằng hạ tầng thuê; người dùng VPN thật thường dùng máy của chính mình."
    ),
    needs=("account", "user_agent"),
    min_action="step_up",
    notes=(
        "MR29 — luật KẾT HỢP duy nhất được thêm. Hành động tối thiểu `step_up`: chủ tài khoản (vd người dùng VPN đổi điện thoại mới) qua được bằng "
        "OTP, kẻ chỉ có mật khẩu thì bị chặn — đoán OTP thì `otp_guessing` khoá. Trọng số giữ ở mức của IP (trần 0,31 như `vpn_ip`/`datacenter_ip`), "
        "KHÔNG cộng thêm: phần \"thiết bị mới\" đã nằm trong nhóm mô hình; bản đầu dùng trọng số đo được (0,57) thì cộng với mô hình thành KHOÁ "
        "29/44 lần đăng nhập của người dùng VPN hợp lệ đổi điện thoại. Cùng nhóm \"Danh tiếng hạ tầng\" nên gộp bằng max với `tor_exit`/`vpn_ip`/"
        "`datacenter_ip` (cùng một IP, không đếm trùng). Đã đo và KHÔNG thêm: + quốc gia mới (điểm thoát VPN đổi nước liên tục — khớp nhầm người dùng VPN hợp lệ), + đăng "
        "nhập sai (khớp người dùng VPN gõ sai mật khẩu bằng máy của mình), bot/script UA + đăng nhập sai (hai luật đó một mình đã đủ cảnh báo từ "
        "MR25 — không bắt thêm gì, chỉ đếm trùng). Né được bằng cách chép đúng User-Agent của nạn nhân. Số đo: docs/combined-rules.md."
    ),
)
def anonymizer_new_device(ctx: RuleContext) -> Finding | None:
    a, h = ctx.attempt, ctx.history
    if h is None or h.n_success == 0 or not a.ua_hash or a.ua_hash in h.known_devices:
        return None
    if ctx.intel.is_tor(a.ip):
        kind, label = "tor", "Tor exit node"
    elif ctx.intel.in_vpn(a.ip):
        kind, label = "vpn", "VPN thương mại"
    elif ctx.intel.in_datacenter(a.ip):
        kind, label = "datacenter", "datacenter/hosting"
    else:
        return None
    return Finding(
        f"Tài khoản '{a.username}': đăng nhập {_outcome(a.success)} qua {label} {a.ip} bằng thiết bị chưa từng dùng với tài khoản này.",
        {"ip": a.ip, "list": kind, "new_device": True},
    )
