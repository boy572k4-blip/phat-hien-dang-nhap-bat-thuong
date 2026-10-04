"""Các họ tấn công và họ lưu lượng hợp lệ "khó" của bộ dữ liệu hiệu chỉnh (MR24). Mỗi họ là một hàm `rng, pools -> Variant`;
mọi thứ ngẫu nhiên (nạn nhân, IP, nhịp, số bước, giờ quen, thiết bị) lấy từ `random.Random(f"{họ}:{seed}")` nên cùng seed
luôn ra cùng biến thể. Tách bộ hiệu chỉnh / bộ đánh giá theo seed (`SPLIT_SEEDS`), hai khoảng không giao nhau.

Nhãn ở mức TỪNG lần thử (`Step.malicious`): lần thử của kẻ tấn công = True; lần thử của chính chủ tài khoản (kể cả trong
một kịch bản tấn công, vd lần đăng nhập ở nhà ngay trước lần chiếm tài khoản) = False. Lịch sử (`history`) chỉ để dựng
"thói quen" — được ghi thẳng như lần đăng nhập thành công thật, không qua pipeline, không chấm.

Thời gian: giây tương đối so với 00:00 UTC của "ngày đo"; lịch sử là các ngày trước đó (giây âm). Ngưỡng của các họ chọn
quanh ngưỡng thật của luật (vd 5–12 lần sai cho dò mật khẩu, ngưỡng luật là 5) — có biến thể dưới ngưỡng, đúng ý đồ: đo
hệ thống bắt được bao nhiêu, không phải dựng kịch bản để chắc chắn bắt được."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Callable

from ml.corpus.ip_pools import ANONYMIZER_POOLS, FOREIGN_POOLS, TRAVEL_POOLS, VN_POOLS, IpInfo

DAY, HOUR, MINUTE = 86400.0, 3600.0, 60.0

BROWSER_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
)
MOBILE_UAS = (
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Redmi Note 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
)
SCRIPT_UAS = ("curl/8.7.1", "python-requests/2.31.0", "Go-http-client/1.1")
BOT_UAS = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
)

SPLIT_SEEDS = {"calibration": range(0, 1000), "evaluation": range(1000, 2000)}  # không giao nhau
VARIANTS_PER_FAMILY = 30


@dataclass(frozen=True)
class Step:
    username: str
    success: bool
    ip: IpInfo
    offset_s: float
    user_agent: str
    malicious: bool = False
    kind: str = "login"  # "login": một lần đăng nhập (qua cửa `/login` rồi pipeline); "otp_fail" (MR28): một lần gửi sai mã OTP


@dataclass(frozen=True)
class Lock:
    """MR28 — tài khoản/IP đã bị khoá TRƯỚC biến thể (vd hệ thống vừa tự khoá), còn hiệu lực đến `until_s`."""

    kind: str  # "username" | "ip"
    value: str
    until_s: float


@dataclass(frozen=True)
class Variant:
    family: str
    kind: str  # "attack" | "benign"
    seed: int
    accounts: tuple[str, ...]  # tài khoản có thật cần tạo trước (tên không có ở đây = tên không tồn tại)
    history: tuple[Step, ...]
    steps: tuple[Step, ...]
    locks: tuple[Lock, ...] = ()

    @property
    def id(self) -> str:
        return f"{self.family}#{self.seed}"


Pools = dict[str, tuple[IpInfo, ...]]


# ------------------------------------------------------------------------------------------------------- tiện ích


def _ip(rng: random.Random, pools: Pools, names: tuple[str, ...], *, exclude: IpInfo | None = None) -> IpInfo:
    candidates = [ip for name in names for ip in pools[name] if exclude is None or ip.ip != exclude.ip]
    return rng.choice(candidates)


def _other_vn(rng: random.Random, pools: Pools, home: IpInfo, *, same_city: bool) -> IpInfo:
    """IP Việt Nam của NHÀ MẠNG KHÁC — cùng thành phố với `home` nếu có (proxy/mimic tinh vi), không thì bất kỳ."""
    others = [ip for name in VN_POOLS if name != home.pool for ip in pools[name]]
    if same_city:
        local = [ip for ip in others if ip.city == home.city]
        if local:
            return rng.choice(local)
    return rng.choice(others)


def _habit(rng: random.Random) -> float:
    """Giờ quen (giây kể từ 00:00 UTC): 07:00–21:00 giờ Việt Nam."""
    return rng.uniform(0, 14) * HOUR


def _history(rng: random.Random, user: str, ip: IpInfo, ua: str, *, n: int, habit: float, last_day: int = 1) -> tuple[Step, ...]:
    """`n` lần thành công, mỗi ngày tối đa một lần (thỉnh thoảng nghỉ), quanh giờ quen ± 1 giờ, kết thúc `last_day` ngày trước."""
    days = sorted(rng.sample(range(last_day, last_day + n * 2), n), reverse=True)
    return tuple(Step(user, True, ip, -d * DAY + habit + rng.uniform(-HOUR, HOUR), ua) for d in days)


def _account(family: str, seed: int, i: int = 0) -> str:
    return f"{family[:10]}_{seed}_{i}"


def _victim(rng: random.Random, pools: Pools, family: str, seed: int, *, n_min: int = 8, n_max: int = 25):
    user = _account(family, seed)
    home = _ip(rng, pools, VN_POOLS)
    ua = rng.choice(BROWSER_UAS + MOBILE_UAS)
    habit = _habit(rng)
    return user, home, ua, habit, _history(rng, user, home, ua, n=rng.randint(n_min, n_max), habit=habit)


def _attacker_ip(rng: random.Random, pools: Pools, home: IpInfo | None = None) -> IpInfo:
    names = rng.choice((FOREIGN_POOLS, ANONYMIZER_POOLS, VN_POOLS))
    return _ip(rng, pools, names, exclude=home)


def _distance_km(a: IpInfo, b: IpInfo) -> float:
    from app.utils.geo import haversine_distance

    return haversine_distance(a.latitude, a.longitude, b.latitude, b.longitude)


# ------------------------------------------------------------------------------------------------------- họ tấn công


def brute_force(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "brute_force", seed)
    ip = _attacker_ip(rng, pools, home)
    attacker_ua = rng.choice(SCRIPT_UAS) if rng.random() < 0.3 else rng.choice(BROWSER_UAS)
    t, steps = rng.uniform(0, DAY - HOUR), []
    for _ in range(rng.randint(5, 12)):
        steps.append(Step(user, False, ip, t, attacker_ua, True))
        t += rng.uniform(3, 40)
    if rng.random() < 0.3:  # đoán trúng
        steps.append(Step(user, True, ip, t, attacker_ua, True))
    return (user,), history, steps


def credential_stuffing(rng, pools, seed):
    accounts = tuple(_account("credential_stuffing", seed, i) for i in range(rng.randint(6, 15)))
    history = []
    for user in accounts:
        home = _ip(rng, pools, VN_POOLS)
        history += _history(rng, user, home, rng.choice(BROWSER_UAS + MOBILE_UAS), n=rng.randint(3, 8), habit=_habit(rng))
    targets = list(accounts) + [f"ghost_cs_{seed}_{i}" for i in range(rng.randint(0, 5))]
    ip = _ip(rng, pools, rng.choice((FOREIGN_POOLS, ANONYMIZER_POOLS)))
    attacker_ua = rng.choice(SCRIPT_UAS) if rng.random() < 0.5 else rng.choice(BROWSER_UAS)
    t, steps = rng.uniform(0, DAY - HOUR), []
    for _ in range(rng.randint(10, 25)):
        steps.append(Step(rng.choice(targets), False, ip, t, attacker_ua, True))
        t += rng.uniform(5, 20)
    if rng.random() < 0.3:
        steps.append(Step(rng.choice(accounts), True, ip, t, attacker_ua, True))
    return accounts, tuple(history), steps


def password_spray_slow(rng, pools, seed):
    accounts = tuple(_account("password_spray", seed, i) for i in range(rng.randint(15, 25)))
    history = []
    for user in accounts:
        history += _history(rng, user, _ip(rng, pools, VN_POOLS), rng.choice(BROWSER_UAS), n=rng.randint(3, 6), habit=_habit(rng))
    ip = _attacker_ip(rng, pools)
    attacker_ua = rng.choice(BROWSER_UAS + SCRIPT_UAS)
    t, steps = rng.uniform(0, 4 * HOUR), []
    for user in rng.sample(accounts, len(accounts)):
        steps.append(Step(user, False, ip, t, attacker_ua, True))
        t += rng.uniform(15, 50) * MINUTE
    return accounts, tuple(history), steps


def distributed_botnet(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "distributed_botnet", seed)
    bots = rng.sample([ip for name in FOREIGN_POOLS + ANONYMIZER_POOLS for ip in pools[name]], rng.randint(5, 10))
    window = rng.uniform(15, 60) * MINUTE
    start = rng.uniform(0, DAY - 2 * HOUR)
    steps = [Step(user, False, ip, start + rng.uniform(0, window), rng.choice(BROWSER_UAS + MOBILE_UAS), True)
             for ip in bots for _ in range(rng.randint(1, 2))]
    return (user,), history, steps


def ua_rotation(rng, pools, seed):
    users = tuple(_account("ua_rotation", seed, i) for i in range(rng.randint(1, 2)))
    history = []
    for user in users:
        history += _history(rng, user, _ip(rng, pools, VN_POOLS), rng.choice(BROWSER_UAS), n=rng.randint(5, 15), habit=_habit(rng))
    ip = _attacker_ip(rng, pools)
    uas = rng.sample(BROWSER_UAS + MOBILE_UAS, rng.randint(5, 6))
    window = rng.uniform(3, 8) * MINUTE
    start = rng.uniform(0, DAY - HOUR)
    n = rng.randint(8, 12)
    steps = [Step(rng.choice(users), False, ip, start + window * i / n, uas[i % len(uas)], True) for i in range(n)]
    return users, tuple(history), steps


def account_enumeration(rng, pools, seed):
    ip = _ip(rng, pools, rng.choice((FOREIGN_POOLS, ANONYMIZER_POOLS)))
    ua = rng.choice(SCRIPT_UAS + BROWSER_UAS)
    t, steps = rng.uniform(0, DAY - HOUR), []
    for i in range(rng.randint(8, 20)):
        steps.append(Step(f"ghost_en_{seed}_{i}", False, ip, t, ua, True))
        t += rng.uniform(10, 60)
    return (), (), steps


def impossible_travel(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "impossible_travel", seed)
    far = _ip(rng, pools, FOREIGN_POOLS)
    t = habit + rng.uniform(-HOUR, HOUR)
    steps = [Step(user, True, home, t, ua, False)]  # chính chủ đăng nhập ở nhà
    attacker_ua = ua if rng.random() < 0.5 else rng.choice(BROWSER_UAS)
    steps.append(Step(user, True, far, t + rng.uniform(2, 90) * MINUTE, attacker_ua, True))
    return (user,), history, steps


def dormant_account(rng, pools, seed):
    user = _account("dormant_account", seed)
    home = _ip(rng, pools, VN_POOLS)
    ua = rng.choice(BROWSER_UAS)
    habit = _habit(rng)
    history = _history(rng, user, home, ua, n=rng.randint(1, 6), habit=habit, last_day=rng.randint(95, 250))
    ip = _ip(rng, pools, rng.choice((FOREIGN_POOLS, VN_POOLS)), exclude=home)
    return (user,), history, [Step(user, True, ip, rng.uniform(0, DAY), rng.choice(BROWSER_UAS + MOBILE_UAS), True)]


def targeted_mimic(rng, pools, seed):
    """Cố ý khó: thành công đúng giờ quen, CÙNG thành phố, nhà mạng khác, trình duyệt khác nhưng bình thường."""
    user, home, ua, habit, history = _victim(rng, pools, "targeted_mimic", seed, n_min=10)
    ip = _other_vn(rng, pools, home, same_city=True)
    other_ua = rng.choice([u for u in BROWSER_UAS if u != ua])
    return (user,), history, [Step(user, True, ip, habit + rng.uniform(-HOUR, HOUR), other_ua, True)]


def same_country_proxy(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "same_country_proxy", seed)
    ip = _other_vn(rng, pools, home, same_city=False)
    attacker_ua = ua if rng.random() < 0.4 else rng.choice(BROWSER_UAS + MOBILE_UAS)
    return (user,), history, [Step(user, True, ip, rng.uniform(0, DAY), attacker_ua, True)]


def success_after_failures(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "success_after_failures", seed)
    ip = _attacker_ip(rng, pools, home)
    attacker_ua = rng.choice(BROWSER_UAS)
    window = rng.uniform(1, 6) * MINUTE
    n = rng.randint(5, 9)
    start = rng.uniform(0, DAY - HOUR)
    steps = [Step(user, False, ip, start + window * i / n, attacker_ua, True) for i in range(n)]
    steps.append(Step(user, True, ip, start + window + rng.uniform(5, 60), attacker_ua, True))
    return (user,), history, steps


def anonymizer_login(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "anonymizer_login", seed)
    ip = _ip(rng, pools, ANONYMIZER_POOLS)
    attacker_ua = rng.choice(BROWSER_UAS)
    t, steps = rng.uniform(0, DAY - HOUR), []
    for _ in range(rng.randint(0, 3)):
        steps.append(Step(user, False, ip, t, attacker_ua, True))
        t += rng.uniform(10, 120)
    steps.append(Step(user, True, ip, t, attacker_ua, True))
    return (user,), history, steps


def bot_client(rng, pools, seed):
    accounts = tuple(_account("bot_client", seed, i) for i in range(rng.randint(0, 2)))
    history = []
    for user in accounts:
        history += _history(rng, user, _ip(rng, pools, VN_POOLS), rng.choice(BROWSER_UAS), n=rng.randint(3, 10), habit=_habit(rng))
    targets = list(accounts) + [f"ghost_bot_{seed}_{i}" for i in range(rng.randint(1, 3))]
    ua = rng.choice(BOT_UAS + SCRIPT_UAS)
    t, steps = rng.uniform(0, DAY - HOUR), []
    for _ in range(rng.randint(1, 5)):
        steps.append(Step(rng.choice(targets), False, _attacker_ip(rng, pools), t, ua, True))
        t += rng.uniform(30, 600)
    return accounts, tuple(history), steps


def country_hop(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "country_hop", seed)
    countries = rng.sample(FOREIGN_POOLS, rng.randint(3, 4))
    t, steps = rng.uniform(0, DAY - 8 * HOUR), []
    for name in countries:
        steps.append(Step(user, False, _ip(rng, pools, (name,)), t, rng.choice(BROWSER_UAS), True))
        t += rng.uniform(20, 120) * MINUTE
    return (user,), history, steps


def regular_rhythm(rng, pools, seed):
    users = tuple(_account("regular_rhythm", seed, i) for i in range(rng.randint(1, 3)))
    history = []
    for user in users:
        history += _history(rng, user, _ip(rng, pools, VN_POOLS), rng.choice(BROWSER_UAS), n=rng.randint(3, 10), habit=_habit(rng))
    ip = _attacker_ip(rng, pools)
    interval = rng.uniform(3, 25)
    t, steps = rng.uniform(0, DAY - HOUR), []
    for _ in range(rng.randint(8, 14)):
        steps.append(Step(rng.choice(users), False, ip, t, rng.choice(SCRIPT_UAS + BROWSER_UAS[:1]), True))
        t += interval * rng.uniform(0.97, 1.03)  # nhịp gần như cố định — dấu hiệu của máy
    return users, tuple(history), steps


def distributed_botnet_local(rng, pools, seed):
    """MR27 — botnet CÙNG khu vực: 5–10 IP dân cư Việt Nam (nhiều nhà mạng), mỗi IP 1–2 lần sai vào một tài khoản. Không có quốc gia lạ hay
    di chuyển bất khả thi để dựa vào (MR18 chỉ bắt được botnet nước ngoài nhờ khoảng cách địa lý)."""
    user, home, ua, habit, history = _victim(rng, pools, "distributed_botnet_local", seed)
    candidates = [ip for name in VN_POOLS for ip in pools[name] if ip.ip != home.ip]
    bots = rng.sample(candidates, rng.randint(5, 10))
    window = rng.uniform(15, 60) * MINUTE
    start = rng.uniform(0, DAY - 2 * HOUR)
    steps = [Step(user, False, ip, start + rng.uniform(0, window), rng.choice(BROWSER_UAS + MOBILE_UAS), True)
             for ip in bots for _ in range(rng.randint(1, 2))]
    return (user,), history, steps


def login_burst(rng, pools, seed):
    """MR27 — đăng nhập THÀNH CÔNG dồn dập bằng thông tin đã đánh cắp (công cụ lấy phiên/cào dữ liệu): 5–20 lần, cách nhau 10–90 giây, từ
    1–2 IP của kẻ tấn công. Có biến thể dưới ngưỡng luật (8 lần/10 phút)."""
    user, home, ua, habit, history = _victim(rng, pools, "login_burst", seed)
    ips = [_attacker_ip(rng, pools, home) for _ in range(rng.randint(1, 2))]
    attacker_ua = rng.choice(SCRIPT_UAS) if rng.random() < 0.5 else rng.choice(BROWSER_UAS)
    t, steps = rng.uniform(0, DAY - HOUR), []
    for _ in range(rng.randint(5, 20)):
        steps.append(Step(user, True, rng.choice(ips), t, attacker_ua, True))
        t += rng.uniform(10, 90)
    return (user,), history, steps


def otp_guessing(rng, pools, seed):
    """MR28 — kẻ đã có mật khẩu (lộ từ nơi khác) bị đòi OTP và đoán mã: mỗi lượt đăng nhập đúng mật khẩu rồi gửi 5 mã sai (hết lượt của mã),
    1–4 lượt, rồi đăng nhập lại thêm một lần. Một lượt là dưới ngưỡng luật (5 < 10). Giả định mỗi lần đăng nhập của kẻ này đều bị đòi OTP: bộ
    chạy ghi lần sai mã như `POST /login/verify-otp`, bất kể pipeline ra hành động gì."""
    user, home, ua, habit, history = _victim(rng, pools, "otp_guessing", seed)
    ip = _other_vn(rng, pools, home, same_city=False)
    attacker_ua = rng.choice(BROWSER_UAS)
    t, steps = rng.uniform(0, DAY - 2 * HOUR), []
    for _ in range(rng.randint(1, 4)):
        steps.append(Step(user, True, ip, t, attacker_ua, True))
        for _ in range(5):
            t += rng.uniform(5, 20)
            steps.append(Step(user, False, ip, t, attacker_ua, True, kind="otp_fail"))
        t += rng.uniform(60, 300)
    steps.append(Step(user, True, ip, t, attacker_ua, True))
    return (user,), history, steps


def locked_hammering(rng, pools, seed):
    """MR28 — tài khoản đang bị khoá 30 phút; kẻ tấn công cứ thử tiếp 5–40 lần trong lúc khoá (bị cửa `/login` từ chối ngay, không qua
    pipeline), rồi thử thêm 1–4 lần sau khi khoá hết hạn."""
    user, home, ua, habit, history = _victim(rng, pools, "locked_hammering", seed)
    ip = _attacker_ip(rng, pools, home)
    attacker_ua = rng.choice(BROWSER_UAS + SCRIPT_UAS)
    start = rng.uniform(0, DAY - 2 * HOUR)
    until = start + 30 * MINUTE
    steps = [Step(user, False, ip, start + rng.uniform(0, 29 * MINUTE), attacker_ua, True) for _ in range(rng.randint(5, 40))]
    t = until + rng.uniform(10, 300)
    for _ in range(rng.randint(1, 4)):
        steps.append(Step(user, False, ip, t, attacker_ua, True))
        t += rng.uniform(5, 60)
    return (user,), history, steps, (Lock("username", user, until),)


def account_checker(rng, pools, seed):
    """MR28 — sau nhồi thông tin: kẻ có danh sách mật khẩu đúng vào lần lượt 3–12 tài khoản từ MỘT IP bằng MỘT công cụ/trình duyệt (IP và
    thiết bị đều lạ với từng tài khoản), xen 0–3 lần thử tên không tồn tại. Dưới 5 tài khoản là dưới ngưỡng luật."""
    accounts = tuple(_account("account_checker", seed, i) for i in range(rng.randint(3, 12)))
    history = []
    for user in accounts:
        history += _history(rng, user, _ip(rng, pools, VN_POOLS), rng.choice(BROWSER_UAS + MOBILE_UAS), n=rng.randint(3, 15), habit=_habit(rng))
    ip = _attacker_ip(rng, pools)
    attacker_ua = rng.choice(SCRIPT_UAS + BROWSER_UAS)
    targets = list(accounts) + [f"ghost_ac_{seed}_{i}" for i in range(rng.randint(0, 3))]
    t, steps = rng.uniform(0, DAY - 2 * HOUR), []
    for user in rng.sample(targets, len(targets)):
        steps.append(Step(user, user in accounts, ip, t, attacker_ua, True))
        t += rng.uniform(20, 120)
    return accounts, tuple(history), steps


# ------------------------------------------------------------------------------------------------ họ hợp lệ "khó"


def routine(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "routine", seed, n_min=10, n_max=30)
    steps = [Step(user, True, home, d * DAY + habit + rng.uniform(-HOUR, HOUR), ua) for d in range(rng.randint(3, 6))]
    return (user,), history, steps


def new_account(rng, pools, seed):
    user = _account("new_account", seed)
    home, ua, habit = _ip(rng, pools, VN_POOLS), rng.choice(BROWSER_UAS + MOBILE_UAS), _habit(rng)
    days = sorted(rng.sample(range(0, 14), rng.randint(3, 8)))
    return (user,), (), [Step(user, True, home, d * DAY + habit + rng.uniform(-2 * HOUR, 2 * HOUR), ua) for d in days]


def typo(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "typo", seed)
    t, steps = habit + rng.uniform(-HOUR, HOUR), []
    for _ in range(rng.randint(1, 3)):
        steps.append(Step(user, False, home, t, ua))
        t += rng.uniform(10, 90)
    steps.append(Step(user, True, home, t, ua))
    return (user,), history, steps


def heavy_typo(rng, pools, seed):
    """Khó nhất cho luật dò mật khẩu: chính chủ quên mật khẩu, sai 4–6 lần trong vài phút rồi đăng nhập được."""
    user, home, ua, habit, history = _victim(rng, pools, "heavy_typo", seed)
    n, window = rng.randint(4, 6), rng.uniform(1, 8) * MINUTE
    start = habit + rng.uniform(-HOUR, HOUR)
    steps = [Step(user, False, home, start + window * i / n, ua) for i in range(n)]
    steps.append(Step(user, True, home, start + window + rng.uniform(20, 120), ua))
    return (user,), history, steps


def vpn_user(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "vpn_user", seed)
    steps = [Step(user, True, _ip(rng, pools, ("vpn",)), d * DAY + habit + rng.uniform(-HOUR, HOUR), ua) for d in range(rng.randint(1, 3))]
    return (user,), history, steps


def office_nat(rng, pools, seed):
    """5–15 đồng nghiệp đăng nhập trong một giờ qua CÙNG một IP văn phòng (NAT) — giống nguồn nhồi thông tin."""
    office = _ip(rng, pools, VN_POOLS)
    accounts = tuple(_account("office_nat", seed, i) for i in range(rng.randint(5, 15)))
    history, steps = [], []
    start = rng.uniform(0, 3) * HOUR  # 07:00–10:00 giờ Việt Nam
    for user in accounts:
        ua = rng.choice(BROWSER_UAS)
        history += _history(rng, user, office, ua, n=rng.randint(5, 20), habit=start + rng.uniform(0, HOUR))
        t = start + rng.uniform(0, HOUR)
        if rng.random() < 0.2:
            steps.append(Step(user, False, office, t, ua))
            t += rng.uniform(10, 60)
        steps.append(Step(user, True, office, t, ua))
    return accounts, tuple(history), steps


def business_travel(rng, pools, seed):
    """Bay sang nước gần (Singapore, Thái Lan, Hàn Quốc) với thời gian di chuyển HỢP LÝ, dùng thiết bị quen."""
    user, home, ua, habit, history = _victim(rng, pools, "business_travel", seed)
    dest = _ip(rng, pools, TRAVEL_POOLS)
    flight = _distance_km(home, dest) / 800 * HOUR + 2 * HOUR  # 800 km/h + thủ tục
    t = habit + rng.uniform(-HOUR, HOUR)
    steps = [Step(user, True, home, t, ua)]
    t += flight + rng.uniform(0, DAY)
    for _ in range(rng.randint(1, 3)):
        steps.append(Step(user, True, dest, t, ua))
        t += rng.uniform(4, 30) * HOUR
    return (user,), history, steps


def new_device(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "new_device", seed)
    phone = rng.choice([u for u in MOBILE_UAS + BROWSER_UAS if u != ua])
    steps = [Step(user, True, home, d * DAY + habit + rng.uniform(-HOUR, HOUR), phone) for d in range(rng.randint(1, 3))]
    return (user,), history, steps


def mobile_isp_switch(rng, pools, seed):
    """Wifi nhà (FPT/VNPT) xen 4G Viettel cùng thành phố — IP mới mỗi lần nhưng nhà mạng đã quen."""
    user = _account("mobile_isp_switch", seed)
    home = _ip(rng, pools, ("vn_fpt", "vn_vnpt"))
    mobiles = [ip for ip in pools["vn_viettel"] if ip.city == home.city] or list(pools["vn_viettel"])
    ua, habit = rng.choice(MOBILE_UAS), _habit(rng)
    history = []
    for d in range(1, rng.randint(10, 25)):
        ip = home if rng.random() < 0.6 else rng.choice(mobiles)
        history.append(Step(user, True, ip, -d * DAY + habit + rng.uniform(-2 * HOUR, 2 * HOUR), ua))
    steps = [Step(user, True, rng.choice(mobiles), d * DAY + habit + rng.uniform(-2 * HOUR, 2 * HOUR), ua) for d in range(rng.randint(2, 4))]
    return (user,), tuple(sorted(history, key=lambda s: s.offset_s)), steps


def night_login(rng, pools, seed):
    user, home, ua, habit, history = _victim(rng, pools, "night_login", seed)
    night = (habit + rng.uniform(8, 12) * HOUR) % DAY
    steps = [Step(user, True, home, d * DAY + night, ua) for d in range(rng.randint(1, 3))]
    return (user,), history, steps


def relogin(rng, pools, seed):
    """MR27 — chính chủ đăng nhập lại liên tục vài lần (hết phiên, nhiều tab, đổi giữa máy tính và điện thoại): 2–8 lần cách nhau 15–150
    giây ở nhà; 8 lần chỉ ở ~10% biến thể (ca xấu nhất: ứng dụng lỗi phiên). Đối chứng cho luật đăng nhập dồn dập."""
    user, home, ua, habit, history = _victim(rng, pools, "relogin", seed)
    phone = rng.choice(MOBILE_UAS)
    n = rng.choice((2, 2, 3, 3, 3, 4, 4, 5, 6, 8))
    t, steps = habit + rng.uniform(-HOUR, HOUR), []
    for _ in range(n):
        steps.append(Step(user, True, home, t, ua if rng.random() < 0.7 else phone))
        t += rng.uniform(15, 150)
    return (user,), history, steps


def office_nat_day(rng, pools, seed):
    """MR27 — NAT văn phòng LỚN cả ngày làm việc: 15–25 nhân viên cùng một IP, mỗi người 1–2 lần đăng nhập trong 8 giờ, 60–90% có một lần
    gõ sai trước — nhiều tài khoản khác nhau sai ở một IP, rải rác, mỗi tài khoản một lần: đúng dáng "rải mật khẩu chậm". Khác `office_nat`
    (5–15 người trong một giờ, giống nhồi thông tin)."""
    office = _ip(rng, pools, VN_POOLS)
    accounts = tuple(_account("office_nat_day", seed, i) for i in range(rng.randint(15, 25)))
    typo_rate = rng.uniform(0.6, 0.9)
    history, steps = [], []
    start = rng.uniform(0, 2) * HOUR  # 07:00–09:00 giờ Việt Nam
    for user in accounts:
        ua = rng.choice(BROWSER_UAS)
        history += _history(rng, user, office, ua, n=rng.randint(5, 20), habit=start + rng.uniform(0, HOUR))
        for _ in range(rng.randint(1, 2)):
            t = start + rng.uniform(0, 8 * HOUR)
            if rng.random() < typo_rate:
                steps.append(Step(user, False, office, t, ua))
                t += rng.uniform(10, 60)
            steps.append(Step(user, True, office, t, ua))
    return accounts, tuple(history), steps


def otp_typo(rng, pools, seed):
    """MR28 — đối chứng cho `otp_guessing`: chính chủ bị đòi OTP và gõ sai mã 1–5 lần; hết lượt (5 lần) thì đăng nhập lại và sai thêm 0–2 lần
    trước khi đúng — tối đa 7 lần sai."""
    user, home, ua, habit, history = _victim(rng, pools, "otp_typo", seed)
    t = habit + rng.uniform(-HOUR, HOUR)
    steps = [Step(user, True, home, t, ua)]
    wrong = rng.choice((1, 1, 1, 2, 2, 3, 4, 5))
    for _ in range(wrong):
        t += rng.uniform(10, 60)
        steps.append(Step(user, False, home, t, ua, kind="otp_fail"))
    if wrong == 5:
        t += rng.uniform(30, 120)
        steps.append(Step(user, True, home, t, ua))
        for _ in range(rng.randint(0, 2)):
            t += rng.uniform(10, 60)
            steps.append(Step(user, False, home, t, ua, kind="otp_fail"))
    return (user,), history, steps


def locked_owner(rng, pools, seed):
    """MR28 — đối chứng cho `blocked_retry`: chính chủ bị khoá nhầm 30 phút, thử lại 1–8 lần trong lúc khoá (đúng mật khẩu, bị từ chối), rồi
    đăng nhập sau khi khoá hết hạn. 8 lần chỉ ở ~10% biến thể."""
    user, home, ua, habit, history = _victim(rng, pools, "locked_owner", seed)
    start = habit + rng.uniform(-HOUR, HOUR)
    until = start + 30 * MINUTE
    steps = [Step(user, True, home, start + rng.uniform(30, 25 * MINUTE), ua) for _ in range(rng.choice((1, 1, 2, 2, 3, 3, 4, 5, 6, 8)))]
    steps.append(Step(user, True, home, until + rng.uniform(60, 30 * MINUTE), ua))
    return (user,), history, steps, (Lock("username", user, until),)


def training_lab(rng, pools, seed):
    """MR28 — đối chứng KHÓ cho `multi_account_success`: 5–15 nhân viên đăng nhập trong 1 giờ ở phòng máy đào tạo — IP lạ VÀ máy lạ với mọi
    người. Luật không phân biệt được (giới hạn đã biết) — họ này đo đúng cái giá đó."""
    lab = _ip(rng, pools, VN_POOLS)
    lab_ua = rng.choice(BROWSER_UAS)
    accounts = tuple(_account("training_lab", seed, i) for i in range(rng.randint(5, 15)))
    history, steps = [], []
    start = rng.uniform(1, 3) * HOUR
    for user in accounts:
        history += _history(rng, user, _ip(rng, pools, VN_POOLS, exclude=lab), rng.choice(BROWSER_UAS + MOBILE_UAS), n=rng.randint(5, 20), habit=_habit(rng))
        steps.append(Step(user, True, lab, start + rng.uniform(0, HOUR), lab_ua))
    return accounts, tuple(history), steps


def event_wifi(rng, pools, seed):
    """MR28 — đối chứng cho `multi_account_success`: 5–15 người dự hội nghị đăng nhập qua wifi khách sạn (IP lạ với mọi người) bằng máy của
    CHÍNH mình trong 2 giờ."""
    venue = _ip(rng, pools, VN_POOLS)
    accounts = tuple(_account("event_wifi", seed, i) for i in range(rng.randint(5, 15)))
    history, steps = [], []
    start = rng.uniform(1, 3) * HOUR
    for user in accounts:
        ua = rng.choice(BROWSER_UAS + MOBILE_UAS)
        history += _history(rng, user, _ip(rng, pools, VN_POOLS, exclude=venue), ua, n=rng.randint(5, 20), habit=_habit(rng))
        steps.append(Step(user, True, venue, start + rng.uniform(0, 2 * HOUR), ua))
    return accounts, tuple(history), steps


FAMILIES: dict[str, tuple[str, Callable]] = {
    **{f.__name__: ("attack", f) for f in (
        brute_force, credential_stuffing, password_spray_slow, distributed_botnet, ua_rotation, account_enumeration,
        impossible_travel, dormant_account, targeted_mimic, same_country_proxy, success_after_failures, anonymizer_login,
        bot_client, country_hop, regular_rhythm, distributed_botnet_local, login_burst,  # 2 họ: MR27
        otp_guessing, locked_hammering, account_checker,  # MR28
    )},
    **{f.__name__: ("benign", f) for f in (
        routine, new_account, typo, heavy_typo, vpn_user, office_nat, business_travel, new_device, mobile_isp_switch, night_login,
        relogin, office_nat_day,  # MR27
        otp_typo, locked_owner, training_lab, event_wifi,  # MR28
    )},
}


def build_variant(family: str, seed: int, pools: Pools) -> Variant:
    kind, builder = FAMILIES[family]
    rng = random.Random(f"{family}:{seed}")
    built = builder(rng, pools, seed)
    accounts, history, steps = built[:3]
    locks = tuple(built[3]) if len(built) > 3 else ()  # MR28: khoá có sẵn trước biến thể
    steps = tuple(sorted(steps, key=lambda s: s.offset_s))
    assert all(math.isfinite(s.offset_s) for s in steps)
    if kind == "benign":
        assert not any(s.malicious for s in steps), family
    return Variant(family, kind, seed, tuple(accounts), tuple(sorted(history, key=lambda s: s.offset_s)), steps, locks)


def generate(split: str, pools: Pools, *, per_family: int = VARIANTS_PER_FAMILY, families: tuple[str, ...] | None = None) -> list[Variant]:
    seeds = SPLIT_SEEDS[split]
    return [build_variant(family, seeds[i], pools) for family in (families or tuple(FAMILIES)) for i in range(per_family)]
