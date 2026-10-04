"""Kiểm tra nhiệm vụ 6.1 — resolve_client_ip chỉ tin X-Forwarded-For khi
TRUST_FORWARDED_FOR được bật tường minh (mặc định phải là False) — và (MR32) chỉ khi kết nối đến từ proxy tin cậy, đọc từ phải sang."""

from types import SimpleNamespace

import pytest

from app.utils.network import resolve_client_ip

LOOPBACK = frozenset({"127.0.0.1", "::1"})


def _fake_request(forwarded_for: str | None, peer: str = "127.0.0.1") -> SimpleNamespace:
    headers = {} if forwarded_for is None else {"x-forwarded-for": forwarded_for}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))


@pytest.fixture
def settings(monkeypatch):
    def use(trust: bool, proxies=LOOPBACK):
        monkeypatch.setattr("app.utils.network.get_settings", lambda: SimpleNamespace(trust_forwarded_for=trust, trusted_proxy_hosts=proxies))
    return use


def test_uses_real_tcp_ip_by_default(settings):
    settings(False)
    assert resolve_client_ip(_fake_request("1.2.3.4", peer="9.9.9.9")) == "9.9.9.9"
    assert resolve_client_ip(_fake_request("1.2.3.4")) == "127.0.0.1"


def test_trusts_forwarded_header_only_when_enabled_and_from_a_trusted_proxy(settings):
    settings(True)
    assert resolve_client_ip(_fake_request("1.2.3.4")) == "1.2.3.4"            # script demo trên chính máy chạy backend
    assert resolve_client_ip(_fake_request("1.2.3.4", peer="9.9.9.9")) == "9.9.9.9"  # máy khác trong mạng tự khai header: bỏ qua


def test_reads_right_to_left_so_client_cannot_choose_its_ip_behind_a_proxy(settings):
    settings(True, proxies=frozenset({"127.0.0.1", "10.0.0.2"}))
    # client tự khai "1.2.3.4", proxy nối IP thật 5.6.7.8 vào cuối, rồi một proxy tin cậy nội bộ
    assert resolve_client_ip(_fake_request("1.2.3.4, 5.6.7.8, 10.0.0.2")) == "5.6.7.8"


def test_falls_back_to_real_ip_when_header_missing_or_not_an_ip(settings):
    settings(True)
    assert resolve_client_ip(_fake_request(None)) == "127.0.0.1"
    assert resolve_client_ip(_fake_request("khong-phai-ip")) == "127.0.0.1"
    assert resolve_client_ip(_fake_request("127.0.0.1")) == "127.0.0.1"
