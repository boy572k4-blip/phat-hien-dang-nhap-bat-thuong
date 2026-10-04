import logging
import secrets
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("config")

# MR32: khoá mẫu đã công khai trong mã nguồn/.env.example — ai đọc repo cũng ký được JWT admin hợp lệ với các khoá này.
_PUBLIC_JWT_SECRETS = frozenset({"change-me-to-a-random-secret", "doi-chuoi-nay-thanh-random-secret-that-dai"})
MIN_JWT_SECRET_BYTES = 32  # HS256: khoá ít nhất bằng độ dài đầu ra của SHA-256


class Settings(BaseSettings):
    """Cấu hình backend, đọc từ biến môi trường / file .env ở gốc repo.

    Chỉ `database_url` là bắt buộc cho Tuần 1. Các trường còn lại đã có
    placeholder để không phải sửa lại cấu trúc khi triển khai các tuần sau
    (Redis ở Tuần 3, GeoIP ở Tuần 3, JWT ở Tuần 5).
    """

    model_config = SettingsConfigDict(env_file="../.env", extra="ignore")

    app_env: str = "development"
    database_url: str = "postgresql+psycopg2://lad_user:lad_password@localhost:5432/lad_db"
    frontend_origin: str = "http://localhost:5173"

    # Tuần 3+
    redis_url: str = "redis://localhost:6379/0"
    geoip_db_path: str = "./geoip/GeoLite2-City.mmdb"
    geoip_asn_db_path: str = "./geoip/GeoLite2-ASN.mmdb"

    # Tuần 5+
    jwt_secret_key: str = "change-me-to-a-random-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # Tuần 6 — CHỈ bật khi demo cục bộ để script impossible_travel.py giả
    # lập IP nguồn qua header X-Forwarded-For. TUYỆT ĐỐI KHÔNG bật nếu
    # backend expose ra internet không qua reverse proxy đáng tin cậy —
    # bật sai chỗ cho phép BẤT KỲ ai tự khai IP nguồn tuỳ ý, né được toàn
    # bộ rule theo IP (brute force theo IP, credential stuffing, GeoIP).
    trust_forwarded_for: bool = False
    # MR32: kể cả khi bật, header chỉ được tin khi kết nối TCP đến từ một trong các địa chỉ này (reverse proxy / máy demo).
    trusted_proxies: str = "127.0.0.1,::1"

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def trusted_proxy_hosts(self) -> frozenset[str]:
        return frozenset(host.strip() for host in self.trusted_proxies.split(",") if host.strip())

    @model_validator(mode="after")
    def _jwt_secret_must_be_private(self) -> "Settings":
        """MR32: khoá JWT là giá trị mẫu công khai hoặc quá ngắn — production: từ chối khởi động; môi trường khác: dùng khoá ngẫu
        nhiên cho riêng tiến trình này (token admin mất hiệu lực khi khởi động lại) và cảnh báo, thay vì âm thầm ký bằng khoá ai cũng có."""
        if self.jwt_secret_key not in _PUBLIC_JWT_SECRETS and len(self.jwt_secret_key.encode("utf-8")) >= MIN_JWT_SECRET_BYTES:
            return self
        if self.is_production:
            raise ValueError(f"JWT_SECRET_KEY là giá trị mẫu công khai hoặc ngắn hơn {MIN_JWT_SECRET_BYTES} byte — đặt khoá ngẫu nhiên trong .env")
        logger.warning(
            "JWT_SECRET_KEY là giá trị mẫu công khai hoặc ngắn hơn %d byte — dùng khoá ngẫu nhiên tạm cho tiến trình này (đăng nhập "
            "quản trị lại sau mỗi lần khởi động). Đặt khoá riêng: python -c \"import secrets; print(secrets.token_urlsafe(48))\"",
            MIN_JWT_SECRET_BYTES,
        )
        self.jwt_secret_key = secrets.token_urlsafe(48)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
