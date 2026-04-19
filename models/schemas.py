import ipaddress
import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
SAFE_HOST_REGEX = re.compile(r"^[a-z0-9.-]{1,253}$")


class ScanRequest(BaseModel):
    target: str = Field(..., description="IP address, domain, or URL")

    @staticmethod
    def _is_safe_public_ip(candidate: str) -> bool:
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return False

        return bool(ip.is_global)

    @staticmethod
    def _is_unsafe_hostname(hostname: str) -> bool:
        blocked_hosts = {
            "localhost",
            "localhost.localdomain",
            "metadata.google.internal",
            "169.254.169.254",
            "0.0.0.0",
            "127.0.0.1",
            "::1",
        }

        blocked_suffixes = (
            ".local",
            ".internal",
            ".home",
            ".localhost",
        )

        return hostname in blocked_hosts or hostname.endswith(blocked_suffixes)

    @staticmethod
    def normalize_target(candidate: str) -> str:
        value = candidate.strip()
        if not value:
            return ""

        parsed = urlparse(value)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            return ""

        if parsed.hostname:
            return parsed.hostname.strip().lower()

        return value.lower()

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        raw_target = value.strip()
        if not raw_target:
            raise ValueError("Target is required")

        normalized = cls.normalize_target(raw_target)
        if not normalized:
            raise ValueError("Target is required")

        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            pass
        else:
            if not cls._is_safe_public_ip(normalized):
                raise ValueError("Private, reserved, or local IP ranges are not allowed")
            return raw_target

        if cls._is_unsafe_hostname(normalized):
            raise ValueError("Local or internal hosts are not allowed")

        if not SAFE_HOST_REGEX.match(normalized):
            raise ValueError("Target contains invalid characters")

        if DOMAIN_REGEX.match(normalized):
            return raw_target

        raise ValueError("Target must be a valid IP address, domain, or URL")


class Detection(BaseModel):
    malicious: int
    total_engines: int


class Geolocation(BaseModel):
    country: str
    city: str
    isp: str
    latitude: float
    longitude: float


class ThreatLocation(BaseModel):
    latitude: float
    longitude: float
    country: str


class ThreatAnalysisResponse(BaseModel):
    target: str
    resolved_ip: str | None = None
    risk_score: int
    confidence_score: int
    risk_level: str
    threat_categories: list[str]
    detection: Detection
    geolocation: Geolocation
    server_location: ThreatLocation
    threat_origin: ThreatLocation
    summary: str
