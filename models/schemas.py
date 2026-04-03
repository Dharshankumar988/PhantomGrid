import ipaddress
import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


class ScanRequest(BaseModel):
    target: str = Field(..., description="IP address, domain, or URL")

    @staticmethod
    def normalize_target(candidate: str) -> str:
        value = candidate.strip()
        if not value:
            return ""

        parsed = urlparse(value)
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
            return raw_target
        except ValueError:
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


class ThreatAnalysisResponse(BaseModel):
    target: str
    risk_score: int
    confidence_score: int
    risk_level: str
    threat_categories: list[str]
    detection: Detection
    geolocation: Geolocation
    summary: str
