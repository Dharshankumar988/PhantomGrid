import ipaddress
import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


class ScanRequest(BaseModel):
    target: str = Field(..., description="IP address or domain")

    @staticmethod
    def _extract_host(candidate: str) -> str:
        parsed = urlparse(candidate)
        if parsed.hostname:
            return parsed.hostname.strip().lower()
        return candidate

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        target = value.strip()
        if not target:
            raise ValueError("Target is required")

        if "://" in target or target.startswith("//"):
            target = cls._extract_host(target)

        if not target:
            raise ValueError("Target is required")

        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            if DOMAIN_REGEX.match(target):
                return target.lower()

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
