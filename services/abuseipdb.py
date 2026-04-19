import httpx

from config import ABUSE_API_KEY, REQUEST_TIMEOUT_SECONDS

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"


async def fetch_abuseipdb(ip: str) -> dict:
    if not ABUSE_API_KEY or not ip:
        return {}

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(ABUSE_URL, headers=headers, params=params)
            response.raise_for_status()
            return response.json().get("data", {})
    except Exception:
        return {}


async def fetch_abuseipdb_blacklist(confidence_minimum: int = 75, limit: int = 500) -> list[dict]:
    if not ABUSE_API_KEY:
        return []

    safe_confidence = max(25, min(confidence_minimum, 100))
    safe_limit = max(100, min(limit, 10000))

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": safe_confidence,
        "limit": safe_limit,
        "plaintext": "false",
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(ABUSE_BLACKLIST_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json().get("data", [])
            return data if isinstance(data, list) else []
    except Exception:
        return []
