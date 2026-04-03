import httpx

from config import ABUSE_API_KEY, REQUEST_TIMEOUT_SECONDS

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"


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
