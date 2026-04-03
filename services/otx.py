import httpx

from config import OTX_API_KEY, REQUEST_TIMEOUT_SECONDS

OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


async def fetch_otx(target: str, target_type: str) -> dict:
    if not OTX_API_KEY or not target:
        return {}

    indicator_type = "IPv4" if target_type == "ip" else "domain"
    url = f"{OTX_BASE_URL}/{indicator_type}/{target}/general"

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
    except Exception:
        return {}


def parse_otx_pulse_count(otx_data: dict) -> int:
    pulses = otx_data.get("pulse_info", {}).get("pulses", [])
    if isinstance(pulses, list):
        return len(pulses)
    return 0
