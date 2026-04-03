import httpx

from config import REQUEST_TIMEOUT_SECONDS, VT_API_KEY

VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def fetch_virustotal(target: str, target_type: str) -> dict:
    if not VT_API_KEY or not target:
        return {}

    endpoint = "ip_addresses" if target_type == "ip" else "domains"
    url = f"{VT_BASE_URL}/{endpoint}/{target}"

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json().get("data", {}).get("attributes", {})
    except Exception:
        return {}


def parse_vt_detection(vt_attributes: dict) -> tuple[int, int]:
    stats = vt_attributes.get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        return 0, 0

    malicious = int(stats.get("malicious", 0) or 0)
    total_engines = int(sum(v for v in stats.values() if isinstance(v, int)))
    return malicious, total_engines
