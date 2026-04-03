import httpx

from config import REQUEST_TIMEOUT_SECONDS


async def fetch_geolocation(ip: str) -> dict:
    if not ip:
        return {}

    url = f"http://ip-api.com/json/{ip}"

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "success":
                return {}
            return {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "latitude": float(data.get("lat", 0) or 0),
                "longitude": float(data.get("lon", 0) or 0),
            }
    except Exception:
        return {}
