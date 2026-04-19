import asyncio
import ipaddress
import socket
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from api.ws import threat_stream_manager
from config import (
    CACHE_TTL_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
    SUPABASE_KEY,
    SUPABASE_URL,
    TEMPLATES_DIR,
    get_supabase_client,
)
from models.schemas import ScanRequest, ThreatAnalysisResponse
from services.abuseipdb import fetch_abuseipdb, fetch_abuseipdb_blacklist
from services.geo import fetch_geolocation
from services.otx import fetch_otx, parse_otx_pulse_count
from services.virustotal import fetch_virustotal, parse_vt_detection
from utils.categorizer import extract_threat_categories
from utils.confidence import calculate_confidence_score
from utils.scorer import calculate_risk_score, get_risk_level
from utils.summary import generate_summary

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
router = APIRouter()

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = asyncio.Lock()
_rate_limit_lock = asyncio.Lock()
_rate_limit_store: dict[str, list[float]] = {}
_global_stats_cache: tuple[float, dict[str, Any]] | None = None

ANALYZE_RATE_LIMIT_WINDOW_SECONDS = 60
ANALYZE_RATE_LIMIT_MAX_REQUESTS = 30
GLOBAL_STATS_CACHE_TTL_SECONDS = 45

MOCK_THREAT_PROFILES: dict[str, dict[str, Any]] = {
    "demo-high-risk.phantomgrid.test": {
        "risk_score": 92,
        "confidence_score": 89,
        "threat_categories": ["Malware", "Phishing", "Botnet"],
        "detection": {"malicious": 58, "total_engines": 70},
        "geolocation": {
            "country": "United States",
            "city": "Ashburn",
            "isp": "Mock Security ASN",
            "latitude": 39.0438,
            "longitude": -77.4874,
        },
    },
    "phishing-bank-alert.phantomgrid.test": {
        "risk_score": 86,
        "confidence_score": 84,
        "threat_categories": ["Phishing", "Spam"],
        "detection": {"malicious": 47, "total_engines": 70},
        "geolocation": {
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Mock Financial Relay",
            "latitude": 50.1109,
            "longitude": 8.6821,
        },
    },
    "botnet-c2.phantomgrid.test": {
        "risk_score": 95,
        "confidence_score": 91,
        "threat_categories": ["Botnet", "Malware"],
        "detection": {"malicious": 63, "total_engines": 70},
        "geolocation": {
            "country": "Netherlands",
            "city": "Amsterdam",
            "isp": "Mock Command Relay",
            "latitude": 52.3676,
            "longitude": 4.9041,
        },
    },
    "credential-reset-secure.phantomgrid.test": {
        "risk_score": 90,
        "confidence_score": 87,
        "threat_categories": ["Phishing", "Credential Theft"],
        "detection": {"malicious": 54, "total_engines": 70},
        "geolocation": {
            "country": "United Kingdom",
            "city": "London",
            "isp": "Mock Identity Relay",
            "latitude": 51.5072,
            "longitude": -0.1276,
        },
    },
    "crypto-drainer-wallet.phantomgrid.test": {
        "risk_score": 93,
        "confidence_score": 88,
        "threat_categories": ["Scam", "Crypto Theft", "Malware"],
        "detection": {"malicious": 57, "total_engines": 70},
        "geolocation": {
            "country": "Singapore",
            "city": "Singapore",
            "isp": "Mock Blockchain Sink",
            "latitude": 1.3521,
            "longitude": 103.8198,
        },
    },
    "ransom-note-portal.phantomgrid.test": {
        "risk_score": 96,
        "confidence_score": 92,
        "threat_categories": ["Ransomware", "Extortion", "Malware"],
        "detection": {"malicious": 66, "total_engines": 70},
        "geolocation": {
            "country": "Russia",
            "city": "Moscow",
            "isp": "Mock Ransom Relay",
            "latitude": 55.7558,
            "longitude": 37.6173,
        },
    },
    "zero-day-dropper.phantomgrid.test": {
        "risk_score": 94,
        "confidence_score": 90,
        "threat_categories": ["Exploit", "Dropper", "Malware"],
        "detection": {"malicious": 61, "total_engines": 70},
        "geolocation": {
            "country": "Sweden",
            "city": "Stockholm",
            "isp": "Mock Exploit CDN",
            "latitude": 59.3293,
            "longitude": 18.0686,
        },
    },
    "invoice-dropper-mumbai.phantomgrid.test": {
        "risk_score": 91,
        "confidence_score": 88,
        "threat_categories": ["Malware", "Dropper"],
        "detection": {"malicious": 56, "total_engines": 70},
        "geolocation": {
            "country": "India",
            "city": "Mumbai",
            "isp": "Mock Invoice Relay",
            "latitude": 19.076,
            "longitude": 72.8777,
        },
    },
    "cloud-sso-phish-singapore.phantomgrid.test": {
        "risk_score": 89,
        "confidence_score": 86,
        "threat_categories": ["Phishing", "Credential Theft"],
        "detection": {"malicious": 52, "total_engines": 70},
        "geolocation": {
            "country": "Singapore",
            "city": "Singapore",
            "isp": "Mock SSO Gateway",
            "latitude": 1.3521,
            "longitude": 103.8198,
        },
    },
    "dns-tunnel-frankfurt.phantomgrid.test": {
        "risk_score": 87,
        "confidence_score": 85,
        "threat_categories": ["C2", "Data Exfiltration"],
        "detection": {"malicious": 49, "total_engines": 70},
        "geolocation": {
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Mock DNS Transit",
            "latitude": 50.1109,
            "longitude": 8.6821,
        },
    },
    "credential-bot-london.phantomgrid.test": {
        "risk_score": 90,
        "confidence_score": 87,
        "threat_categories": ["Credential Stuffing", "Botnet"],
        "detection": {"malicious": 54, "total_engines": 70},
        "geolocation": {
            "country": "United Kingdom",
            "city": "London",
            "isp": "Mock Auth Flood Node",
            "latitude": 51.5072,
            "longitude": -0.1276,
        },
    },
    "typosquat-repo-tokyo.phantomgrid.test": {
        "risk_score": 88,
        "confidence_score": 84,
        "threat_categories": ["Supply Chain", "Malware"],
        "detection": {"malicious": 50, "total_engines": 70},
        "geolocation": {
            "country": "Japan",
            "city": "Tokyo",
            "isp": "Mock Package Mirror",
            "latitude": 35.6762,
            "longitude": 139.6503,
        },
    },
    "adware-installer-sydney.phantomgrid.test": {
        "risk_score": 82,
        "confidence_score": 80,
        "threat_categories": ["Adware", "PUA"],
        "detection": {"malicious": 43, "total_engines": 70},
        "geolocation": {
            "country": "Australia",
            "city": "Sydney",
            "isp": "Mock Install CDN",
            "latitude": -33.8688,
            "longitude": 151.2093,
        },
    },
    "trojan-update-newyork.phantomgrid.test": {
        "risk_score": 92,
        "confidence_score": 89,
        "threat_categories": ["Trojan", "Malware"],
        "detection": {"malicious": 58, "total_engines": 70},
        "geolocation": {
            "country": "United States",
            "city": "New York",
            "isp": "Mock Update Broker",
            "latitude": 40.7128,
            "longitude": -74.006,
        },
    },
    "smishing-hub-saopaulo.phantomgrid.test": {
        "risk_score": 85,
        "confidence_score": 82,
        "threat_categories": ["Smishing", "Phishing"],
        "detection": {"malicious": 46, "total_engines": 70},
        "geolocation": {
            "country": "Brazil",
            "city": "Sao Paulo",
            "isp": "Mock SMS Redirect",
            "latitude": -23.5505,
            "longitude": -46.6333,
        },
    },
    "exfil-proxy-johannesburg.phantomgrid.test": {
        "risk_score": 93,
        "confidence_score": 90,
        "threat_categories": ["Data Exfiltration", "Proxy"],
        "detection": {"malicious": 60, "total_engines": 70},
        "geolocation": {
            "country": "South Africa",
            "city": "Johannesburg",
            "isp": "Mock Exfil Relay",
            "latitude": -26.2041,
            "longitude": 28.0473,
        },
    },
    "ddos-node-toronto.phantomgrid.test": {
        "risk_score": 86,
        "confidence_score": 83,
        "threat_categories": ["DDoS", "Botnet"],
        "detection": {"malicious": 48, "total_engines": 70},
        "geolocation": {
            "country": "Canada",
            "city": "Toronto",
            "isp": "Mock Amplifier Node",
            "latitude": 43.6532,
            "longitude": -79.3832,
        },
    },
}


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.websocket("/ws/threat-stream")
async def threat_stream(websocket: WebSocket):
    await threat_stream_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await threat_stream_manager.disconnect(websocket)
    except Exception:
        await threat_stream_manager.disconnect(websocket)


def _target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


async def _resolve_domain_to_ip(domain: str) -> str | None:
    try:
        return await asyncio.to_thread(socket.gethostbyname, domain)
    except Exception:
        return None


def _is_public_ip(candidate: str | None) -> bool:
    if not candidate:
        return False

    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False

    return bool(ip.is_global)


def _parse_public_ip(candidate: Any) -> str | None:
    if not isinstance(candidate, str):
        return None

    value = candidate.strip()
    if not value:
        return None

    return value if _is_public_ip(value) else None


def _extract_threat_ip(
    target: str,
    target_type: str,
    resolved_ip: str | None,
    abuse_data: dict[str, Any],
    otx_data: dict[str, Any],
    vt_data: dict[str, Any],
) -> str | None:
    if target_type == "ip" and _is_public_ip(target):
        return target

    abuse_ip = _parse_public_ip(abuse_data.get("ipAddress"))
    if abuse_ip:
        return abuse_ip

    otx_indicator = otx_data.get("indicator") if isinstance(otx_data, dict) else None
    otx_ip = _parse_public_ip(otx_indicator)
    if otx_ip:
        return otx_ip

    vt_dns_records = vt_data.get("last_dns_records", []) if isinstance(vt_data, dict) else []
    if isinstance(vt_dns_records, list):
        for record in vt_dns_records:
            ip_value = _parse_public_ip(record.get("value") if isinstance(record, dict) else None)
            if ip_value:
                return ip_value

    return resolved_ip if _is_public_ip(resolved_ip) else None


def _safe_geo_payload(raw_geo: dict[str, Any]) -> dict[str, Any]:
    return {
        "country": raw_geo.get("country", "") if isinstance(raw_geo, dict) else "",
        "city": raw_geo.get("city", "") if isinstance(raw_geo, dict) else "",
        "isp": raw_geo.get("isp", "") if isinstance(raw_geo, dict) else "",
        "latitude": float((raw_geo or {}).get("latitude", 0) or 0),
        "longitude": float((raw_geo or {}).get("longitude", 0) or 0),
    }


def _location_payload(raw_geo: dict[str, Any]) -> dict[str, Any]:
    geo = _safe_geo_payload(raw_geo)
    return {
        "latitude": geo["latitude"],
        "longitude": geo["longitude"],
        "country": geo["country"],
    }


def _severity_color(risk_level: str) -> str:
    if risk_level == "HIGH":
        return "#ff4d5a"
    if risk_level == "MEDIUM":
        return "#ff9f1a"
    return "#44d06f"


def _build_scan_payload(
    target: str,
    source_input: str,
    resolved_ip: str | None,
    risk_score: int,
    confidence_score: int,
    threat_categories: list[str],
    malicious: int,
    total_engines: int,
    server_geo: dict[str, Any],
    threat_geo: dict[str, Any],
) -> dict[str, Any]:
    risk_level = get_risk_level(risk_score)
    server_location = _location_payload(server_geo)
    threat_origin = _location_payload(threat_geo)
    geolocation = _safe_geo_payload(server_geo)
    timestamp = datetime.now(timezone.utc).isoformat()

    result = {
        "target": target,
        "source_input": source_input,
        "resolved_ip": resolved_ip,
        "risk_score": int(risk_score),
        "confidence_score": int(confidence_score),
        "risk_level": risk_level,
        "threat_categories": threat_categories,
        "detection": {
            "malicious": int(malicious),
            "total_engines": int(total_engines),
        },
        "geolocation": geolocation,
        "server_location": server_location,
        "threat_origin": threat_origin,
        "summary": "",
        "timestamp": timestamp,
        "threat_arc": {
            "from": threat_origin,
            "to": server_location,
            "severity": risk_level,
            "color": _severity_color(risk_level),
        },
        "server_lat": server_location["latitude"],
        "server_lng": server_location["longitude"],
        "threat_lat": threat_origin["latitude"],
        "threat_lng": threat_origin["longitude"],
    }

    result["summary"] = generate_summary(result)
    if result["risk_score"] > 80:
        result["summary"] = f"ALERT: {result['summary']}"

    return result


def _history_storage_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_input": result.get("source_input"),
        "target": result.get("target"),
        "risk_score": result.get("risk_score"),
        "confidence_score": result.get("confidence_score"),
        "risk_level": result.get("risk_level"),
        "threat_categories": result.get("threat_categories", []),
        "detection": result.get("detection", {}),
        "geolocation": result.get("geolocation", {}),
        "summary": result.get("summary", ""),
        "server_lat": result.get("server_lat", 0),
        "server_lng": result.get("server_lng", 0),
        "threat_lat": result.get("threat_lat", 0),
        "threat_lng": result.get("threat_lng", 0),
        "timestamp": result.get("timestamp"),
    }


def _build_cache_hit_result(cached_result: dict[str, Any], source_input: str) -> dict[str, Any]:
    refreshed = dict(cached_result)
    refreshed["source_input"] = source_input
    refreshed["timestamp"] = datetime.now(timezone.utc).isoformat()
    return refreshed


def _store_scan_history(payload: dict[str, Any]) -> None:
    client = get_supabase_client()

    payload_variants: list[dict[str, Any]] = []

    payload_variants.append(dict(payload))

    no_source = dict(payload)
    no_source.pop("source_input", None)
    payload_variants.append(no_source)

    legacy_payload = {
        "target": payload.get("target"),
        "risk_score": payload.get("risk_score", 0),
        "confidence_score": payload.get("confidence_score", 0),
        "risk_level": payload.get("risk_level", "LOW"),
        "threat_categories": payload.get("threat_categories", []),
        "detection": payload.get("detection", {}),
        "geolocation": payload.get("geolocation", {}),
        "summary": payload.get("summary", ""),
    }
    payload_variants.append(legacy_payload)

    for variant in payload_variants:
        if client:
            try:
                client.table("scan_history").insert(variant).execute()
                return
            except Exception:
                pass

        try:
            _insert_history_via_rest(variant)
            return
        except Exception:
            pass

    return


def _supabase_rest_headers() -> dict[str, str]:
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }


def _insert_history_via_rest(payload: dict[str, Any]) -> None:
    if not SUPABASE_URL or not SUPABASE_KEY:
        return

    url = f"{SUPABASE_URL}/rest/v1/scan_history"
    headers = _supabase_rest_headers()
    headers["Prefer"] = "return=minimal"

    with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()


def _fetch_history_via_rest(limit: int) -> list[dict[str, Any]]:
    if not SUPABASE_URL or not SUPABASE_KEY:
        return []

    safe_limit = max(1, min(limit, 100))
    url = f"{SUPABASE_URL}/rest/v1/scan_history?select=*&order=id.desc&limit={safe_limit}"
    headers = _supabase_rest_headers()

    with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            return data
        return []


def _build_mock_result(normalized_target: str, source_input: str, profile: dict[str, Any]) -> dict[str, Any]:
    geo = dict(profile["geolocation"])
    return _build_scan_payload(
        target=normalized_target,
        source_input=source_input,
        resolved_ip=None,
        risk_score=int(profile["risk_score"]),
        confidence_score=int(profile["confidence_score"]),
        threat_categories=list(profile["threat_categories"]),
        malicious=int(profile["detection"].get("malicious", 0)),
        total_engines=int(profile["detection"].get("total_engines", 0)),
        server_geo=geo,
        threat_geo=geo,
    )


def _client_identifier(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        candidate = forwarded_for.split(",")[0].strip()
        if candidate:
            return candidate

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


async def _enforce_analyze_rate_limit(request: Request) -> None:
    client_id = _client_identifier(request)
    now = time.time()
    window_start = now - ANALYZE_RATE_LIMIT_WINDOW_SECONDS

    async with _rate_limit_lock:
        previous = _rate_limit_store.get(client_id, [])
        recent = [ts for ts in previous if ts >= window_start]
        if len(recent) >= ANALYZE_RATE_LIMIT_MAX_REQUESTS:
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Please retry shortly.")

        recent.append(now)
        _rate_limit_store[client_id] = recent


@router.get("/history")
async def scan_history(limit: int = 20):
    client = get_supabase_client()

    if client:
        try:
            response = (
                client.table("scan_history")
                .select("*")
                .order("id", desc=True)
                .limit(max(1, min(limit, 100)))
                .execute()
            )
            return response.data or []
        except Exception:
            pass

    try:
        return _fetch_history_via_rest(limit)
    except Exception:
        return []


@router.get("/client-location")
async def client_location(request: Request):
    client_ip = _client_identifier(request)
    if not _is_public_ip(client_ip):
        return {"available": False}

    geo_data = await fetch_geolocation(client_ip)
    if not geo_data:
        return {"available": False}

    return {
        "available": True,
        "latitude": float(geo_data.get("latitude", 0) or 0),
        "longitude": float(geo_data.get("longitude", 0) or 0),
        "country": geo_data.get("country", ""),
        "source": "server_ip",
    }


@router.get("/supabase-status")
async def supabase_status():
    if not SUPABASE_URL or not SUPABASE_KEY:
        return {"connected": False, "reason": "missing_env"}

    client = get_supabase_client()
    if client:
        try:
            client.table("scan_history").select("id").limit(1).execute()
            return {"connected": True, "reason": "ok"}
        except Exception:
            pass

    try:
        _fetch_history_via_rest(1)
        return {"connected": True, "reason": "ok"}
    except Exception:
        return {"connected": False, "reason": "connection_failed"}


@router.get("/global-live-threats")
async def global_live_threats():
    global _global_stats_cache

    now = time.time()
    if _global_stats_cache and (now - _global_stats_cache[0] < GLOBAL_STATS_CACHE_TTL_SECONDS):
        return _global_stats_cache[1]

    entries = await fetch_abuseipdb_blacklist(confidence_minimum=75, limit=500)
    if not entries:
        payload = {
            "connected": False,
            "source": "abuseipdb",
            "global_malicious_ips": 0,
            "high_confidence_ips": 0,
            "critical_ips": 0,
            "estimated_reports_per_min": 0,
            "countries_flagged": 0,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _global_stats_cache = (now, payload)
        return payload

    total_sources = len(entries)
    high_confidence = sum(1 for row in entries if int(row.get("abuseConfidenceScore", 0) or 0) >= 85)
    critical_sources = sum(1 for row in entries if int(row.get("abuseConfidenceScore", 0) or 0) >= 95)
    total_reports = sum(int(row.get("totalReports", 0) or 0) for row in entries)
    countries = {
        row.get("countryCode", "")
        for row in entries
        if isinstance(row, dict) and row.get("countryCode")
    }

    payload = {
        "connected": True,
        "source": "abuseipdb",
        "global_malicious_ips": int(total_sources),
        "high_confidence_ips": int(high_confidence),
        "critical_ips": int(critical_sources),
        "estimated_reports_per_min": int(round(total_reports / 1440)) if total_reports > 0 else 0,
        "countries_flagged": int(len(countries)),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

    _global_stats_cache = (now, payload)
    return payload


@router.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze(data: ScanRequest, request: Request):
    await _enforce_analyze_rate_limit(request)

    source_input = data.target.strip()
    target = ScanRequest.normalize_target(source_input)

    async with _cache_lock:
        cached = _cache.get(target)
        if cached and (time.time() - cached[0] < CACHE_TTL_SECONDS):
            cached_response = _build_cache_hit_result(cached[1], source_input)
            await asyncio.to_thread(_store_scan_history, _history_storage_payload(cached_response))
            await threat_stream_manager.broadcast({"event": "threat_scan", "data": cached_response})
            return cached_response

    if target in MOCK_THREAT_PROFILES:
        result = _build_mock_result(target, source_input, MOCK_THREAT_PROFILES[target])
        await asyncio.to_thread(_store_scan_history, _history_storage_payload(result))
        await threat_stream_manager.broadcast({"event": "threat_scan", "data": result})

        async with _cache_lock:
            _cache[target] = (time.time(), result)

        return result

    target_type = _target_type(target)
    resolved_ip = target if target_type == "ip" else await _resolve_domain_to_ip(target)

    if target_type == "domain" and not resolved_ip:
        raise HTTPException(status_code=422, detail="Unable to resolve target domain to a public IP address")

    vt_task = fetch_virustotal(target, target_type)
    otx_task = fetch_otx(target, target_type)

    abuse_task = fetch_abuseipdb(resolved_ip) if resolved_ip else asyncio.sleep(0, result={})
    server_geo_task = fetch_geolocation(resolved_ip) if resolved_ip else asyncio.sleep(0, result={})

    vt_data, otx_data, abuse_data, server_geo_data = await asyncio.gather(
        vt_task,
        otx_task,
        abuse_task,
        server_geo_task,
    )

    threat_ip = _extract_threat_ip(target, target_type, resolved_ip, abuse_data, otx_data, vt_data)
    threat_geo_data = await fetch_geolocation(threat_ip) if threat_ip else {}

    vt_malicious, total_engines = parse_vt_detection(vt_data)
    otx_pulses = parse_otx_pulse_count(otx_data)
    abuse_score = int(abuse_data.get("abuseConfidenceScore", 0) or 0)
    report_count = int(abuse_data.get("totalReports", 0) or 0)

    risk_score = calculate_risk_score(abuse_score, vt_malicious, otx_pulses)
    confidence_score = calculate_confidence_score(report_count, vt_malicious, otx_pulses)
    threat_categories = extract_threat_categories(abuse_data, vt_data, otx_data)

    result = _build_scan_payload(
        target=target,
        source_input=source_input,
        resolved_ip=resolved_ip,
        risk_score=risk_score,
        confidence_score=confidence_score,
        threat_categories=threat_categories,
        malicious=vt_malicious,
        total_engines=total_engines,
        server_geo=server_geo_data,
        threat_geo=threat_geo_data if threat_geo_data else server_geo_data,
    )

    await asyncio.to_thread(_store_scan_history, _history_storage_payload(result))
    await threat_stream_manager.broadcast({"event": "threat_scan", "data": result})

    async with _cache_lock:
        _cache[target] = (time.time(), result)

    return result
