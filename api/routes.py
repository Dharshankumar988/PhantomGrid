import asyncio
import ipaddress
import socket
import time
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from config import (
    CACHE_TTL_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
    SUPABASE_KEY,
    SUPABASE_URL,
    TEMPLATES_DIR,
    get_supabase_client,
)
from models.schemas import ScanRequest, ThreatAnalysisResponse
from services.abuseipdb import fetch_abuseipdb
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
}


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


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


def _store_scan_history(payload: dict[str, Any]) -> None:
    client = get_supabase_client()
    if client:
        try:
            client.table("scan_history").insert(payload).execute()
            return
        except Exception:
            pass

    try:
        _insert_history_via_rest(payload)
        return
    except Exception:
        pass

    fallback_payload = dict(payload)
    fallback_payload.pop("source_input", None)

    if client:
        try:
            client.table("scan_history").insert(fallback_payload).execute()
            return
        except Exception:
            pass

    try:
        _insert_history_via_rest(fallback_payload)
    except Exception:
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
    result = {
        "target": normalized_target,
        "source_input": source_input,
        "risk_score": int(profile["risk_score"]),
        "confidence_score": int(profile["confidence_score"]),
        "risk_level": get_risk_level(int(profile["risk_score"])),
        "threat_categories": list(profile["threat_categories"]),
        "detection": dict(profile["detection"]),
        "geolocation": dict(profile["geolocation"]),
        "summary": "",
    }

    result["summary"] = generate_summary(result)
    if result["risk_score"] > 80:
        result["summary"] = f"ALERT: {result['summary']}"

    return result


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


@router.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze(data: ScanRequest):
    source_input = data.target.strip()
    target = ScanRequest.normalize_target(source_input)

    async with _cache_lock:
        cached = _cache.get(target)
        if cached and (time.time() - cached[0] < CACHE_TTL_SECONDS):
            return cached[1]

    if target in MOCK_THREAT_PROFILES:
        result = _build_mock_result(target, source_input, MOCK_THREAT_PROFILES[target])
        await asyncio.to_thread(_store_scan_history, result)

        async with _cache_lock:
            _cache[target] = (time.time(), result)

        return result

    target_type = _target_type(target)
    resolved_ip = target if target_type == "ip" else await _resolve_domain_to_ip(target)

    vt_task = fetch_virustotal(target, target_type)
    otx_task = fetch_otx(target, target_type)

    abuse_task = fetch_abuseipdb(resolved_ip) if resolved_ip else asyncio.sleep(0, result={})
    geo_task = fetch_geolocation(resolved_ip) if resolved_ip else asyncio.sleep(0, result={})

    vt_data, otx_data, abuse_data, geo_data = await asyncio.gather(
        vt_task,
        otx_task,
        abuse_task,
        geo_task,
    )

    vt_malicious, total_engines = parse_vt_detection(vt_data)
    otx_pulses = parse_otx_pulse_count(otx_data)
    abuse_score = int(abuse_data.get("abuseConfidenceScore", 0) or 0)
    report_count = int(abuse_data.get("totalReports", 0) or 0)

    risk_score = calculate_risk_score(abuse_score, vt_malicious, otx_pulses)
    risk_level = get_risk_level(risk_score)
    confidence_score = calculate_confidence_score(report_count, vt_malicious, otx_pulses)
    threat_categories = extract_threat_categories(abuse_data, vt_data, otx_data)

    result = {
        "target": target,
        "source_input": source_input,
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "risk_level": risk_level,
        "threat_categories": threat_categories,
        "detection": {
            "malicious": vt_malicious,
            "total_engines": total_engines,
        },
        "geolocation": {
            "country": geo_data.get("country", ""),
            "city": geo_data.get("city", ""),
            "isp": geo_data.get("isp", ""),
            "latitude": float(geo_data.get("latitude", 0) or 0),
            "longitude": float(geo_data.get("longitude", 0) or 0),
        },
        "summary": "",
    }

    result["summary"] = generate_summary(result)

    if result["risk_score"] > 80:
        result["summary"] = f"ALERT: {result['summary']}"

    await asyncio.to_thread(_store_scan_history, result)

    async with _cache_lock:
        _cache[target] = (time.time(), result)

    return result
