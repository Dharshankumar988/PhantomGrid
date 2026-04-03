import asyncio
import ipaddress
import socket
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from config import CACHE_TTL_SECONDS, get_supabase_client
from models.schemas import ScanRequest, ThreatAnalysisResponse
from services.abuseipdb import fetch_abuseipdb
from services.geo import fetch_geolocation
from services.otx import fetch_otx, parse_otx_pulse_count
from services.virustotal import fetch_virustotal, parse_vt_detection
from utils.categorizer import extract_threat_categories
from utils.confidence import calculate_confidence_score
from utils.scorer import calculate_risk_score, get_risk_level
from utils.summary import generate_summary

templates = Jinja2Templates(directory="templates")
router = APIRouter()

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = asyncio.Lock()


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
    if not client:
        return

    try:
        client.table("scan_history").insert(payload).execute()
    except Exception:
        return


@router.get("/history")
async def scan_history(limit: int = 20):
    client = get_supabase_client()
    if not client:
        return []

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
        return []


@router.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze(data: ScanRequest):
    target = data.target.strip().lower()

    async with _cache_lock:
        cached = _cache.get(target)
        if cached and (time.time() - cached[0] < CACHE_TTL_SECONDS):
            return cached[1]

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
