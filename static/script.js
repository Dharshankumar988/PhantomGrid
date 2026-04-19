const form = document.getElementById("scanForm");
const input = document.getElementById("targetInput");
const loading = document.getElementById("loading");
const errorText = document.getElementById("errorText");
const results = document.getElementById("results");
const analyzeBtn = document.getElementById("analyzeBtn");
const alertBanner = document.getElementById("alertBanner");
const analyzedTarget = document.getElementById("analyzedTarget");
const mapMeta = document.getElementById("mapMeta");
const tooltipEl = document.getElementById("globeTooltip");
const liveRefreshTime = document.getElementById("liveRefreshTime");
const liveCounterOAS = document.getElementById("liveCounterOAS");
const liveCounterODS = document.getElementById("liveCounterODS");
const liveCounterMAV = document.getElementById("liveCounterMAV");
const liveCounterWAV = document.getElementById("liveCounterWAV");
const liveCounterIDS = document.getElementById("liveCounterIDS");
const liveCounterVUL = document.getElementById("liveCounterVUL");
const liveCounterKAS = document.getElementById("liveCounterKAS");
const liveCounterRMW = document.getElementById("liveCounterRMW");
const liveEventFeed = document.getElementById("liveEventFeed");

const MAX_ACTIVE_POINTS = 50;
const MAX_HISTORY_ITEMS = 15;
const ARC_LIFETIME_MS = 22000;
const HISTORY_REFRESH_MS = 3000;
const state = {
  globe: null,
  activePoints: [],
  historyPoints: [],
  requesterPoint: null,
  activeArcs: [],
  historyArcs: [],
  requesterArcs: [],
  historyItems: [],
  historySignature: "",
  seenEvents: new Set(),
  ws: null,
  clientLocation: null,
  baselineItems: [],
  userSearchItems: [],
  renderedItems: [],
  globalCounters: null,
  counterValues: {
    oas: 0,
    ods: 0,
    mav: 0,
    wav: 0,
    ids: 0,
    vul: 0,
    kas: 0,
    rmw: 0,
  },
  supabaseConnected: null,
  geoWatchId: null,
  globeResizeObserver: null,
  activeSearchTargets: new Set(),
  highlightedTarget: "",
  highlightedUntil: 0,
};

function applyClientLocation(location, options = {}) {
  if (!location || !isFiniteCoord(location.latitude, location.longitude)) return false;

  state.clientLocation = {
    latitude: Number(location.latitude),
    longitude: Number(location.longitude),
    country: safeText(location.country, ""),
    city: safeText(location.city, ""),
    source: safeText(location.source, ""),
  };

  buildHistoryPoints();
  buildHistoryArcs();
  buildRequesterArcs();
  setGlobeData();

  if (!options.silentFocus) {
    focusGlobe(state.clientLocation.latitude, state.clientLocation.longitude, 1.45);
  }

  return true;
}

function mergeBaselineAndUserItems() {
  const merged = [];
  const seen = new Set();

  state.baselineItems.forEach((item) => {
    if (!seen.has(item.eventId)) {
      seen.add(item.eventId);
      merged.push(item);
    }
  });

  state.userSearchItems.forEach((item) => {
    if (!seen.has(item.eventId)) {
      seen.add(item.eventId);
      merged.push(item);
    }
  });

  state.renderedItems = merged;
}

const categoryClassMap = {
  Malware: "badge-malware",
  Botnet: "badge-botnet",
  Phishing: "badge-phishing",
  Spam: "badge-spam",
};

function setLoading(isLoading) {
  loading.classList.toggle("hidden", !isLoading);
  loading.classList.toggle("flex", isLoading);
  analyzeBtn.disabled = isLoading;
}

function setError(message = "") {
  if (!message) {
    errorText.classList.add("hidden");
    errorText.textContent = "";
    return;
  }
  errorText.classList.remove("hidden");
  errorText.textContent = String(message);
}

function normalizeApiError(detail) {
  if (!detail) return "Failed to analyze target";

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (typeof item === "string" ? item : item?.msg || null))
    if (messages.length > 0) return messages.join(" | ");
  }

  if (typeof detail === "object" && detail.msg) return detail.msg;
  return "Failed to analyze target";
}

function debounce(fn, wait = 250) {
  let timeoutId;
  return (...args) => {
    window.clearTimeout(timeoutId);
    timeoutId = window.setTimeout(() => fn(...args), wait);
  };
}

function clampScore(score) {
  const n = Number(score || 0);
  return Math.max(0, Math.min(100, n));
}

function toFiniteOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function riskColor(level) {
  if (level === "HIGH") return "#ff4057";
  if (level === "MEDIUM") return "#ff9f1a";
  return "#3ad97f";
}

function riskColorFromScore(score, alpha = 0.9) {
  const clamped = clampScore(score);
  const red = Math.round(70 + (185 * clamped) / 100);
  const green = Math.round(168 - (140 * clamped) / 100);
  const blue = Math.round(255 - (205 * clamped) / 100);
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

function stableHash(input) {
  const str = String(input || "");
  let hash = 0;
  for (let i = 0; i < str.length; i += 1) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

function eventArcJitter(eventKey, magnitude = 0.45) {
  const seed = stableHash(eventKey);
  const angle = ((seed % 360) * Math.PI) / 180;
  const ring = 0.22 + ((seed % 1000) / 1000) * magnitude;

  return {
    lat: Math.sin(angle) * ring,
    lng: Math.cos(angle) * ring,
  };
}

function angularDistanceDegrees(startLat, startLng, endLat, endLng) {
  const toRad = (deg) => (deg * Math.PI) / 180;
  const lat1 = toRad(Number(startLat));
  const lon1 = toRad(Number(startLng));
  const lat2 = toRad(Number(endLat));
  const lon2 = toRad(Number(endLng));

  const dLat = lat2 - lat1;
  const dLon = lon2 - lon1;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return (c * 180) / Math.PI;
}

function arcAltitudeFromDistance(startLat, startLng, endLat, endLng, floor = 0.22, ceil = 0.58) {
  const ang = angularDistanceDegrees(startLat, startLng, endLat, endLng);
  const normalized = Math.min(1, Math.max(0, ang / 180));
  return floor + ((ceil - floor) * normalized);
}

function getRiskRingClass(level) {
  if (level === "HIGH") return "risk-high";
  if (level === "MEDIUM") return "risk-medium";
  return "risk-low";
}

function isFiniteCoord(lat, lng) {
  return Number.isFinite(Number(lat)) && Number.isFinite(Number(lng));
}

function safeText(value, fallback = "-") {
  if (value === null || value === undefined) return fallback;
  const str = String(value).trim();
  return str.length > 0 ? str : fallback;
}

function nowStamp() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function animateCounterValue(key, target, element, suffix = "") {
  if (!element) return;

  const start = Number(state.counterValues[key] || 0);
  const end = Number(target || 0);
  if (start === end) {
    element.textContent = `${Math.round(end)}${suffix}`;
    return;
  }

  const duration = 460;
  const startTime = performance.now();

  function frame(now) {
    const progress = Math.min(1, (now - startTime) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    const value = start + (end - start) * eased;
    element.textContent = `${Math.round(value)}${suffix}`;

    if (progress < 1) {
      window.requestAnimationFrame(frame);
      return;
    }

    state.counterValues[key] = end;
  }

  window.requestAnimationFrame(frame);
}

function levelDotColor(riskLevel) {
  if (riskLevel === "HIGH") return "#ff5d74";
  if (riskLevel === "MEDIUM") return "#ffb05d";
  return "#57d389";
}

function toDisplayTime(isoValue) {
  const parsed = new Date(isoValue);
  if (Number.isNaN(parsed.getTime())) return "--:--:--";
  return parsed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function normalizeTargetKey(value) {
  return safeText(value, "").toLowerCase();
}

function isTargetHighlighted(target) {
  const key = normalizeTargetKey(target);
  if (!key) return false;

  if (state.activeSearchTargets.has(key)) return true;
  return state.highlightedTarget === key && Date.now() <= Number(state.highlightedUntil || 0);
}

function pulseWave(speed = 220) {
  return (Math.sin(Date.now() / speed) + 1) / 2;
}

function glowColorByRisk(riskScore, alpha = 1) {
  const score = clampScore(riskScore);
  if (score >= 80) return `rgba(255, 88, 118, ${alpha})`;
  if (score >= 45) return `rgba(255, 179, 77, ${alpha})`;
  return `rgba(92, 236, 148, ${alpha})`;
}

function initializeGlobe() {
  const globeContainer = document.getElementById("globeViz");
  if (!globeContainer || typeof Globe !== "function") return;

  const globe = Globe()(globeContainer)
    .backgroundColor("#04070f")
    .globeImageUrl("https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg")
    .bumpImageUrl("https://unpkg.com/three-globe/example/img/earth-topology.png")
    .showAtmosphere(true)
    .showGraticules(true)
    .atmosphereColor("#7aa8ff")
    .atmosphereAltitude(0.1)
    .pointLat((d) => d.lat)
    .pointLng((d) => d.lng)
    .pointAltitude((d) => d.altitude)
    .pointRadius((d) => d.radius)
    .pointColor((d) => d.color)
    .onPointHover((point, prevPoint) => {
      if (prevPoint && prevPoint.__el) prevPoint.__el.classList.remove("hovered");
      if (!point) {
        tooltipEl.classList.add("hidden");
        return;
      }

      tooltipEl.classList.remove("hidden");
      const description = safeText(point.description, "No additional details");
      tooltipEl.textContent = `${safeText(point.label)} | ${safeText(point.country)} | Risk ${safeText(point.riskScore, "0")} | ${description}`;
    })
    .onPointClick((point) => {
      focusGlobe(point.lat, point.lng, 1.3);
    })
    .arcStartLat((d) => d.startLat)
    .arcStartLng((d) => d.startLng)
    .arcEndLat((d) => d.endLat)
    .arcEndLng((d) => d.endLng)
    .arcAltitude((d) => (Number.isFinite(Number(d.altitude)) ? Number(d.altitude) : null))
    .arcAltitudeAutoScale((d) => (Number.isFinite(Number(d.altitudeAutoScale)) ? Number(d.altitudeAutoScale) : 0))
    .arcColor((d) => d.color)
    .arcStroke((d) => d.stroke || 0.6)
    .arcDashLength(0.45)
    .arcDashGap(0.85)
    .arcDashAnimateTime((d) => d.dashTime || 2800)
    .onArcHover((arc) => {
      if (!arc) {
        tooltipEl.classList.add("hidden");
        return;
      }

      tooltipEl.classList.remove("hidden");
      tooltipEl.textContent = `${safeText(arc.label)} | Threat: ${safeText(arc.threatType, "No threat detected")}`;
    });

  const controls = globe.controls();
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.23;
  controls.enableZoom = true;
  controls.enablePan = false;
  controls.minDistance = 110;
  controls.maxDistance = 320;

  globeContainer.addEventListener("mouseenter", () => {
    controls.autoRotate = false;
  });

  globeContainer.addEventListener("mouseleave", () => {
    controls.autoRotate = true;
  });

  state.globe = globe;
  syncGlobeDimensions();
  setupGlobeResizeHandling();

  window.addEventListener("mousemove", (event) => {
    tooltipEl.style.left = `${event.clientX + 16}px`;
    tooltipEl.style.top = `${event.clientY + 16}px`;
  });
}

function syncGlobeDimensions() {
  const globeContainer = document.getElementById("globeViz");
  if (!state.globe || !globeContainer) return;

  const width = Math.max(280, Math.floor(globeContainer.clientWidth || 0));
  const height = Math.max(240, Math.floor(globeContainer.clientHeight || 0));
  state.globe.width(width).height(height);
}

function setupGlobeResizeHandling() {
  const globeContainer = document.getElementById("globeViz");
  if (!globeContainer) return;

  if (state.globeResizeObserver) {
    state.globeResizeObserver.disconnect();
    state.globeResizeObserver = null;
  }

  if (typeof ResizeObserver === "function") {
    state.globeResizeObserver = new ResizeObserver(() => {
      syncGlobeDimensions();
    });
    state.globeResizeObserver.observe(globeContainer);
  }

  window.addEventListener("resize", syncGlobeDimensions);
  if (window.visualViewport) {
    window.visualViewport.addEventListener("resize", syncGlobeDimensions);
  }
}

function focusGlobe(lat, lng, altitude = 1.9) {
  if (!state.globe || !isFiniteCoord(lat, lng)) return;
  state.globe.pointOfView(
    {
      lat: Number(lat),
      lng: Number(lng),
      altitude,
    },
    950,
  );
}

function updateRiskCard(data) {
  const ring = document.getElementById("riskRing");
  const score = document.getElementById("riskScore");
  const level = document.getElementById("riskLevel");

  ring.classList.remove("risk-low", "risk-medium", "risk-high");
  ring.classList.add(getRiskRingClass(data.risk_level));
  ring.style.setProperty("--risk-pct", String(clampScore(data.risk_score)));

  score.textContent = String(clampScore(data.risk_score));
  level.textContent = safeText(data.risk_level, "LOW");
  analyzedTarget.textContent = safeText(data.target, "Unknown");
}

function updateAlert(data) {
  alertBanner.classList.toggle("hidden", Number(data.risk_score || 0) <= 80);
}

function updateDetection(data) {
  const text = document.getElementById("detectionText");
  const bar = document.getElementById("detectionBar");

  const malicious = Number(data.detection?.malicious || 0);
  const total = Number(data.detection?.total_engines || 0);
  const ratio = total > 0 ? (malicious / total) * 100 : 0;

  text.textContent = `${malicious} / ${total} engines flagged`;
  bar.style.width = `${Math.min(100, ratio)}%`;
}

function updateConfidence(data) {
  const value = document.getElementById("confidenceValue");
  const bar = document.getElementById("confidenceBar");
  const confidence = clampScore(data.confidence_score);

  value.textContent = `${confidence}%`;
  bar.style.width = `${confidence}%`;
}

function renderCategories(categories) {
  const tags = document.getElementById("categoryTags");
  tags.textContent = "";

  if (!Array.isArray(categories) || categories.length === 0) {
    const empty = document.createElement("span");
    empty.className = "text-slate-300 text-sm";
    empty.textContent = "No significant categories extracted";
    tags.appendChild(empty);
    return;
  }

  categories.forEach((category) => {
    const badge = document.createElement("span");
    badge.className = `category-badge ${categoryClassMap[category] || "badge-spam"}`;
    badge.textContent = safeText(category, "Unknown");
    tags.appendChild(badge);
  });
}

function updateGeo(data) {
  const server = data.server_location || {};
  const threat = data.threat_origin || {};
  const geo = data.geolocation || {};

  document.getElementById("geoCountry").textContent = safeText(server.country || geo.country);
  document.getElementById("geoCity").textContent = safeText(geo.city);
  document.getElementById("geoISP").textContent = safeText(geo.isp);

  document.getElementById("threatCountry").textContent = safeText(threat.country);
  document.getElementById("threatLat").textContent = Number.isFinite(Number(threat.latitude)) ? Number(threat.latitude).toFixed(4) : "-";
  document.getElementById("threatLng").textContent = Number.isFinite(Number(threat.longitude)) ? Number(threat.longitude).toFixed(4) : "-";
}

function renderSummary(summary) {
  document.getElementById("summaryText").textContent = safeText(summary, "No summary available.");
}

function buildActivePoints(scan) {
  const risk = safeText(scan.risk_level, "LOW");
  const color = riskColor(risk);
  const server = scan.server_location || {};
  const threat = scan.threat_origin || {};
  const targetRef = safeText(scan.source_input || scan.target);
  const isLiveTarget = isTargetHighlighted(targetRef);

  const points = [];

  if (isFiniteCoord(server.latitude, server.longitude)) {
    points.push({
      lat: Number(server.latitude),
      lng: Number(server.longitude),
      altitude: 0.06,
      radius: 0.65,
      color: "#39a8ff",
      label: `Server ${safeText(scan.target, "target")}`,
      country: safeText(server.country),
      riskScore: clampScore(scan.risk_score),
      description: `Server host location | Confidence ${clampScore(scan.confidence_score)}`,
      kind: "server",
      liveGlow: isLiveTarget,
    });
  }

  if (isFiniteCoord(threat.latitude, threat.longitude)) {
    points.push({
      lat: Number(threat.latitude),
      lng: Number(threat.longitude),
      altitude: 0.08,
      radius: 0.85,
      color,
      label: `Threat origin ${safeText(scan.target, "target")}`,
      country: safeText(threat.country),
      riskScore: clampScore(scan.risk_score),
      description: `Threat origin | ${Array.isArray(scan.threat_categories) && scan.threat_categories.length > 0 ? scan.threat_categories.join(", ") : "No category"}`,
      kind: "threat",
      liveGlow: isLiveTarget,
    });
  }

  return points;
}

function addActiveThreatArc(scan) {
  const origin = scan.threat_origin || {};
  const server = scan.server_location || {};

  const hasThreat = isFiniteCoord(origin.latitude, origin.longitude);
  const hasServer = isFiniteCoord(server.latitude, server.longitude);
  if (!hasThreat && !hasServer) return;

  const sink = state.clientLocation && isFiniteCoord(state.clientLocation.latitude, state.clientLocation.longitude)
    ? { latitude: Number(state.clientLocation.latitude), longitude: Number(state.clientLocation.longitude) }
    : (hasServer ? { latitude: Number(server.latitude), longitude: Number(server.longitude) } : null);

  if (!sink) return;

  const source = hasThreat
    ? { latitude: Number(origin.latitude), longitude: Number(origin.longitude) }
    : { latitude: Number(server.latitude), longitude: Number(server.longitude) };

  const categories = Array.isArray(scan.threat_categories) && scan.threat_categories.length > 0
    ? scan.threat_categories.join(", ")
    : "No threat detected";
  const isLiveTarget = isTargetHighlighted(scan.source_input || scan.target);

  state.activeArcs.push({
    startLat: source.latitude,
    startLng: source.longitude,
    endLat: sink.latitude,
    endLng: sink.longitude,
    altitude: arcAltitudeFromDistance(source.latitude, source.longitude, sink.latitude, sink.longitude, 0.26, 0.62),
    altitudeAutoScale: 0,
    baseColor: riskColor(safeText(scan.risk_level, "LOW")),
    color: riskColor(safeText(scan.risk_level, "LOW")),
    stroke: 0.72,
    dashTime: 2500,
    label: `${safeText(scan.target)} threat to current location`,
    threatType: categories,
    createdAt: Date.now(),
    liveGlow: isLiveTarget,
    riskScore: clampScore(scan.risk_score),
  });
}

function addActiveRequesterArc(scan) {
  const target = scan.server_location || {};
  const requester = state.clientLocation;
  if (!requester || !isFiniteCoord(target.latitude, target.longitude)) return;
  const isLiveTarget = isTargetHighlighted(scan.source_input || scan.target);

  state.activeArcs.push({
    startLat: Number(target.latitude),
    startLng: Number(target.longitude),
    endLat: Number(requester.latitude),
    endLng: Number(requester.longitude),
    altitude: arcAltitudeFromDistance(target.latitude, target.longitude, requester.latitude, requester.longitude, 0.24, 0.56),
    altitudeAutoScale: 0,
    baseColor: "#4aa8ff",
    color: "#4aa8ff",
    stroke: 0.55,
    dashTime: 2900,
    label: `${safeText(scan.target)} server to requester`,
    threatType: "Request trace",
    createdAt: Date.now(),
    liveGlow: isLiveTarget,
    riskScore: clampScore(scan.risk_score),
  });
}

function buildHistoryArcs() {
  const sink = state.clientLocation && isFiniteCoord(state.clientLocation.latitude, state.clientLocation.longitude)
    ? { latitude: Number(state.clientLocation.latitude), longitude: Number(state.clientLocation.longitude) }
    : null;

  state.historyArcs = state.renderedItems
    .filter((item) => isFiniteCoord(item.serverLat, item.serverLng))
    .map((item) => {
      const hasThreatOrigin = isFiniteCoord(item.threatLat, item.threatLng)
        && (Math.abs(item.threatLat - item.serverLat) > 0.0001 || Math.abs(item.threatLng - item.serverLng) > 0.0001);

      const startLat = hasThreatOrigin ? item.threatLat : item.serverLat;
      const startLng = hasThreatOrigin ? item.threatLng : item.serverLng;
      const jitter = eventArcJitter(item.eventId || `${item.target}|${item.timestamp}`, 0.35);
      const endLat = sink ? sink.latitude : item.serverLat;
      const endLng = sink ? sink.longitude : item.serverLng;
      const jitteredStartLat = startLat + jitter.lat;
      const jitteredStartLng = startLng + jitter.lng;

      return {
        startLat: jitteredStartLat,
        startLng: jitteredStartLng,
        endLat,
        endLng,
        altitude: arcAltitudeFromDistance(jitteredStartLat, jitteredStartLng, endLat, endLng, hasThreatOrigin ? 0.25 : 0.22, hasThreatOrigin ? 0.6 : 0.52),
        altitudeAutoScale: 0,
        color: hasThreatOrigin ? riskColorFromScore(item.riskScore, 0.5) : "rgba(74,168,255,0.25)",
        stroke: 0.45,
        dashTime: 4200,
        label: sink ? `History ${item.target} to current location` : `History ${item.target}`,
        threatType: hasThreatOrigin ? item.threatType : "No threat detected",
        liveGlow: isTargetHighlighted(item.target),
        riskScore: item.riskScore,
      };
    });
}

function buildRequesterArcs() {
  if (!state.clientLocation || !isFiniteCoord(state.clientLocation.latitude, state.clientLocation.longitude)) {
    state.requesterArcs = [];
    return;
  }

  state.requesterArcs = state.renderedItems
    .filter((item) => isFiniteCoord(item.serverLat, item.serverLng))
    .map((item) => {
      const hasThreatOrigin = isFiniteCoord(item.threatLat, item.threatLng)
        && (Math.abs(item.threatLat - item.serverLat) > 0.0001 || Math.abs(item.threatLng - item.serverLng) > 0.0001);
      const jitter = eventArcJitter(item.eventId || `${item.target}|${item.timestamp}`, 0.42);
      const startLat = (hasThreatOrigin ? item.threatLat : item.serverLat) + jitter.lat;
      const startLng = (hasThreatOrigin ? item.threatLng : item.serverLng) + jitter.lng;
      const endLat = Number(state.clientLocation.latitude);
      const endLng = Number(state.clientLocation.longitude);

      return {
      startLat,
      startLng,
      endLat,
      endLng,
      altitude: arcAltitudeFromDistance(startLat, startLng, endLat, endLng, 0.24, 0.56),
      altitudeAutoScale: 0,
      color: "rgba(77, 170, 255, 0.4)",
      stroke: 0.38,
      dashTime: 3600,
      label: `${item.target} to current location`,
      threatType: item.threatType || "Requester trace",
      liveGlow: isTargetHighlighted(item.target),
      riskScore: item.riskScore,
    };
    });
}

function targetSearchCountMap(items) {
  const counts = new Map();
  items.forEach((item) => {
    const key = safeText(item.target, "Unknown");
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return counts;
}

function renderLiveDashboard() {
  const items = state.renderedItems;
  const total = items.length;

  let high = 0;
  let threats = 0;
  let medium = 0;
  let low = 0;
  const uniqueTargets = new Set();
  const oneMinuteAgo = Date.now() - 60000;
  let perMinute = 0;

  items.forEach((item) => {
    uniqueTargets.add(item.target);

    if (item.riskLevel === "HIGH") high += 1;
    else if (item.riskLevel === "MEDIUM") medium += 1;
    else low += 1;

    if (item.riskScore >= 50 || item.threatType !== "No threat detected") {
      threats += 1;
    }

    const itemTime = new Date(item.timestamp).getTime();
    if (!Number.isNaN(itemTime) && itemTime >= oneMinuteAgo) {
      perMinute += 1;
    }
  });

  const activeArcs = state.historyArcs.length + state.activeArcs.length + state.requesterArcs.length;

  if (state.globalCounters?.connected) {
    animateCounterValue("oas", Number(state.globalCounters.global_malicious_ips || 0), liveCounterOAS);
    animateCounterValue("ods", Number(state.globalCounters.high_confidence_ips || 0), liveCounterODS);
    animateCounterValue("mav", Number(state.globalCounters.critical_ips || 0), liveCounterMAV);
    animateCounterValue("wav", Number(state.globalCounters.estimated_reports_per_min || 0), liveCounterWAV);
    animateCounterValue("ids", Number(state.globalCounters.countries_flagged || 0), liveCounterIDS);
    animateCounterValue("vul", activeArcs, liveCounterVUL);
    animateCounterValue("kas", uniqueTargets.size, liveCounterKAS);
  } else {
    animateCounterValue("oas", total, liveCounterOAS);
    animateCounterValue("ods", threats, liveCounterODS);
    animateCounterValue("mav", high, liveCounterMAV);
    animateCounterValue("wav", perMinute, liveCounterWAV);
    animateCounterValue("ids", medium + low, liveCounterIDS);
    animateCounterValue("vul", activeArcs, liveCounterVUL);
    animateCounterValue("kas", uniqueTargets.size, liveCounterKAS);
  }

  if (liveRefreshTime) {
    if (state.supabaseConnected === false) {
      liveRefreshTime.textContent = `Supabase disconnected | Live refresh ${nowStamp()}`;
    } else if (state.globalCounters?.connected) {
      liveRefreshTime.textContent = `Global source ${safeText(state.globalCounters.source).toUpperCase()} | Live refresh ${nowStamp()}`;
    } else {
      liveRefreshTime.textContent = `Live refresh ${nowStamp()}`;
    }
  }

  const threatRatio = total > 0 ? Math.round((threats / total) * 100) : 0;
  if (liveCounterRMW) {
    liveCounterRMW.textContent = `${threatRatio}%`;
  }

  if (!liveEventFeed) return;
  liveEventFeed.textContent = "";
  const targetCounts = targetSearchCountMap(items);

  const feedItems = items
    .slice()
    .sort(compareByTimestampDesc)
    .slice(0, 12);

  if (feedItems.length === 0) {
    const empty = document.createElement("p");
    empty.className = "event-text";
    empty.textContent = "No live events yet";
    liveEventFeed.appendChild(empty);
    return;
  }

  feedItems.forEach((item) => {
    const row = document.createElement("div");
    row.className = "event-row";

    const itemTime = new Date(item.timestamp).getTime();
    const isRecent = !Number.isNaN(itemTime) && (Date.now() - itemTime) <= 180000;
    const isActiveSearch = state.activeSearchTargets.has(normalizeTargetKey(item.target));
    if (isRecent || isActiveSearch) {
      row.classList.add("event-row-live");
    }

    const dot = document.createElement("span");
    dot.className = "event-dot";
    dot.style.color = levelDotColor(item.riskLevel);
    dot.style.background = levelDotColor(item.riskLevel);

    const text = document.createElement("p");
    text.className = "event-text";
    const threatLabel = item.threatType === "No threat detected" ? "clean" : item.threatType;
    const targetKey = safeText(item.target, "Unknown");
    const count = Number(targetCounts.get(targetKey) || 1);
    text.textContent = `${targetKey} (x${count}) | ${threatLabel} | ${toDisplayTime(item.timestamp)}`;

    const score = document.createElement("span");
    score.className = "event-score";
    score.textContent = `R${item.riskScore}`;

    row.appendChild(dot);
    row.appendChild(text);
    row.appendChild(score);
    liveEventFeed.appendChild(row);
  });
}

function updateArcsWithFade() {
  const now = Date.now();
  state.activeArcs = state.activeArcs
    .filter((arc) => now - arc.createdAt < ARC_LIFETIME_MS)
    .map((arc) => {
      const age = now - arc.createdAt;
      const alpha = Math.max(0.1, 1 - age / ARC_LIFETIME_MS);
      const hex = arc.baseColor.replace("#", "");
      const r = Number.parseInt(hex.substring(0, 2), 16);
      const g = Number.parseInt(hex.substring(2, 4), 16);
      const b = Number.parseInt(hex.substring(4, 6), 16);
      return { ...arc, color: `rgba(${r}, ${g}, ${b}, ${alpha.toFixed(2)})` };
    });
}

function setGlobeData() {
  if (!state.globe) return;

  updateArcsWithFade();
  const wave = pulseWave(190);

  const points = [...state.historyPoints, ...state.activePoints]
    .slice(-MAX_ACTIVE_POINTS)
    .map((point) => {
      if (!point.liveGlow) return point;
      const pulse = 1 + (wave * 0.16);
      return {
        ...point,
        radius: Number(point.radius || 0.5) * pulse,
        altitude: Number(point.altitude || 0.06),
        color: glowColorByRisk(point.riskScore, 0.72 + wave * 0.28),
      };
    });

  if (state.requesterPoint && isFiniteCoord(state.requesterPoint.lat, state.requesterPoint.lng)) {
    points.push(state.requesterPoint);
  }

  const arcs = [...state.historyArcs, ...state.requesterArcs, ...state.activeArcs]
    .map((arc) => {
      if (!arc.liveGlow) return arc;
      return {
        ...arc,
        color: glowColorByRisk(arc.riskScore, 0.58 + wave * 0.4),
        stroke: Math.max(0.46, Number(arc.stroke || 0.5) + (wave * 0.1)),
        altitude: Number(arc.altitude || 0.24),
      };
    });

  state.globe.pointsData(points);
  state.globe.arcsData(arcs);
  renderLiveDashboard();
}

function mapMetaText(scan) {
  const server = scan.server_location || {};
  const threat = scan.threat_origin || {};
  const serverInfo = isFiniteCoord(server.latitude, server.longitude)
    ? `${Number(server.latitude).toFixed(2)}, ${Number(server.longitude).toFixed(2)}`
    : "n/a";
  const threatInfo = isFiniteCoord(threat.latitude, threat.longitude)
    ? `${Number(threat.latitude).toFixed(2)}, ${Number(threat.longitude).toFixed(2)}`
    : "n/a";

  return `Server ${serverInfo} | Threat ${threatInfo} | Score ${clampScore(scan.risk_score)} | Visible sites ${state.renderedItems.length}`;
}

function toHistoryView(scan) {
  const riskScore = clampScore(scan.risk_score);
  const confidenceScore = clampScore(scan.confidence_score);
  const timestamp = safeText(scan.timestamp || scan.created_at, "Time unavailable");
  const rowId = safeText(scan.id, "");

  const serverLat = toFiniteOrNull(scan.server_location?.latitude ?? scan.server_lat ?? scan.geolocation?.latitude);
  const serverLng = toFiniteOrNull(scan.server_location?.longitude ?? scan.server_lng ?? scan.geolocation?.longitude);

  const rawThreatLat = toFiniteOrNull(scan.threat_origin?.latitude ?? scan.threat_lat);
  const rawThreatLng = toFiniteOrNull(scan.threat_origin?.longitude ?? scan.threat_lng);

  const threatLat = rawThreatLat ?? serverLat ?? 0;
  const threatLng = rawThreatLng ?? serverLng ?? 0;

  let confidencePriority = "LOW";
  if (confidenceScore >= 75) confidencePriority = "HIGH";
  else if (confidenceScore >= 45) confidencePriority = "MEDIUM";

  return {
    target: safeText(scan.source_input || scan.target),
    riskLevel: safeText(scan.risk_level, "LOW"),
    riskScore,
    confidenceScore,
    confidencePriority,
    country: safeText(scan.server_location?.country || scan.geolocation?.country),
    timestamp,
    serverLat: serverLat ?? 0,
    serverLng: serverLng ?? 0,
    threatLat,
    threatLng,
    threatCountry: safeText(scan.threat_origin?.country),
    threatType: Array.isArray(scan.threat_categories) && scan.threat_categories.length > 0
      ? scan.threat_categories.join(", ")
      : "No threat detected",
    eventId: [
      rowId,
      safeText(scan.target),
      timestamp,
      String(riskScore),
    ].join("|"),
  };
}

function compareByTimestampDesc(left, right) {
  const l = new Date(left.timestamp).getTime();
  const r = new Date(right.timestamp).getTime();
  return (Number.isNaN(r) ? 0 : r) - (Number.isNaN(l) ? 0 : l);
}

function mergeHistoryWindow(allItems) {
  return allItems.slice(0, MAX_HISTORY_ITEMS);
}

function computeHistorySignature(items) {
  return items
    .map((item) => `${item.eventId}:${item.riskScore}`)
    .join(";");
}

function buildHistoryPoints() {
  const points = [];

  state.renderedItems
    .forEach((item) => {
      if (isFiniteCoord(item.serverLat, item.serverLng)) {
        const isLiveTarget = isTargetHighlighted(item.target);
        points.push({
          lat: item.serverLat,
          lng: item.serverLng,
          altitude: 0.06,
          radius: 0.48,
          color: riskColorFromScore(item.riskScore, 0.72),
          label: `History server ${item.target}`,
          country: item.country,
          riskScore: item.riskScore,
          description: `Confidence ${item.confidenceScore} | ${item.threatType}`,
          kind: "history-server",
          liveGlow: isLiveTarget,
        });
      }

      if (isFiniteCoord(item.threatLat, item.threatLng)
        && (Math.abs(item.threatLat - item.serverLat) > 0.0001 || Math.abs(item.threatLng - item.serverLng) > 0.0001)) {
        const isLiveTarget = isTargetHighlighted(item.target);
        points.push({
          lat: item.threatLat,
          lng: item.threatLng,
          altitude: 0.07,
          radius: 0.42,
          color: riskColorFromScore(item.riskScore, 0.62),
          label: `History threat ${item.target}`,
          country: item.threatCountry || item.country,
          riskScore: item.riskScore,
          description: `Threat origin | ${item.threatType}`,
          kind: "history-threat",
          liveGlow: isLiveTarget,
        });
      }
    });

  if (state.clientLocation && isFiniteCoord(state.clientLocation.latitude, state.clientLocation.longitude)) {
    state.requesterPoint = {
      lat: Number(state.clientLocation.latitude),
      lng: Number(state.clientLocation.longitude),
      altitude: 0.1,
      radius: 0.62,
      color: "rgba(120, 225, 255, 0.95)",
      label: "Current PhantomGrid location",
      country: safeText(state.clientLocation.country, ""),
      riskScore: 0,
      description: "Requester location for trace arcs",
      kind: "requester",
    };
  } else {
    state.requesterPoint = null;
  }

  state.historyPoints = points;
}

function applyScanToUi(scan) {
  updateRiskCard(scan);
  updateAlert(scan);
  updateDetection(scan);
  updateConfidence(scan);
  renderCategories(scan.threat_categories || []);
  updateGeo(scan);
  renderSummary(scan.summary);

  const activePoints = buildActivePoints(scan);
  state.activePoints = [...state.activePoints, ...activePoints].slice(-MAX_ACTIVE_POINTS);
  addActiveThreatArc(scan);
  addActiveRequesterArc(scan);
  setGlobeData();

  if (isFiniteCoord(scan.server_location?.latitude, scan.server_location?.longitude)) {
    focusGlobe(scan.server_location.latitude, scan.server_location.longitude);
  }

  mapMeta.textContent = mapMetaText(scan);
  results.classList.remove("hidden");
}

function makeEventId(scan) {
  return [safeText(scan.target), safeText(scan.timestamp), safeText(scan.risk_score, "0")].join("|");
}

function consumeIncomingScan(scan) {
  const eventId = makeEventId(scan);
  if (state.seenEvents.has(eventId)) return;
  state.seenEvents.add(eventId);

  applyScanToUi(scan);

  const historyView = toHistoryView(scan);
  state.userSearchItems = [historyView, ...state.userSearchItems];
  mergeBaselineAndUserItems();
  state.historySignature = computeHistorySignature(state.baselineItems);
  buildHistoryPoints();
  buildHistoryArcs();
  buildRequesterArcs();
  renderLiveDashboard();
  setGlobeData();
}

async function loadHistory() {
  try {
    const response = await fetch(`/history?limit=${MAX_HISTORY_ITEMS}`);
    if (!response.ok) return;

    const payload = await response.json();
    if (!Array.isArray(payload)) return;

    const baseline = mergeHistoryWindow(payload.map(toHistoryView));
    const signature = computeHistorySignature(baseline);
    if (signature === state.historySignature) {
      return;
    }

    state.baselineItems = baseline;
    mergeBaselineAndUserItems();
    state.historySignature = signature;
    buildHistoryPoints();
    buildHistoryArcs();
    buildRequesterArcs();
    renderLiveDashboard();
    setGlobeData();
  } catch (_) {
    if (liveRefreshTime) {
      liveRefreshTime.textContent = "History unavailable";
    }
  }
}

async function checkSupabaseStatus() {
  try {
    const response = await fetch("/supabase-status");
    if (!response.ok) {
      state.supabaseConnected = false;
      return;
    }

    const data = await response.json();
    state.supabaseConnected = Boolean(data?.connected);
  } catch (_) {
    state.supabaseConnected = false;
  }
}

async function loadGlobalLiveThreats() {
  try {
    const response = await fetch("/global-live-threats");
    if (!response.ok) {
      state.globalCounters = { connected: false };
      return;
    }

    const payload = await response.json();
    state.globalCounters = payload;
    renderLiveDashboard();
  } catch (_) {
    state.globalCounters = { connected: false };
  }
}

async function fetchRequesterLocationFallback() {
  try {
    const response = await fetch("/client-location");
    if (!response.ok) return false;

    const data = await response.json();
    if (!data?.available || !isFiniteCoord(data.latitude, data.longitude)) {
      return false;
    }

    return applyClientLocation({
      latitude: Number(data.latitude),
      longitude: Number(data.longitude),
      country: safeText(data.country, ""),
      source: safeText(data.source, "server_ip"),
    });
  } catch (_) {
    return false;
  }
}

async function fetchClientIpLocationFromPublicApi() {
  const providers = [
    {
      url: "https://ipapi.co/json/",
      parse: (data) => ({
        latitude: Number(data?.latitude),
        longitude: Number(data?.longitude),
        country: safeText(data?.country_name || data?.country, ""),
        city: safeText(data?.city, ""),
        source: "browser_ipapi",
      }),
    },
    {
      url: "https://ipwho.is/",
      parse: (data) => ({
        latitude: Number(data?.latitude),
        longitude: Number(data?.longitude),
        country: safeText(data?.country, ""),
        city: safeText(data?.city, ""),
        source: "browser_ipwhois",
      }),
    },
  ];

  for (const provider of providers) {
    try {
      const response = await fetch(provider.url, { method: "GET" });
      if (!response.ok) continue;
      const payload = await response.json();
      const candidate = provider.parse(payload);
      if (applyClientLocation(candidate, { silentFocus: true })) {
        return true;
      }
    } catch (_) {
      continue;
    }
  }

  return false;
}

function stopGeoWatch() {
  if (state.geoWatchId !== null && navigator.geolocation) {
    navigator.geolocation.clearWatch(state.geoWatchId);
    state.geoWatchId = null;
  }
}

function startGeoWatch() {
  if (!navigator.geolocation || state.geoWatchId !== null) return;

  state.geoWatchId = navigator.geolocation.watchPosition(
    (position) => {
      applyClientLocation({
        latitude: Number(position.coords.latitude),
        longitude: Number(position.coords.longitude),
        country: state.clientLocation?.country || "",
        city: state.clientLocation?.city || "",
        source: "browser_gps_watch",
      }, { silentFocus: true });
    },
    () => {
      stopGeoWatch();
    },
    {
      enableHighAccuracy: true,
      timeout: 15000,
      maximumAge: 60000,
    },
  );
}

async function resolveLocationWithoutBrowserGps() {
  const browserIpSuccess = await fetchClientIpLocationFromPublicApi();
  if (browserIpSuccess) return true;

  const backendSuccess = await fetchRequesterLocationFallback();
  return backendSuccess;
}

async function tryBrowserGeolocation() {
  if (!navigator.geolocation) return false;

  return new Promise((resolve) => {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const applied = applyClientLocation({
          latitude: Number(position.coords.latitude),
          longitude: Number(position.coords.longitude),
          source: "browser_gps",
        });

        if (applied) {
          startGeoWatch();
          resolve(true);
          return;
        }

        resolve(false);
      },
      () => {
        resolve(false);
      },
      {
        enableHighAccuracy: true,
        timeout: 12000,
        maximumAge: 60000,
      },
    );
  });
}

async function initRequesterLocation() {
  stopGeoWatch();

  const browserSuccess = await tryBrowserGeolocation();
  if (browserSuccess) return;

  const fallbackSuccess = await resolveLocationWithoutBrowserGps();
  if (!fallbackSuccess) {
    state.clientLocation = null;
    buildHistoryPoints();
    buildHistoryArcs();
    buildRequesterArcs();
    setGlobeData();
  }
}

function updateRequesterLabel() {
  const el = document.getElementById("geoCity");
  if (!el) return;

  if (!state.clientLocation || !isFiniteCoord(state.clientLocation.latitude, state.clientLocation.longitude)) {
    return;
  }

  try {
    if (state.clientLocation.city && state.clientLocation.city !== "-") {
      el.textContent = `${state.clientLocation.city}`;
    }
  } catch (_) {
    return;
  }
}

function connectThreatWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${protocol}://${window.location.host}/ws/threat-stream`;

  try {
    state.ws = new WebSocket(wsUrl);
  } catch (_) {
    return;
  }

  state.ws.addEventListener("open", () => {
    state.ws.send("subscribe");
  });

  state.ws.addEventListener("message", (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload?.event !== "threat_scan" || !payload?.data) return;
      consumeIncomingScan(payload.data);
    } catch (_) {
      return;
    }
  });

  state.ws.addEventListener("close", () => {
    window.setTimeout(connectThreatWebSocket, 2000);
  });
}

const submitScan = debounce(async (target) => {
  setError("");
  setLoading(true);
  const targetKey = normalizeTargetKey(target);
  state.activeSearchTargets.add(targetKey);
  state.highlightedTarget = targetKey;
  state.highlightedUntil = Date.now() + 90000;
  buildHistoryPoints();
  buildHistoryArcs();
  buildRequesterArcs();
  setGlobeData();
  renderLiveDashboard();

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(normalizeApiError(payload?.detail));
    }

    const data = await response.json();
    consumeIncomingScan(data);
  } catch (error) {
    setError(error?.message || "Unexpected error");
  } finally {
    state.activeSearchTargets.delete(targetKey);
    state.highlightedUntil = Date.now() + 90000;
    buildHistoryPoints();
    buildHistoryArcs();
    buildRequesterArcs();
    setLoading(false);
    setGlobeData();
    renderLiveDashboard();
  }
}, 300);

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const target = safeText(input.value, "").trim();
  if (!target) {
    setError("Please enter a target");
    return;
  }
  submitScan(target);
});

initializeGlobe();
initRequesterLocation().then(() => {
  updateRequesterLabel();
});
connectThreatWebSocket();
window.setInterval(setGlobeData, 220);
window.setInterval(loadHistory, HISTORY_REFRESH_MS);
window.setInterval(checkSupabaseStatus, 12000);
window.setInterval(loadGlobalLiveThreats, 15000);
checkSupabaseStatus();
loadGlobalLiveThreats();
loadHistory();
