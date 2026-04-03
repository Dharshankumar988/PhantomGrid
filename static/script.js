const form = document.getElementById("scanForm");
const input = document.getElementById("targetInput");
const loading = document.getElementById("loading");
const errorText = document.getElementById("errorText");
const results = document.getElementById("results");
const historyList = document.getElementById("historyList");
const analyzeBtn = document.getElementById("analyzeBtn");
const alertBanner = document.getElementById("alertBanner");
const analyzedTarget = document.getElementById("analyzedTarget");
const mapMeta = document.getElementById("mapMeta");
const toggleMapBtn = document.getElementById("toggleMapBtn");
const mapShell = document.getElementById("mapShell");
const footerCreditCanvas = document.getElementById("footerCreditCanvas");

let map;
let marker;
let threatCircle;

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
  analyzeBtn.classList.toggle("opacity-60", isLoading);
  analyzeBtn.classList.toggle("cursor-not-allowed", isLoading);
}

function setError(message = "") {
  if (!message) {
    errorText.classList.add("hidden");
    errorText.textContent = "";
    return;
  }
  errorText.textContent = message;
  errorText.classList.remove("hidden");
}

function normalizeApiError(detail) {
  if (!detail) return "Failed to analyze target";

  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item?.msg) return item.msg;
        return null;
      })
      .filter(Boolean);

    if (messages.length > 0) {
      return messages.join(" | ");
    }
  }

  if (typeof detail === "object" && detail.msg) {
    return detail.msg;
  }

  return "Failed to analyze target";
}

function getRiskRingClass(level) {
  if (level === "HIGH") return "risk-high";
  if (level === "MEDIUM") return "risk-medium";
  return "risk-low";
}

function updateRiskCard(data) {
  const ring = document.getElementById("riskRing");
  const score = document.getElementById("riskScore");
  const level = document.getElementById("riskLevel");

  ring.classList.remove("risk-low", "risk-medium", "risk-high");
  ring.classList.add(getRiskRingClass(data.risk_level));
  ring.style.setProperty("--risk-pct", String(Math.max(0, Math.min(100, data.risk_score ?? 0))));

  score.textContent = data.risk_score;
  level.textContent = data.risk_level;
  analyzedTarget.textContent = data.target || "Unknown";
}

function updateAlert(data) {
  const isCritical = Number(data.risk_score || 0) > 80;
  alertBanner.classList.toggle("hidden", !isCritical);
}

function updateDetection(data) {
  const text = document.getElementById("detectionText");
  const bar = document.getElementById("detectionBar");

  const malicious = data.detection?.malicious ?? 0;
  const total = data.detection?.total_engines ?? 0;
  const ratio = total > 0 ? (malicious / total) * 100 : 0;

  text.textContent = `${malicious} / ${total} engines flagged`;
  bar.style.width = `${Math.min(100, ratio)}%`;
}

function updateConfidence(data) {
  const value = document.getElementById("confidenceValue");
  const bar = document.getElementById("confidenceBar");

  value.textContent = `${data.confidence_score}%`;
  bar.style.width = `${Math.min(100, data.confidence_score)}%`;
}

function renderCategories(categories) {
  const tags = document.getElementById("categoryTags");
  tags.innerHTML = "";

  if (!categories || categories.length === 0) {
    const span = document.createElement("span");
    span.className = "text-slate-300 text-sm";
    span.textContent = "No significant categories extracted";
    tags.appendChild(span);
    return;
  }

  categories.forEach((category) => {
    const badge = document.createElement("span");
    badge.className = `category-badge ${categoryClassMap[category] || "badge-spam"}`;
    badge.textContent = category;
    tags.appendChild(badge);
  });
}

function updateGeo(data) {
  document.getElementById("geoCountry").textContent = data.geolocation?.country || "-";
  document.getElementById("geoCity").textContent = data.geolocation?.city || "-";
  document.getElementById("geoISP").textContent = data.geolocation?.isp || "-";
}

function getRiskMapStyle(riskLevel) {
  if (riskLevel === "HIGH") {
    return { className: "high", color: "#ff5c8a", radius: 240000 };
  }
  if (riskLevel === "MEDIUM") {
    return { className: "medium", color: "#f8d34a", radius: 140000 };
  }
  return { className: "low", color: "#44ffa1", radius: 80000 };
}

function showMap(lat, lon, target, riskLevel, riskScore) {
  if (!lat || !lon) {
    mapMeta.textContent = "No geolocation coordinates available for this target.";
    mapMeta.classList.add("map-meta-warning");
    return;
  }

  mapMeta.classList.remove("map-meta-warning");
  mapMeta.textContent = `Lat ${Number(lat).toFixed(4)} | Lon ${Number(lon).toFixed(4)} | Score ${riskScore}`;

  const mapStyle = getRiskMapStyle(riskLevel);

  if (!map) {
    map = L.map("map", { zoomControl: true }).setView([lat, lon], 5);
    L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png", {
      attribution: "&copy; OpenStreetMap &copy; CARTO",
    }).addTo(map);
  } else {
    map.setView([lat, lon], 5);
  }

  if (marker) {
    marker.remove();
  }

  if (threatCircle) {
    threatCircle.remove();
  }

  const markerIcon = L.divIcon({
    className: "",
    html: `<div class="threat-marker ${mapStyle.className}"></div>`,
    iconSize: [16, 16],
    iconAnchor: [8, 8],
  });

  marker = L.marker([lat, lon], { icon: markerIcon }).addTo(map);
  marker.bindPopup(`Target: ${target}<br/>Risk: ${riskLevel}`).openPopup();

  threatCircle = L.circle([lat, lon], {
    radius: mapStyle.radius,
    color: mapStyle.color,
    fillColor: mapStyle.color,
    fillOpacity: 0.14,
    weight: 1.5,
  }).addTo(map);

  setTimeout(() => map.invalidateSize(), 120);
}

function updateMapExpandButton() {
  const isFullscreen = document.fullscreenElement === mapShell;
  toggleMapBtn.textContent = isFullscreen ? "Exit Fullscreen" : "Expand Map";
}

async function toggleMapFullscreen() {
  try {
    if (document.fullscreenElement === mapShell) {
      await document.exitFullscreen();
    } else {
      await mapShell.requestFullscreen();
    }
    setTimeout(() => {
      if (map) map.invalidateSize();
    }, 150);
  } catch (_) {
    return;
  }
}

function renderSummary(summary) {
  document.getElementById("summaryText").textContent = summary || "No summary available.";
}

function renderResult(data) {
  updateRiskCard(data);
  updateAlert(data);
  updateDetection(data);
  updateConfidence(data);
  renderCategories(data.threat_categories || []);
  updateGeo(data);
  renderSummary(data.summary);

  const { latitude, longitude } = data.geolocation || {};
  showMap(latitude, longitude, data.target, data.risk_level, data.risk_score);

  results.classList.remove("hidden");
  results.classList.add("fade-in");
}

function formatHistoryItem(item) {
  const usedInput = item.source_input && String(item.source_input).trim().length > 0
    ? item.source_input
    : item.target;
  return {
    target: usedInput,
    riskLevel: String(item.risk_level || "UNKNOWN").toUpperCase(),
    riskScore: Number(item.risk_score || 0),
    malicious: Number(item.detection?.malicious || 0),
    totalEngines: Number(item.detection?.total_engines || 0),
    confidence: Number(item.confidence_score || 0),
    createdAt: item.created_at || item.timestamp || null,
  };
}

function getRiskChipClass(riskLevel) {
  if (riskLevel === "HIGH") return "risk-chip-high";
  if (riskLevel === "MEDIUM") return "risk-chip-medium";
  return "risk-chip-low";
}

function toDisplayTime(isoValue) {
  if (!isoValue) return "Time unavailable";
  const parsed = new Date(isoValue);
  if (Number.isNaN(parsed.getTime())) return "Time unavailable";

  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function buildHistoryRow(item) {
  const data = formatHistoryItem(item);
  const ratio = data.totalEngines > 0 ? ((data.malicious / data.totalEngines) * 100).toFixed(0) : "0";

  const row = document.createElement("div");
  row.className = "history-row";

  const top = document.createElement("div");
  top.className = "history-top";

  const target = document.createElement("p");
  target.className = "history-target";
  target.textContent = data.target;
  target.title = data.target;

  const risk = document.createElement("span");
  risk.className = `history-risk ${getRiskChipClass(data.riskLevel)}`;
  risk.textContent = `${data.riskLevel} ${data.riskScore}`;

  top.appendChild(target);
  top.appendChild(risk);

  const meta = document.createElement("div");
  meta.className = "history-meta";

  const detectionChip = document.createElement("span");
  detectionChip.className = "history-chip";
  detectionChip.textContent = `Detection ${data.malicious}/${data.totalEngines} (${ratio}%)`;

  const confidenceChip = document.createElement("span");
  confidenceChip.className = "history-chip";
  confidenceChip.textContent = `Confidence ${data.confidence}%`;

  const timeChip = document.createElement("span");
  timeChip.className = "history-chip history-time";
  timeChip.textContent = toDisplayTime(data.createdAt);

  meta.appendChild(detectionChip);
  meta.appendChild(confidenceChip);
  meta.appendChild(timeChip);

  row.appendChild(top);
  row.appendChild(meta);
  return row;
}

function decodeObfuscatedCredit() {
  const payload = [40, 200, 199, 242, 228, 216, 210, 48, 197, 194, 18, 86, 189, 34, 249, 4, 249, 240, 45, 29, 15, 180, 224, 244, 239, 247, 248, 245, 238, 43, 146, 193, 213, 211, 209, 209, 137, 209, 233, 219, 131, 164, 175, 174, 189, 132, 188, 129, 190, 177, 229];
  return payload
    .map((value, index) => {
      const decoded = (value ^ (73 + index * 3)) - 17 - ((index % 5) * 11);
      return String.fromCharCode(decoded);
    })
    .join("");
}

function renderObfuscatedCredit() {
  if (!footerCreditCanvas) return;

  const ctx = footerCreditCanvas.getContext("2d");
  if (!ctx) return;

  const message = decodeObfuscatedCredit();
  const ratio = Math.max(1, Math.floor(window.devicePixelRatio || 1));
  const width = footerCreditCanvas.clientWidth || 960;
  const height = 24;

  footerCreditCanvas.width = width * ratio;
  footerCreditCanvas.height = height * ratio;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

  ctx.clearRect(0, 0, width, height);
  ctx.clearRect(0, 0, width, height);
  ctx.font = '500 10px "Inter", sans-serif';
  ctx.textBaseline = "middle";
  ctx.textAlign = "center";

  const x = width / 2;
  const y = height / 2;
  ctx.fillStyle = "rgba(148, 163, 184, 0.12)";
  ctx.fillText(message, x + 1, y + 1);
  ctx.fillStyle = "rgba(148, 163, 184, 0.52)";
  ctx.fillText(message, x, y);
}

async function loadHistory() {
  try {
    const response = await fetch("/history?limit=10");
    if (!response.ok) return;
    const data = await response.json();

    historyList.innerHTML = "";
    if (!Array.isArray(data) || data.length === 0) {
      historyList.innerHTML = '<p class="text-slate-400">No scans stored yet.</p>';
      return;
    }

    data.forEach((item) => {
      historyList.appendChild(buildHistoryRow(item));
    });
  } catch (err) {
    historyList.innerHTML = '<p class="text-slate-400">History unavailable.</p>';
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const target = input.value.trim();
  if (!target) {
    setError("Please enter an IP or domain");
    return;
  }

  setError("");
  setLoading(true);

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ target }),
    });

    if (!response.ok) {
      const errorPayload = await response.json().catch(() => ({}));
      const detailMessage = normalizeApiError(errorPayload?.detail);
      throw new Error(detailMessage);
    }

    const data = await response.json();
    renderResult(data);
    await loadHistory();
  } catch (error) {
    setError(error.message || "Unexpected error");
  } finally {
    setLoading(false);
  }
});

loadHistory();
renderObfuscatedCredit();
window.addEventListener("resize", renderObfuscatedCredit);

toggleMapBtn.addEventListener("click", toggleMapFullscreen);
document.addEventListener("fullscreenchange", () => {
  updateMapExpandButton();
  if (map) {
    setTimeout(() => map.invalidateSize(), 120);
  }
});
