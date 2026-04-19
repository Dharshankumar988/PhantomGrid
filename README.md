# PhantomGrid 🛡️⚡

PhantomGrid is a SOC-style threat intelligence dashboard built with FastAPI. It analyzes IPs/domains/URLs, aggregates data from multiple threat feeds, and visualizes threats on an interactive 3D globe with live arcs and streaming updates.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-API-green)
![Vercel](https://img.shields.io/badge/Deploy-Vercel-black)

## ✨ Features

- Analyze IP, domain, or URL targets from a single input.
- Multi-source enrichment using AbuseIPDB, VirusTotal, OTX, and IP geolocation.
- Unified scoring model:
  - Risk score (0-100)
  - Confidence score (0-100)
  - Risk level (LOW, MEDIUM, HIGH)
- Threat category extraction (for example Malware, Phishing, Botnet, Spam).
- 3D globe visualization with:
  - Threat origin and server points
  - Arcs flowing toward current user location
  - Duplicate scan arc separation for clearer visibility
  - Current target pulse/glow highlights (risk-colored)
- Live websocket stream for near-real-time scan updates.
- Supabase-backed scan history with polling refresh.
- Location-aware sink using browser geolocation with layered fallback.

## 🧱 Tech Stack

- Backend: FastAPI, Uvicorn, httpx, pydantic
- Frontend: HTML, Tailwind CSS, JavaScript, Globe.gl, Three.js
- Database: Supabase (PostgreSQL)
- Config: python-dotenv, supabase-py

## 📁 Project Structure

```text
threat-dashboard/
├── main.py
├── config.py
├── requirements.txt
├── README.md
├── vercel.json
├── api/
│   ├── routes.py
│   └── ws.py
├── models/
│   └── schemas.py
├── services/
│   ├── abuseipdb.py
│   ├── geo.py
│   ├── otx.py
│   └── virustotal.py
├── static/
│   ├── script.js
│   └── style.css
├── templates/
│   └── index.html
├── supabase/
│   └── scan_history.sql
└── utils/
    ├── categorizer.py
    ├── confidence.py
    ├── scorer.py
    └── summary.py
```

## 🚀 Local Setup

1. Clone repository

```bash
git clone https://github.com/Dharshankumar988/PhantomGrid.git
cd PhantomGrid/threat-dashboard
```

2. Create and activate virtual environment

```powershell
python -m venv .venv
\.venv\Scripts\Activate.ps1
```

3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

4. Configure environment variables in `.env`

```dotenv
ABUSE_API_KEY=your_abuseipdb_api_key
VT_API_KEY=your_virustotal_api_key
OTX_API_KEY=your_otx_api_key
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_KEY=your_supabase_anon_key
```

5. Run Supabase schema setup

- Execute `supabase/scan_history.sql` in Supabase SQL Editor.

6. Start server

```powershell
python -m uvicorn main:app --reload
```

Open `http://127.0.0.1:8000`.

## 🧪 API Endpoints

- `POST /analyze`
  - Input: `{ "target": "https://example.com" }`
  - Output includes risk metrics, categories, detection stats, location data, and summary.
- `GET /history?limit=20`
  - Returns latest scan history rows.
- `GET /client-location`
  - Returns server-derived client geolocation when available.
- `GET /global-live-threats`
  - Returns global aggregate metrics from AbuseIPDB blacklist.
- `GET /supabase-status`
  - Returns Supabase connectivity status.
- `WS /ws/threat-stream`
  - Pushes live scan events.

## ☁️ Deploy (Vercel)

1. Install CLI

```bash
npm i -g vercel
```

2. Deploy from `threat-dashboard`

```bash
vercel
vercel --prod
```

3. Configure environment variables in Vercel project settings:

- `ABUSE_API_KEY`
- `VT_API_KEY`
- `OTX_API_KEY`
- `SUPABASE_URL`
- `SUPABASE_KEY`

## 🛠️ Troubleshooting

- If history is empty, check `/supabase-status` and confirm `scan_history.sql` was applied.
- If current location seems off, allow browser geolocation and refresh.
- If globe rendering looks stale at unusual zoom levels, reload tab (resize handlers are active).
- If repeated searches do not appear, verify API logs and Supabase insert permissions.

## 🔐 Security Notes

- Keep API keys only in backend environment variables.
- Do not expose service role keys to frontend.
- Rotate keys immediately if they are accidentally shared.

## 📜 License

MIT

## 🙌 Credits

Made by Dharshan Kumar B.
