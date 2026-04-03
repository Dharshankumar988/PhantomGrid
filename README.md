# PhantomGrid 🛡️⚡

A futuristic full-stack cybersecurity dashboard built with **FastAPI** that analyzes IPs, domains, and URLs using multi-source threat intelligence.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-API-green)
![Vercel](https://img.shields.io/badge/Deploy-Vercel-black)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

- 🔎 Analyze **IP address**, **domain**, or **full URL**
- 🧠 Aggregate threat intelligence from:
  - AbuseIPDB
  - VirusTotal
  - AlienVault OTX
  - IP Geolocation API
- 📊 Unified scoring engine:
  - Risk score (0-100)
  - Confidence score (0-100)
  - Risk levels: LOW / MEDIUM / HIGH
- 🏷️ Threat category extraction (Spam, Botnet, Malware, Phishing)
- 🗺️ Interactive threat map with fullscreen mode
- 💾 Scan history stored in Supabase
- ⚡ Async calls + in-memory caching

---

## 🧱 Tech Stack

- **Backend:** FastAPI, Uvicorn
- **Frontend:** HTML, Tailwind CSS, JavaScript, Leaflet
- **Database:** Supabase (PostgreSQL)
- **Libraries:** httpx, python-dotenv, supabase-py, pydantic

---

## 📁 Project Structure

```text
threat-dashboard/
├── main.py
├── config.py
├── .env
├── .env.example
├── requirements.txt
├── vercel.json
├── README.md
├── /api
│   └── routes.py
├── /services
│   ├── abuseipdb.py
│   ├── virustotal.py
│   ├── otx.py
│   └── geo.py
├── /utils
│   ├── scorer.py
│   ├── categorizer.py
│   ├── confidence.py
│   └── summary.py
├── /models
│   └── schemas.py
├── /templates
│   └── index.html
├── /static
│   ├── script.js
│   └── style.css
└── /supabase
    └── scan_history.sql
```

---

## 🚀 Local Setup

### 1) Clone repo

```bash
git clone https://github.com/Dharshankumar988/PhantomGrid.git
cd PhantomGrid/threat-dashboard
```

### 2) Create virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3) Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4) Configure environment variables

Copy `.env.example` to `.env` and fill real values:

```dotenv
ABUSE_API_KEY=your_abuseipdb_api_key
VT_API_KEY=your_virustotal_api_key
OTX_API_KEY=your_otx_api_key
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_KEY=your_supabase_anon_key
```

### 5) Create Supabase table

Run SQL from `supabase/scan_history.sql` in Supabase SQL Editor.

### 6) Run app

```powershell
python -m uvicorn main:app --reload
```

Open: `http://127.0.0.1:8000`

---

## ☁️ Deploy on Vercel

This project is already configured with `vercel.json`.

### 1) Install Vercel CLI

```bash
npm i -g vercel
```

### 2) Login

```bash
vercel login
```

### 3) Deploy from project folder

```bash
cd threat-dashboard
vercel
```

### 4) Add environment variables in Vercel

In Vercel Dashboard -> Project -> Settings -> Environment Variables, add:

- `ABUSE_API_KEY`
- `VT_API_KEY`
- `OTX_API_KEY`
- `SUPABASE_URL`
- `SUPABASE_KEY`

### 5) Production deploy

```bash
vercel --prod
```

---

## 🔐 Which API Keys To Put In Vercel?

Put these exact keys (names must match):

1. `ABUSE_API_KEY` -> from AbuseIPDB account API page
2. `VT_API_KEY` -> from VirusTotal profile/API key page
3. `OTX_API_KEY` -> from AlienVault OTX account settings
4. `SUPABASE_URL` -> from Supabase project API settings
5. `SUPABASE_KEY` -> Supabase **anon public key** (not service_role key)

---

## 🧪 API Usage

### Analyze endpoint

`POST /analyze`

Request:

```json
{
  "target": "https://example.com/login"
}
```

Response format:

```json
{
  "target": "example.com",
  "risk_score": 0,
  "confidence_score": 0,
  "risk_level": "LOW | MEDIUM | HIGH",
  "threat_categories": [],
  "detection": {
    "malicious": 0,
    "total_engines": 0
  },
  "geolocation": {
    "country": "",
    "city": "",
    "isp": "",
    "latitude": 0,
    "longitude": 0
  },
  "summary": ""
}
```

---

## 🛠️ Troubleshooting

- If map does not render correctly after expand/collapse, run another scan or resize window.
- If history does not save, verify Supabase table exists and env vars are set correctly.
- If local install fails, ensure you are in activated virtual environment.

---

## 📜 License

MIT License

---

## 🙌 Credits

Built by Dharshan with a SOC-style dashboard vision.
