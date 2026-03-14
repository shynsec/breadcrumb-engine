# 🔍 The Breadcrumb Engine

> **IP geolocation and threat intelligence, visualised.**  
> Paste a list of IPs, get an interactive dark-mode map with VirusTotal risk scores — exportable as CSV.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.55-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Powered-394EFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📸 Screenshots

> **Map View** — Each IP is plotted on a dark CartoDB basemap. Markers are colour-coded by VirusTotal risk score.

```
🟢 Green  → Risk score 0–4%    (Clean — few or no vendors flagged it)
🟠 Orange → Risk score 5–14%   (Suspicious — worth investigating)
🔴 Red    → Risk score 15%+    (Malicious — flagged by multiple vendors)
```

> **Intelligence Table** — Full enriched data underneath the map, downloadable as CSV.

---

## ✨ Features

- **Interactive dark map** — CartoDB dark_matter basemap powered by Folium
- **VirusTotal integration** — Aggregates 90+ security vendor votes per IP
- **Geolocation via ipinfo.io** — HTTPS-encrypted, no MITM risk
- **Risk colour coding** — Instant visual triage at a glance
- **CSV export** — One-click download of the full intelligence table
- **Input validation** — Rejects malformed IPs before they hit any API
- **Deduplication** — Duplicate IPs are resolved once, not multiple times
- **Rate-limit safe** — Threaded fetching with conservative delays

---

## 🚀 Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/YOUR-USERNAME/IP_Mapper.git
cd IP_Mapper
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set your API key

The app reads your VirusTotal key from an environment variable. **Never hardcode it.**

```bash
export VT_API_KEY="your_key_here"
```

To make this permanent on Mac, add it to your `~/.zshrc`:

```bash
echo 'export VT_API_KEY="your_key_here"' >> ~/.zshrc
source ~/.zshrc
```

### 5. Run the app

```bash
streamlit run app.py
```

The app will open at `http://localhost:8501`.

---

## 🔑 API Keys

| Service | Required | Free Tier | Get Key |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com) | Yes | 500 requests/day | [Sign up](https://www.virustotal.com/gui/join-us) |
| [ipinfo.io](https://ipinfo.io) | No (anonymous) | 50,000 req/month | [Sign up](https://ipinfo.io/signup) for higher limits |

---

## 🏗️ Project Structure

```
IP_Mapper/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── .gitignore          # Keeps secrets and cache out of Git
└── README.md           # This file
```

---

## ⚙️ Configuration

All configuration lives at the top of `app.py`:

| Variable | Location | Description |
|---|---|---|
| `VT_API_KEY` | Environment variable | VirusTotal API key |
| `MAX_IPS` | `app.py` | Maximum IPs per run (default: 500) |
| `RATE_LIMIT_DELAY` | `app.py` | Seconds between API calls (default: 1.4s) |
| `MAX_WORKERS` | `app.py` | Parallel fetch threads (default: 2) |

---

## 🛡️ Security Notes

- **API key** is loaded from `os.environ` — never committed to source control
- **Geolocation** uses `https://ipinfo.io` (HTTPS only — prevents MITM attacks)
- **Input validation** strips and validates every IP with a regex + octet range check
- **Status fields** are stripped from all outputs to avoid tooling fingerprinting in exports
- **Input cap** of 500 IPs prevents API quota exhaustion

---

## 📦 Dependencies

Key packages (see `requirements.txt` for full pinned versions):

| Package | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `folium` | Interactive map rendering |
| `streamlit-folium` | Folium ↔ Streamlit bridge |
| `pandas` | Data handling and CSV export |
| `requests` | HTTP calls to geo and threat intel APIs |

---

## 🗺️ Roadmap

- [ ] IPv6 support
- [ ] CIDR range expansion (e.g. `192.168.1.0/24`)
- [ ] Bulk upload via CSV file input
- [ ] AbuseIPDB dual-source enrichment
- [ ] Saved investigation history

---

## 📄 License

MIT — free to use, modify, and distribute.

---

<p align="center">Built for threat hunters, blue teamers, and the curious.</p>
