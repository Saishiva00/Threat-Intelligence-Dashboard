# 🛡️ Threat Intelligence Dashboard

A real-world cybersecurity project that aggregates live threat intelligence data from multiple public feeds and displays it in an interactive web dashboard.

Built with Python + Streamlit. Resume-ready project for cybersecurity roles.

---

## 🎯 Features

| Feature | Description |
|---|---|
| **Live IOC Feed** | Fetches malicious IPs, domains, and hashes from AbuseIPDB, OTX, and URLhaus |
| **IP Reputation Checker** | Enter any IP to get a full threat report |
| **CVE Feed** | Latest vulnerabilities from NVD/NIST |
| **Visual Analytics** | Interactive charts: bar, timeline, world map, pie |
| **Export** | Download IOCs as CSV |
| **Search & Filter** | Filter IOCs by type, source, and keyword |

---

## 🗂️ Project Structure

```
threat-intel-dashboard/
├── app.py              ← Main Streamlit app (UI + navigation)
├── fetcher.py          ← API integrations (AbuseIPDB, OTX, URLhaus, NVD)
├── database.py         ← SQLite database functions
├── visualizations.py   ← Plotly chart functions
├── requirements.txt    ← Python dependencies
└── README.md
```

---

## ⚙️ Setup Instructions

### Step 1 — Clone the project
```bash
git clone https://github.com/yourusername/threat-intel-dashboard.git
cd threat-intel-dashboard
```

### Step 2 — Create a virtual environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Get free API keys

| API | Where to get | Link |
|---|---|---|
| AbuseIPDB | Sign up free → My Account → API | https://www.abuseipdb.com |
| AlienVault OTX | Sign up free → API Key in profile | https://otx.alienvault.com |
| URLhaus | No key needed | — |
| NVD CVE | No key needed | — |

### Step 5 — Set your API keys

**Option A — Environment variables (recommended):**
```bash
# Windows
set ABUSEIPDB_API_KEY=your_key_here
set OTX_API_KEY=your_key_here

# macOS/Linux
export ABUSEIPDB_API_KEY=your_key_here
export OTX_API_KEY=your_key_here
```

**Option B — Edit fetcher.py directly (for testing only):**
```python
ABUSEIPDB_API_KEY = "paste_your_key_here"
OTX_API_KEY       = "paste_your_key_here"
```

### Step 6 — Run the app
```bash
streamlit run app.py
```

Open your browser at: **http://localhost:8501**

---

## 🚀 Usage

1. Click **"🔄 Fetch All Feeds"** in the sidebar to load threat data
2. Click **"🌐 URLhaus"** for immediate data (no API key needed)
3. Browse the **IOC Browser** to search for specific IPs/domains
4. Use the **IP Reputation Checker** to investigate suspicious IPs
5. Check the **CVE Feed** for latest vulnerabilities
6. View **Visual Analytics** for charts and world map

### Test IPs
```
185.220.101.45   ← Known malicious (Tor exit node)
45.83.193.218    ← Known C2 server
8.8.8.8          ← Google DNS (should be clean)
1.1.1.1          ← Cloudflare DNS (should be clean)
```

---

## 🏗️ Architecture

```
User (Browser)
     │
     ▼
Streamlit (app.py)          ← Web UI layer
     │
     ├── fetcher.py          ← Calls external APIs
     │       ├── AbuseIPDB API
     │       ├── AlienVault OTX API
     │       ├── URLhaus API
     │       └── NVD CVE API
     │
     ├── database.py         ← SQLite storage
     │       └── threat_intel.db
     │
     └── visualizations.py  ← Plotly charts
```

**Data Flow:**
1. User clicks "Fetch" → `fetcher.py` calls APIs
2. API JSON responses are parsed and cleaned
3. IOC data is stored in `threat_intel.db` (SQLite)
4. Dashboard reads from DB and renders charts via Plotly
5. User can search, filter, export

---

## ☁️ Free Deployment (Streamlit Cloud)

1. Push your project to GitHub
2. Go to **[share.streamlit.io](https://share.streamlit.io)**
3. Connect your GitHub account
4. Select your repo and set `app.py` as the main file
5. Under **Advanced Settings → Secrets**, add:
   ```toml
   ABUSEIPDB_API_KEY = "your_key"
   OTX_API_KEY = "your_key"
   ```
6. Click **Deploy** — your app will be live in 2 minutes!

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core language |
| Streamlit | Web framework / UI |
| SQLite | Local database |
| Requests | HTTP API calls |
| Pandas | Data processing |
| Plotly | Interactive charts |

---

## 📄 Resume Description

> **Threat Intelligence Dashboard** | Python, Streamlit, REST APIs, SQLite, Plotly
>
> Built a real-time threat intelligence dashboard integrating AbuseIPDB, AlienVault OTX, and URLhaus APIs to aggregate and visualize Indicators of Compromise (IOCs) including malicious IPs, domains, and file hashes. Implemented IP reputation lookup engine, CVE vulnerability feed from NVD/NIST, geolocation mapping of threat origins with Plotly choropleth maps, and automated data export in CSV format. Deployed on Streamlit Cloud.

---

## 👤 Author

Your Name | ECE Graduate | Aspiring Cybersecurity Analyst

LinkedIn: linkedin.com/in/yourprofile  
GitHub: github.com/yourusername

---

## 📜 License

This project is open-source for educational purposes.
Data sources: AbuseIPDB, AlienVault OTX, URLhaus (abuse.ch), NIST NVD
