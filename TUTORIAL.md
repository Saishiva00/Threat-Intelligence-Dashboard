# 🛡️ Complete Threat Intelligence Dashboard — Full Tutorial Guide
### For Freshers | ECE Graduates | Cybersecurity Beginners

---

## 📚 TABLE OF CONTENTS

1. Architecture Explanation
2. Folder Structure
3. Environment Setup
4. Step-by-Step Development Walkthrough
5. How Each File Works
6. Running the Project
7. Testing Guide
8. Deployment Guide (Free)
9. Resume Tips

---

---

# PART 1 — ARCHITECTURE EXPLANATION

## How All the Pieces Fit Together

Think of this project like a news aggregator — but instead of news, it collects and displays threat intelligence.

```
┌─────────────────────────────────────────────────────────┐
│                    USER'S BROWSER                       │
│              http://localhost:8501                      │
└───────────────────────┬─────────────────────────────────┘
                        │  HTTP
                        ▼
┌─────────────────────────────────────────────────────────┐
│                    app.py                               │
│              (Streamlit Web App)                        │
│  - Navigation sidebar                                   │
│  - Dashboard page                                       │
│  - IOC Browser page                                     │
│  - IP Reputation Checker                                │
│  - CVE Feed page                                        │
│  - Visual Analytics page                               │
└──────┬──────────────────────┬────────────────────────────┘
       │                      │
       ▼                      ▼
┌──────────────┐    ┌──────────────────────┐
│  fetcher.py  │    │   visualizations.py  │
│              │    │                      │
│ Calls APIs:  │    │  Creates charts:     │
│ - AbuseIPDB  │    │  - Bar chart         │
│ - OTX        │    │  - Timeline          │
│ - URLhaus    │    │  - World Map         │
│ - NVD CVE    │    │  - Pie chart         │
└──────┬───────┘    └──────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│             database.py                  │
│           (SQLite Functions)             │
│                                          │
│  - initialize_database()                 │
│  - insert_ioc()                          │
│  - get_all_iocs()                        │
│  - search_ioc()                          │
│  - get_ioc_stats()                       │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│          threat_intel.db                 │
│          (SQLite file on disk)           │
│                                          │
│  Tables:                                 │
│  - iocs      (malicious IPs, domains)    │
│  - cve_feed  (vulnerability records)     │
└──────────────────────────────────────────┘
```

## How Streamlit Works

Streamlit is special — you don't need to know HTML, CSS, or JavaScript to build a web app.

You just write Python, and Streamlit converts it to a web page automatically.

**Key rule:** Every time a user clicks a button or types in a text box, Streamlit re-runs your entire `app.py` script from top to bottom.

**st.session_state** is used to remember values between reruns (like the result of an IP reputation check).

## How SQLite Works

SQLite is a database stored in a single file on your computer (`threat_intel.db`).

No need to install a separate database server (unlike MySQL or PostgreSQL). It's perfect for small projects.

You interact with it using standard SQL commands through Python's built-in `sqlite3` library.

## How API Calls Work

APIs (Application Programming Interfaces) are URLs that return data in JSON format when you send an HTTP request to them.

Example flow for AbuseIPDB:

```
Your Python code
      │
      │  GET https://api.abuseipdb.com/api/v2/blacklist
      │  Headers: { "Key": "your_api_key" }
      ▼
AbuseIPDB Server
      │
      │  Response: { "data": [ {"ipAddress": "1.2.3.4", ...}, ... ] }
      ▼
Your Python code parses the JSON
      │
      ▼
Saves to SQLite database
```

---

---

# PART 2 — FOLDER STRUCTURE

```
threat-intel-dashboard/
│
├── app.py                ← MAIN FILE — Run this with Streamlit
│                           Contains all UI pages and navigation
│
├── fetcher.py            ← API INTEGRATION
│                           Functions to call each threat feed API
│                           Parses JSON and saves to database
│
├── database.py           ← DATABASE LAYER
│                           All SQLite read/write functions
│                           Never write raw SQL anywhere except here
│
├── visualizations.py     ← CHARTS
│                           All Plotly chart functions
│                           Returns figure objects used in app.py
│
├── requirements.txt      ← DEPENDENCIES
│                           List of Python packages to install
│
├── README.md             ← DOCUMENTATION
│                           Project description, setup guide
│
└── threat_intel.db       ← DATABASE FILE (auto-created when you run the app)
                            SQLite database — do not edit manually
```

**Why this structure?**

Each file has ONE responsibility (called "separation of concerns"):
- `database.py` only does database operations
- `fetcher.py` only does API calls
- `visualizations.py` only creates charts
- `app.py` only handles the user interface

This makes your code clean, professional, and easy to maintain.

---

---

# PART 3 — ENVIRONMENT SETUP

## Step-by-Step Setup

### 1. Install Python

Download Python 3.10 or newer from https://www.python.org/downloads/

During installation on Windows, CHECK the box "Add Python to PATH"

Verify installation:
```bash
python --version
# Should print: Python 3.10.x or newer
```

### 2. Install VS Code (Recommended Editor)

Download from https://code.visualstudio.com/

Install the Python extension inside VS Code.

### 3. Create Your Project Folder

```bash
# Create a new folder
mkdir threat-intel-dashboard
cd threat-intel-dashboard
```

### 4. Create Virtual Environment

A virtual environment is an isolated Python environment just for this project. It prevents package conflicts between projects.

```bash
# Create virtual environment named "venv"
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate
```

After activation, your terminal prompt will show `(venv)` at the start.

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `streamlit` — web framework
- `requests` — HTTP calls to APIs
- `pandas` — data handling
- `plotly` — charts

### 6. Get Free API Keys

**AbuseIPDB:**
1. Go to https://www.abuseipdb.com
2. Click "Sign Up" (it's free)
3. Go to My Account → API
4. Copy your API key

**AlienVault OTX:**
1. Go to https://otx.alienvault.com
2. Click "Sign Up" (it's free)
3. Click your username → Settings
4. Copy your OTX Key

**URLhaus and NVD:** No registration needed.

### 7. Set Your API Keys

Edit `fetcher.py` and replace the placeholder values:

```python
# In fetcher.py — find these lines and replace:
ABUSEIPDB_API_KEY = "paste_your_abuseipdb_key_here"
OTX_API_KEY       = "paste_your_otx_key_here"
```

---

---

# PART 4 — FILE WALKTHROUGH

## database.py Explained

### `initialize_database()`

This creates your database tables when the app first starts. Think of it like creating spreadsheet sheets before you can write data into them.

```python
initialize_database()
# Creates threat_intel.db file
# Creates 'iocs' table and 'cve_feed' table
```

The `CREATE TABLE IF NOT EXISTS` clause means this is safe to call multiple times — it won't recreate tables that already exist.

### `insert_ioc()`

This saves a single IOC to the database.

```python
insert_ioc(
    indicator_value  = "185.220.101.45",
    indicator_type   = "IP",
    threat_category  = "malicious-ip",
    source           = "AbuseIPDB",
    country          = "DE",
    confidence_score = 100
)
```

The `INSERT OR IGNORE` SQL clause means if this exact IP from this exact source already exists, it silently skips it instead of throwing an error.

### `get_all_iocs()`

Returns all IOCs as a pandas DataFrame. A DataFrame is like an Excel spreadsheet in Python — rows and columns of data.

```python
df = get_all_iocs()
print(df.head())  # See first 5 rows
print(len(df))    # How many IOCs total
```

### `search_ioc(query)`

Uses SQL LIKE with wildcards to do a partial match search.

```python
results = search_ioc("185.220")
# Returns all IOCs where indicator_value contains "185.220"
```

The `%` characters in SQL LIKE are wildcards meaning "any characters here":
- `%185.220%` means "anything before AND after 185.220"

## fetcher.py Explained

### How API Authentication Works

**AbuseIPDB** uses a header-based API key:
```python
headers = {
    "Key": "your_api_key_here",    # API key in header named "Key"
    "Accept": "application/json"   # Tell server we want JSON
}
response = requests.get(url, headers=headers)
```

**AlienVault OTX** uses a different header name:
```python
headers = {
    "X-OTX-API-KEY": "your_otx_key"   # OTX uses this header name
}
```

**URLhaus** needs no authentication at all — just send a POST request.

### `response.raise_for_status()`

This is a safety check. If the server returns an error (like 404 Not Found or 401 Unauthorized), this line raises a Python exception so you know something went wrong.

### JSON Parsing

APIs return data as JSON strings. `response.json()` converts that string into a Python dictionary you can work with.

```python
response = requests.get(url, headers=headers)
data = response.json()

# Now you can access fields like a dictionary:
ip_list = data["data"]          # Get the "data" field
for item in ip_list:
    ip = item["ipAddress"]      # Get the IP from each item
```

## visualizations.py Explained

### Why Plotly?

Plotly creates interactive charts — users can hover to see exact values, zoom in, and pan around. Much better than static images.

### Basic Plotly Pattern

```python
import plotly.express as px

fig = px.bar(
    dataframe,          # Your pandas DataFrame
    x = "column_name",  # Which column goes on X axis
    y = "count",        # Which column goes on Y axis
    title = "My Chart"
)

# In Streamlit:
st.plotly_chart(fig, use_container_width=True)
```

### `update_layout()`

Used to customize colors, fonts, backgrounds:

```python
fig.update_layout(
    paper_bgcolor = "#1a1f2e",  # Chart background color
    font_color    = "#ffffff",  # Text color
    height        = 400         # Chart height in pixels
)
```

## app.py Explained

### Page Configuration

```python
st.set_page_config(
    page_title = "My Dashboard",
    page_icon  = "🛡️",
    layout     = "wide"         # Uses full screen width
)
```

This MUST be the first Streamlit call. If you put anything before it, you'll get an error.

### The Sidebar

Everything inside `with st.sidebar:` appears in the left sidebar panel.

```python
with st.sidebar:
    st.title("Navigation")
    page = st.radio("Go to:", ["Page 1", "Page 2"])
```

### Page Navigation Pattern

```python
if page == "🏠 Dashboard Overview":
    # Code for dashboard page here

elif page == "🔍 IOC Browser":
    # Code for IOC browser here
```

This is the simplest navigation pattern in Streamlit. No routing libraries needed.

### Columns Layout

```python
col1, col2, col3 = st.columns(3)    # Creates 3 equal columns

with col1:
    st.metric("IPs", 1234)

with col2:
    st.metric("Domains", 567)

with col3:
    st.metric("CVEs", 89)
```

### Session State

```python
# Initialize (only runs once)
if "my_value" not in st.session_state:
    st.session_state.my_value = None

# Set a value (persists across reruns)
st.session_state.my_value = "some result"

# Read it later
if st.session_state.my_value:
    st.write(st.session_state.my_value)
```

---

---

# PART 5 — RUNNING THE PROJECT

## First Run

```bash
# 1. Make sure your virtual environment is activated
# (you should see (venv) in your terminal)

# 2. Navigate to your project folder
cd threat-intel-dashboard

# 3. Run the Streamlit app
streamlit run app.py
```

Streamlit will print something like:
```
  You can now view your Streamlit app in your browser.

  Local URL: http://localhost:8501
  Network URL: http://192.168.x.x:8501
```

Open http://localhost:8501 in your browser.

## Getting Your First Data

1. Look at the left sidebar
2. Click the **"🌐 URLhaus"** button first (no API key needed!)
3. Wait for the spinner to finish
4. You'll see "X domains" appear — that's real threat data!
5. Now click **"📊 Visual Analytics"** to see charts populate

Once you add your API keys:

6. Click **"🔄 Fetch All Feeds"** to pull data from all sources at once

## Stopping the App

Press `Ctrl + C` in your terminal to stop the Streamlit server.

---

---

# PART 6 — TESTING GUIDE

## Test IPs to Use in IP Reputation Checker

```
185.220.101.45    → Known Tor exit node, should show HIGH abuse score
45.83.193.218     → Known C2 server
162.247.74.74     → Tor exit node
8.8.8.8           → Google DNS — should be CLEAN
1.1.1.1           → Cloudflare DNS — should be CLEAN
```

## Expected Behaviors

| Test | Expected Result |
|---|---|
| Fetch URLhaus | 50-100 new domains added, shows in IOC Browser |
| Search "185.220" in IOC Browser | Returns matching IPs |
| IP check on 8.8.8.8 | AbuseIPDB score near 0, OTX pulse count = 0 |
| IP check on 185.220.101.45 | AbuseIPDB score > 80, OTX shows pulses |
| Fetch CVE | 20 CVEs appear in CVE Feed page |
| Download CSV | Downloads threat_intel_iocs.csv file |

## Common Errors & Fixes

| Error | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | Package not installed | Run `pip install -r requirements.txt` |
| `401 Unauthorized` | Wrong API key | Double-check your key in fetcher.py |
| `Connection refused` | No internet | Check your network connection |
| `streamlit: command not found` | venv not activated | Run `venv\Scripts\activate` |

---

---

# PART 7 — DEPLOYMENT GUIDE (Free)

## Deploy on Streamlit Cloud (Recommended — Free)

### Step 1: Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit: Threat Intelligence Dashboard"
git branch -M main
git remote add origin https://github.com/yourusername/threat-intel-dashboard.git
git push -u origin main
```

### Step 2: Deploy on Streamlit Cloud

1. Go to https://share.streamlit.io
2. Sign in with GitHub
3. Click "New app"
4. Select your repository: `threat-intel-dashboard`
5. Set main file: `app.py`
6. Click "Advanced settings"
7. Under **Secrets**, paste:

```toml
ABUSEIPDB_API_KEY = "your_actual_key_here"
OTX_API_KEY = "your_actual_key_here"
```

8. Click **Deploy**

Your live URL will be something like:
`https://yourusername-threat-intel-dashboard-app-abc123.streamlit.app`

This is the URL you add to your resume and GitHub!

### Notes on Streamlit Cloud

- Free tier allows 1 public app
- App sleeps after inactivity but wakes up when visited
- SQLite database resets when the app redeploys (this is normal for free hosting)
- For persistent data, you can upgrade to a cloud database like Supabase (also free)

---

---

# PART 8 — RESUME TIPS

## GitHub Repository Setup

Make your GitHub repo look professional:

1. Add a clear README with screenshots
2. Take screenshots of your dashboard and add them to README
3. Add project description and tags (cybersecurity, threat-intelligence, python, streamlit)
4. Pin the repo on your GitHub profile

## Resume Line

> **Threat Intelligence Dashboard** | Python, Streamlit, REST APIs, SQLite, Plotly  
> Built a real-time threat intelligence dashboard integrating AbuseIPDB, AlienVault OTX, and URLhaus APIs to aggregate and visualize Indicators of Compromise (IOCs) including malicious IPs, domains, and file hashes. Implemented IP reputation lookup engine, CVE vulnerability feed from NVD/NIST, geolocation mapping of threat origins with Plotly choropleth maps, and CSV export. Deployed on Streamlit Cloud.

## Interview Talking Points

When CYFIRMA asks about this project, be ready to explain:

**"What problem does this solve?"**
> Security analysts need to monitor multiple threat intelligence sources simultaneously. This dashboard aggregates data from AbuseIPDB, OTX, and URLhaus into a single view, saving analysts time.

**"What was the hardest part?"**
> Parsing inconsistent JSON responses across different APIs — each API structures its data differently, so I had to write custom parsers for each one.

**"How would you improve it?"**
> I'd add real-time alerts using email or Slack webhooks when a high-confidence IOC is detected. I'd also add ML-based anomaly detection to flag unusual spikes in threat activity.

**"What did you learn?"**
> I learned how REST APIs work, how threat intelligence platforms categorize IOCs, how SQLite manages relational data, and how to build professional data dashboards in Python.

---

---

*Built for learning. Data sourced from AbuseIPDB, AlienVault OTX, URLhaus (abuse.ch), and NIST NVD.*
