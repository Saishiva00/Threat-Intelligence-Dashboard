# ============================================================
# app.py — Main Streamlit Application
# Threat Intelligence Dashboard
# ============================================================
#
# HOW STREAMLIT WORKS:
#   - Streamlit is a Python library that turns Python scripts
#     into web apps automatically.
#   - Every time a user interacts (clicks a button, types in a
#     search bar), the entire script re-runs from top to bottom.
#   - st.session_state is used to remember values between reruns.
#
# HOW TO RUN:
#   streamlit run app.py
#
# SECTIONS:
#   1. Page config & styling
#   2. Sidebar — navigation & API key input
#   3. Dashboard page (overview + stats)
#   4. IOC Browser page
#   5. IP Reputation Checker page
#   6. CVE Feed page
#   7. Visual Analytics page
# ============================================================

import streamlit as st
import pandas    as pd
import time

# Import our custom modules
from database       import (initialize_database, get_all_iocs, search_ioc,
                             get_ioc_stats, get_all_cves, get_total_ioc_count,
                             clear_all_iocs)
from fetcher        import (fetch_abuseipdb, fetch_otx, fetch_urlhaus,
                             fetch_cve_feed, fetch_all_feeds, check_ip_reputation,
                             ABUSEIPDB_API_KEY, OTX_API_KEY)
from visualizations import (create_threat_category_chart, create_timeline_chart,
                             create_world_map, create_source_pie_chart,
                             create_cve_severity_chart, create_indicator_type_chart)

# ─────────────────────────────────────────────────────────
# STEP 1 — PAGE CONFIGURATION
# Must be the FIRST Streamlit call in the script
# ─────────────────────────────────────────────────────────
st.set_page_config(
    page_title     = "Threat Intelligence Dashboard",
    page_icon      = "🛡️",
    layout         = "wide",                   # Use full screen width
    initial_sidebar_state = "expanded"
)

# ─────────────────────────────────────────────────────────
# STEP 2 — CUSTOM CSS STYLING
# Injects custom CSS for dark cybersecurity theme
# ─────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* ── Global background ── */
    .stApp {
        background-color: #0e1117;
        color: #ffffff;
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background-color: #1a1f2e;
        border-right: 1px solid #2d3748;
    }

    /* ── Metric cards ── */
    [data-testid="metric-container"] {
        background-color: #1a1f2e;
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 15px;
    }

    /* ── Buttons ── */
    .stButton > button {
        background-color: #00d4ff;
        color: #000000;
        border: none;
        border-radius: 6px;
        font-weight: bold;
        padding: 8px 20px;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background-color: #00b8d9;
        transform: translateY(-1px);
    }

    /* ── Tables ── */
    .stDataFrame {
        background-color: #1a1f2e;
        border-radius: 8px;
    }

    /* ── Headers ── */
    h1, h2, h3 { color: #00d4ff; }

    /* ── Alert/info boxes ── */
    .stAlert {
        background-color: #1a1f2e;
        border-radius: 6px;
    }

    /* ── Section dividers ── */
    hr {
        border-color: #2d3748;
    }

    /* ── Severity badges ── */
    .badge-critical { color: #ff0000; font-weight: bold; }
    .badge-high     { color: #ff6600; font-weight: bold; }
    .badge-medium   { color: #ffcc00; font-weight: bold; }
    .badge-low      { color: #00cc44; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────
# STEP 3 — INITIALIZE DATABASE
# Creates tables if they don't exist yet
# ─────────────────────────────────────────────────────────
initialize_database()

# ─────────────────────────────────────────────────────────
# STEP 4 — SESSION STATE
# st.session_state persists values across Streamlit reruns
# ─────────────────────────────────────────────────────────
if "last_fetch_time" not in st.session_state:
    st.session_state.last_fetch_time = None

if "reputation_result" not in st.session_state:
    st.session_state.reputation_result = None


# ─────────────────────────────────────────────────────────
# STEP 5 — SIDEBAR NAVIGATION
# ─────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Threat Intel Dashboard")
    st.markdown("---")

    # Navigation menu
    page = st.radio(
        "📍 Navigation",
        options = [
            "🏠 Dashboard Overview",
            "🔍 IOC Browser",
            "🔎 IP Reputation Checker",
            "📋 CVE Feed",
            "📊 Visual Analytics"
        ],
        label_visibility = "collapsed"
    )

    st.markdown("---")

    # ── API Key Status ──────────────────────────
    st.markdown("### 🔑 API Key Status")

    abuse_configured = bool(ABUSEIPDB_API_KEY)
    otx_configured   = bool(OTX_API_KEY)

    st.write("AbuseIPDB:", "✅ Configured" if abuse_configured else "❌ Not set")
    st.write("OTX:",       "✅ Configured" if otx_configured   else "❌ Not set")
    st.write("URLhaus:",   "✅ No key needed")

    st.markdown("---")

    # ── Fetch Controls ──────────────────────────
    st.markdown("### ⚡ Data Controls")

    if st.button("🔄 Fetch All Feeds", use_container_width=True):
        with st.spinner("Fetching threat intelligence data..."):
            counts = fetch_all_feeds()
            st.session_state.last_fetch_time = time.strftime("%H:%M:%S")
        st.success(f"Fetched successfully!")
        st.rerun()

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🌐 URLhaus", use_container_width=True):
            with st.spinner("Fetching URLhaus..."):
                n = fetch_urlhaus()
            st.success(f"+{n} domains")
            st.rerun()
    with col2:
        if st.button("🛡️ CVEs", use_container_width=True):
            with st.spinner("Fetching CVEs..."):
                n = fetch_cve_feed()
            st.success(f"+{n} CVEs")
            st.rerun()

    if st.session_state.last_fetch_time:
        st.caption(f"Last fetch: {st.session_state.last_fetch_time}")

    st.markdown("---")

    # ── Export ──────────────────────────────────
    st.markdown("### 💾 Export Data")
    iocs_df = get_all_iocs()
    if not iocs_df.empty:
        csv_data = iocs_df.to_csv(index=False)
        st.download_button(
            label     = "📥 Download IOCs as CSV",
            data      = csv_data,
            file_name = "threat_intel_iocs.csv",
            mime      = "text/csv",
            use_container_width = True
        )
    else:
        st.caption("No data to export yet.")

    st.markdown("---")
    st.caption("Built with ❤️ using Python + Streamlit")
    st.caption("Data: AbuseIPDB | OTX | URLhaus | NVD")


# ═══════════════════════════════════════════════════════════
# PAGE 1 — DASHBOARD OVERVIEW
# ═══════════════════════════════════════════════════════════
if page == "🏠 Dashboard Overview":

    st.title("🛡️ Threat Intelligence Dashboard")
    st.markdown("Real-time threat intelligence from AbuseIPDB, AlienVault OTX, URLhaus & NVD CVE Feed")
    st.markdown("---")

    # ── Key Metrics Row ──────────────────────────────────
    # Load stats from database
    stats   = get_ioc_stats()
    all_iocs = get_all_iocs()
    all_cves = get_all_cves()

    total_iocs  = len(all_iocs)
    total_ips   = len(all_iocs[all_iocs["indicator_type"] == "IP"])    if not all_iocs.empty else 0
    total_domain= len(all_iocs[all_iocs["indicator_type"] == "Domain"])if not all_iocs.empty else 0
    total_cves  = len(all_cves)

    # Display 4 metric cards side by side
    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric(
            label    = "🎯 Total IOCs",
            value    = f"{total_iocs:,}",
            delta    = "Active threats tracked"
        )
    with m2:
        st.metric(
            label    = "🔴 Malicious IPs",
            value    = f"{total_ips:,}",
            delta    = "IP addresses flagged"
        )
    with m3:
        st.metric(
            label    = "🌐 Malicious Domains",
            value    = f"{total_domain:,}",
            delta    = "Domains flagged"
        )
    with m4:
        st.metric(
            label    = "⚠️ CVEs Tracked",
            value    = f"{total_cves:,}",
            delta    = "Vulnerabilities"
        )

    st.markdown("---")

    # ── Quick Charts Row ────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.plotly_chart(
            create_threat_category_chart(stats["threat_categories"]),
            use_container_width=True
        )

    with col_right:
        st.plotly_chart(
            create_source_pie_chart(stats["sources"]),
            use_container_width=True
        )

    # ── Timeline ────────────────────────────────────────
    st.plotly_chart(
        create_timeline_chart(stats["timeline"]),
        use_container_width=True
    )

    # ── Recent IOCs Table ───────────────────────────────
    st.markdown("### 📋 Latest IOCs")
    if not all_iocs.empty:
        # Show last 20 records
        recent = all_iocs.head(20)[[
            "indicator_value", "indicator_type",
            "threat_category", "source",
            "confidence_score", "country", "date_added"
        ]]
        st.dataframe(recent, use_container_width=True, height=400)
    else:
        st.info("👆 No data yet. Click **'Fetch All Feeds'** in the sidebar to load threat intelligence data.")
        st.markdown("""
        **Getting Started:**
        1. Sign up for free API keys at [AbuseIPDB](https://www.abuseipdb.com) and [AlienVault OTX](https://otx.alienvault.com)
        2. Set your API keys in `fetcher.py` or as environment variables
        3. Click **'Fetch All Feeds'** in the sidebar
        4. Explore the dashboard!
        
        > 💡 **URLhaus works without an API key** — click the URLhaus button to get immediate data!
        """)


# ═══════════════════════════════════════════════════════════
# PAGE 2 — IOC BROWSER
# ═══════════════════════════════════════════════════════════
elif page == "🔍 IOC Browser":

    st.title("🔍 IOC Browser")
    st.markdown("Search and filter Indicators of Compromise (IOCs)")
    st.markdown("---")

    # ── Search Bar ──────────────────────────────────────
    col_search, col_filter = st.columns([3, 1])

    with col_search:
        search_query = st.text_input(
            "🔎 Search IOC",
            placeholder="Enter IP address, domain, or hash...",
            help="Partial matches supported — e.g., type '192.168' to find all matching IPs"
        )

    with col_filter:
        filter_type = st.selectbox(
            "Filter by Type",
            options=["All", "IP", "Domain", "Hash"]
        )

    # ── Load and Filter Data ────────────────────────────
    if search_query:
        df = search_ioc(search_query)
        st.info(f"Found **{len(df)}** results for '{search_query}'")
    else:
        df = get_all_iocs()

    # Apply type filter
    if filter_type != "All" and not df.empty:
        df = df[df["indicator_type"] == filter_type]

    # ── Source Filter ───────────────────────────────────
    if not df.empty:
        sources       = ["All"] + sorted(df["source"].unique().tolist())
        source_filter = st.selectbox("Filter by Source", options=sources)
        if source_filter != "All":
            df = df[df["source"] == source_filter]

    # ── Display Results ─────────────────────────────────
    st.markdown(f"### Showing {len(df)} IOCs")

    if not df.empty:
        # Make confidence score visual with color coding
        display_df = df[[
            "indicator_value", "indicator_type", "threat_category",
            "source", "confidence_score", "country", "date_added"
        ]].copy()

        display_df.columns = [
            "Indicator", "Type", "Threat Category",
            "Source", "Confidence %", "Country", "Date Added"
        ]

        st.dataframe(display_df, use_container_width=True, height=500)

        # Show selected IOC details
        st.markdown("---")
        st.markdown("### 📄 IOC Detail View")
        selected_indicator = st.selectbox(
            "Select an IOC to view details:",
            options=df["indicator_value"].tolist()[:50]  # Limit to 50 for performance
        )

        if selected_indicator:
            row = df[df["indicator_value"] == selected_indicator].iloc[0]
            d1, d2, d3 = st.columns(3)
            with d1:
                st.metric("Indicator",    row["indicator_value"])
                st.metric("Type",         row["indicator_type"])
            with d2:
                st.metric("Source",       row["source"])
                st.metric("Category",     row["threat_category"] or "Unknown")
            with d3:
                st.metric("Confidence",   f"{row['confidence_score']}%")
                st.metric("Country",      row["country"] or "Unknown")

    else:
        st.warning("No IOCs found. Try a different search term or fetch data first.")


# ═══════════════════════════════════════════════════════════
# PAGE 3 — IP REPUTATION CHECKER
# ═══════════════════════════════════════════════════════════
elif page == "🔎 IP Reputation Checker":

    st.title("🔎 IP Reputation Checker")
    st.markdown("Instantly check any IP address against AbuseIPDB and AlienVault OTX")
    st.markdown("---")

    # ── IP Input ────────────────────────────────────────
    ip_col, btn_col = st.columns([3, 1])

    with ip_col:
        ip_input = st.text_input(
            "Enter IP Address",
            placeholder="e.g., 185.220.101.45",
            help="Enter any IPv4 address to check its reputation"
        )

    with btn_col:
        st.markdown("<br>", unsafe_allow_html=True)  # spacing
        check_btn = st.button("🔍 Check Reputation", use_container_width=True)

    # ── Example IPs for Testing ─────────────────────────
    st.markdown("**Quick test (click to use):**")
    test_col1, test_col2, test_col3 = st.columns(3)
    with test_col1:
        if st.button("185.220.101.45 (Known bad)"):
            ip_input = "185.220.101.45"
            check_btn = True
    with test_col2:
        if st.button("8.8.8.8 (Google DNS)"):
            ip_input = "8.8.8.8"
            check_btn = True
    with test_col3:
        if st.button("1.1.1.1 (Cloudflare)"):
            ip_input = "1.1.1.1"
            check_btn = True

    # ── Run Check ───────────────────────────────────────
    if check_btn and ip_input:
        with st.spinner(f"Checking {ip_input} against threat intelligence sources..."):
            result = check_ip_reputation(ip_input)
            st.session_state.reputation_result = result

    # ── Display Results ─────────────────────────────────
    if st.session_state.reputation_result:
        result = st.session_state.reputation_result
        ip     = result["ip"]

        st.markdown(f"### Results for: `{ip}`")
        st.markdown("---")

        # ── Determine Overall Risk ──────────────────────
        abuse_score = 0
        if result["abuseipdb"]:
            abuse_score = result["abuseipdb"].get("abuse_score", 0)

        if abuse_score >= 80:
            risk_color = "🔴"
            risk_label = "HIGH RISK"
        elif abuse_score >= 40:
            risk_color = "🟡"
            risk_label = "MEDIUM RISK"
        elif abuse_score > 0:
            risk_color = "🟠"
            risk_label = "LOW RISK"
        else:
            risk_color = "🟢"
            risk_label = "CLEAN"

        st.markdown(f"## {risk_color} Overall Verdict: **{risk_label}**")
        st.markdown("---")

        # ── AbuseIPDB Results ───────────────────────────
        col_abuse, col_otx = st.columns(2)

        with col_abuse:
            st.markdown("#### 📊 AbuseIPDB")
            if result["abuseipdb"]:
                ab = result["abuseipdb"]
                st.metric("Abuse Confidence Score", f"{ab['abuse_score']}%")
                st.write(f"**Country:**        {ab.get('country', 'N/A')}")
                st.write(f"**ISP:**            {ab.get('isp', 'N/A')}")
                st.write(f"**Total Reports:**  {ab.get('total_reports', 0)}")
                st.write(f"**Last Reported:**  {ab.get('last_reported', 'Never')}")
                st.write(f"**Usage Type:**     {ab.get('usage_type', 'N/A')}")

                if ab["abuse_score"] >= 80:
                    st.error("⛔ This IP has been heavily reported for malicious activity!")
                elif ab["abuse_score"] >= 40:
                    st.warning("⚠️ This IP has moderate abuse reports.")
                else:
                    st.success("✅ Low abuse reports from AbuseIPDB.")
            else:
                st.warning("AbuseIPDB data unavailable. Check your API key.")

        # ── OTX Results ─────────────────────────────────
        with col_otx:
            st.markdown("#### 🌐 AlienVault OTX")
            if result["otx"]:
                otx = result["otx"]
                st.metric("Threat Pulses Found", otx.get("pulse_count", 0))
                st.write(f"**Country:**   {otx.get('country', 'N/A')}")
                st.write(f"**ASN:**       {otx.get('asn', 'N/A')}")

                tags = otx.get("tags", [])
                if tags:
                    st.write("**Associated Tags:**")
                    st.write(", ".join(tags[:10]))

                if otx.get("is_known_threat"):
                    st.error(f"⛔ Found in {otx['pulse_count']} threat intelligence pulses!")
                else:
                    st.success("✅ Not found in OTX threat pulses.")
            else:
                st.warning("OTX data unavailable. Check your API key.")

        # ── Errors ──────────────────────────────────────
        if result["errors"]:
            st.markdown("---")
            st.markdown("**⚠️ Errors encountered:**")
            for err in result["errors"]:
                st.caption(f"• {err}")


# ═══════════════════════════════════════════════════════════
# PAGE 4 — CVE FEED
# ═══════════════════════════════════════════════════════════
elif page == "📋 CVE Feed":

    st.title("📋 CVE Vulnerability Feed")
    st.markdown("Recent CVEs from NVD (National Vulnerability Database) — NIST")
    st.markdown("---")

    cve_df = get_all_cves()

    if cve_df.empty:
        st.info("No CVE data yet. Click **'CVEs'** in the sidebar to fetch the latest vulnerabilities.")
    else:
        # ── CVE Stats ───────────────────────────────────
        total = len(cve_df)
        critical = len(cve_df[cve_df["severity"] == "CRITICAL"])
        high     = len(cve_df[cve_df["severity"] == "HIGH"])
        medium   = len(cve_df[cve_df["severity"] == "MEDIUM"])

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total CVEs",    total)
        c2.metric("🔴 Critical",   critical)
        c3.metric("🟠 High",       high)
        c4.metric("🟡 Medium",     medium)

        st.markdown("---")

        # ── Severity Filter ─────────────────────────────
        sev_filter = st.selectbox(
            "Filter by Severity",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )

        filtered = cve_df if sev_filter == "All" else cve_df[cve_df["severity"] == sev_filter]

        # ── Display CVE Table ───────────────────────────
        display_cve = filtered[[
            "cve_id", "severity", "cvss_score",
            "description", "published_date"
        ]].copy()

        display_cve.columns = [
            "CVE ID", "Severity", "CVSS Score",
            "Description", "Published"
        ]

        # Truncate long descriptions for table display
        display_cve["Description"] = display_cve["Description"].str[:120] + "..."

        st.dataframe(display_cve, use_container_width=True, height=500)

        # ── CVE Severity Chart ──────────────────────────
        st.markdown("---")
        st.plotly_chart(
            create_cve_severity_chart(cve_df),
            use_container_width=True
        )

        # ── CVE Detail Viewer ───────────────────────────
        st.markdown("---")
        st.markdown("### 🔍 CVE Detail")
        selected_cve = st.selectbox(
            "Select a CVE to read full details:",
            options=cve_df["cve_id"].tolist()[:50]
        )
        if selected_cve:
            row = cve_df[cve_df["cve_id"] == selected_cve].iloc[0]
            st.markdown(f"**CVE ID:** `{row['cve_id']}`")
            st.markdown(f"**Severity:** {row['severity']} (CVSS: {row['cvss_score']})")
            st.markdown(f"**Published:** {row['published_date']}")
            st.markdown("**Description:**")
            st.info(row["description"])


# ═══════════════════════════════════════════════════════════
# PAGE 5 — VISUAL ANALYTICS
# ═══════════════════════════════════════════════════════════
elif page == "📊 Visual Analytics":

    st.title("📊 Visual Analytics")
    st.markdown("Interactive charts and geographic analysis of threat intelligence data")
    st.markdown("---")

    stats = get_ioc_stats()

    # ── Row 1: Threat Category + IOC Types ──────────────
    col1, col2 = st.columns(2)

    with col1:
        st.plotly_chart(
            create_threat_category_chart(stats["threat_categories"]),
            use_container_width=True
        )

    with col2:
        st.plotly_chart(
            create_indicator_type_chart(stats["types"]),
            use_container_width=True
        )

    # ── Row 2: Timeline ─────────────────────────────────
    st.plotly_chart(
        create_timeline_chart(stats["timeline"]),
        use_container_width=True
    )

    # ── Row 3: World Map ─────────────────────────────────
    st.plotly_chart(
        create_world_map(stats["countries"]),
        use_container_width=True
    )

    # ── Row 4: Source Distribution ───────────────────────
    st.plotly_chart(
        create_source_pie_chart(stats["sources"]),
        use_container_width=True
    )

    # ── CVE Chart ───────────────────────────────────────
    cve_df = get_all_cves()
    if not cve_df.empty:
        st.plotly_chart(
            create_cve_severity_chart(cve_df),
            use_container_width=True
        )
    else:
        st.info("Fetch CVE data to see vulnerability severity analytics.")
