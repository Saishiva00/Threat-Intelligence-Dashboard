# ============================================================
# visualizations.py — Plotly Charts & Graphs
# Threat Intelligence Dashboard
# ============================================================
# This file creates all visual analytics for the dashboard:
#
#   1. Threat Category Bar Chart
#      → Shows which threat types are most common (malware, phishing, etc.)
#
#   2. Timeline Chart
#      → Shows how many IOCs were detected per day
#
#   3. World Map
#      → Shows geographic distribution of malicious IPs
#
#   4. IOC Source Pie Chart
#      → Shows which data source contributed the most IOCs
#
#   5. CVE Severity Bar Chart
#      → Shows distribution of vulnerability severity levels
#
# All charts use Plotly — an interactive charting library.
# Users can hover over charts to see exact values.
# ============================================================

import plotly.express      as px
import plotly.graph_objects as go
import pandas as pd

# ─────────────────────────────────────────────
# DASHBOARD COLOR THEME
# Using a dark cybersecurity-inspired palette
# ─────────────────────────────────────────────
COLORS = {
    "background": "#0e1117",
    "card":        "#1a1f2e",
    "accent":      "#00d4ff",
    "danger":      "#ff4b4b",
    "warning":     "#ffa500",
    "success":     "#00ff88",
    "text":        "#ffffff",
}

# ─────────────────────────────────────────────
# ISO-2 → ISO-3 COUNTRY CODE MAPPING
# Plotly choropleth works best with 3-letter codes.
# AbuseIPDB and OTX return 2-letter codes, so we convert.
# ─────────────────────────────────────────────
ISO2_TO_ISO3 = {
    "AF":"AFG","AL":"ALB","DZ":"DZA","AD":"AND","AO":"AGO","AG":"ATG","AR":"ARG",
    "AM":"ARM","AU":"AUS","AT":"AUT","AZ":"AZE","BS":"BHS","BH":"BHR","BD":"BGD",
    "BB":"BRB","BY":"BLR","BE":"BEL","BZ":"BLZ","BJ":"BEN","BT":"BTN","BO":"BOL",
    "BA":"BIH","BW":"BWA","BR":"BRA","BN":"BRN","BG":"BGR","BF":"BFA","BI":"BDI",
    "CV":"CPV","KH":"KHM","CM":"CMR","CA":"CAN","CF":"CAF","TD":"TCD","CL":"CHL",
    "CN":"CHN","CO":"COL","KM":"COM","CG":"COG","CD":"COD","CR":"CRI","CI":"CIV",
    "HR":"HRV","CU":"CUB","CY":"CYP","CZ":"CZE","DK":"DNK","DJ":"DJI","DM":"DMA",
    "DO":"DOM","EC":"ECU","EG":"EGY","SV":"SLV","GQ":"GNQ","ER":"ERI","EE":"EST",
    "SZ":"SWZ","ET":"ETH","FJ":"FJI","FI":"FIN","FR":"FRA","GA":"GAB","GM":"GMB",
    "GE":"GEO","DE":"DEU","GH":"GHA","GR":"GRC","GD":"GRD","GT":"GTM","GN":"GIN",
    "GW":"GNB","GY":"GUY","HT":"HTI","HN":"HND","HU":"HUN","IS":"ISL","IN":"IND",
    "ID":"IDN","IR":"IRN","IQ":"IRQ","IE":"IRL","IL":"ISR","IT":"ITA","JM":"JAM",
    "JP":"JPN","JO":"JOR","KZ":"KAZ","KE":"KEN","KI":"KIR","KP":"PRK","KR":"KOR",
    "KW":"KWT","KG":"KGZ","LA":"LAO","LV":"LVA","LB":"LBN","LS":"LSO","LR":"LBR",
    "LY":"LBY","LI":"LIE","LT":"LTU","LU":"LUX","MG":"MDG","MW":"MWI","MY":"MYS",
    "MV":"MDV","ML":"MLI","MT":"MLT","MH":"MHL","MR":"MRT","MU":"MUS","MX":"MEX",
    "FM":"FSM","MD":"MDA","MC":"MCO","MN":"MNG","ME":"MNE","MA":"MAR","MZ":"MOZ",
    "MM":"MMR","NA":"NAM","NR":"NRU","NP":"NPL","NL":"NLD","NZ":"NZL","NI":"NIC",
    "NE":"NER","NG":"NGA","MK":"MKD","NO":"NOR","OM":"OMN","PK":"PAK","PW":"PLW",
    "PA":"PAN","PG":"PNG","PY":"PRY","PE":"PER","PH":"PHL","PL":"POL","PT":"PRT",
    "QA":"QAT","RO":"ROU","RU":"RUS","RW":"RWA","KN":"KNA","LC":"LCA","VC":"VCT",
    "WS":"WSM","SM":"SMR","ST":"STP","SA":"SAU","SN":"SEN","RS":"SRB","SC":"SYC",
    "SL":"SLE","SG":"SGP","SK":"SVK","SI":"SVN","SB":"SLB","SO":"SOM","ZA":"ZAF",
    "SS":"SSD","ES":"ESP","LK":"LKA","SD":"SDN","SR":"SUR","SE":"SWE","CH":"CHE",
    "SY":"SYR","TW":"TWN","TJ":"TJK","TZ":"TZA","TH":"THA","TL":"TLS","TG":"TGO",
    "TO":"TON","TT":"TTO","TN":"TUN","TR":"TUR","TM":"TKM","TV":"TUV","UG":"UGA",
    "UA":"UKR","AE":"ARE","GB":"GBR","US":"USA","UY":"URY","UZ":"UZB","VU":"VUT",
    "VE":"VEN","VN":"VNM","YE":"YEM","ZM":"ZMB","ZW":"ZWE","HK":"HKG","MO":"MAC",
    "PS":"PSE","XK":"XKX","TF":"ATF","AQ":"ATA","CK":"COK","NU":"NIU",
}

CHART_COLORS = [
    "#00d4ff", "#ff4b4b", "#ffa500", "#00ff88",
    "#a855f7", "#ec4899", "#f59e0b", "#10b981"
]


def create_threat_category_chart(threat_df):
    """
    Creates a horizontal bar chart showing threat categories.
    
    Why horizontal? Easier to read long category names.
    
    Input:
        threat_df — DataFrame with columns:
            - threat_category (str)
            - count (int)
    
    Example data:
        threat_category   | count
        malware_download  |  245
        phishing          |  189
        botnet            |  134
        ransomware        |   87
    
    Returns:
        plotly Figure object (displayed in Streamlit with st.plotly_chart)
    """
    if threat_df.empty:
        # Return a placeholder chart if no data
        fig = go.Figure()
        fig.add_annotation(
            text="No data available yet. Fetch threat feeds to populate charts.",
            x=0.5, y=0.5, showarrow=False,
            font=dict(color=COLORS["text"], size=14)
        )
        fig.update_layout(
            paper_bgcolor=COLORS["card"],
            plot_bgcolor=COLORS["card"],
            height=300
        )
        return fig

    # Sort by count descending, take top 10
    df = threat_df.sort_values("count", ascending=True).tail(10)

    fig = px.bar(
        df,
        x          = "count",
        y          = "threat_category",
        orientation= "h",                    # Horizontal bars
        color      = "count",                # Color intensity based on count
        color_continuous_scale = "Reds",     # Red = dangerous
        title      = "🎯 Top Threat Categories",
        labels     = {"count": "Number of IOCs", "threat_category": "Threat Type"}
    )

    fig.update_layout(
        paper_bgcolor    = COLORS["card"],
        plot_bgcolor     = COLORS["card"],
        font_color       = COLORS["text"],
        title_font_size  = 16,
        showlegend       = False,
        coloraxis_showscale = False,
        margin           = dict(l=10, r=10, t=40, b=10),
        xaxis = dict(gridcolor="#2d3748"),
        yaxis = dict(gridcolor="#2d3748")
    )

    return fig


def create_timeline_chart(timeline_df):
    """
    Creates a line chart showing IOC detections over time.
    
    This is useful for spotting attack spikes — sudden surges
    in IOC volume can indicate active campaigns.
    
    Input:
        timeline_df — DataFrame with columns:
            - date  (str, YYYY-MM-DD)
            - count (int)
    
    Returns:
        plotly Figure object
    """
    if timeline_df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No timeline data available yet.",
            x=0.5, y=0.5, showarrow=False,
            font=dict(color=COLORS["text"], size=14)
        )
        fig.update_layout(
            paper_bgcolor=COLORS["card"],
            plot_bgcolor=COLORS["card"],
            height=300
        )
        return fig

    fig = px.area(
        timeline_df,
        x     = "date",
        y     = "count",
        title = "📈 IOC Detection Timeline",
        labels = {"date": "Date", "count": "IOCs Detected"}
    )

    # Style the area fill for a cybersecurity "radar screen" feel
    fig.update_traces(
        line_color  = COLORS["accent"],
        fillcolor   = "rgba(0, 212, 255, 0.15)",  # Semi-transparent cyan
        line_width  = 2
    )

    fig.update_layout(
        paper_bgcolor   = COLORS["card"],
        plot_bgcolor    = COLORS["card"],
        font_color      = COLORS["text"],
        title_font_size = 16,
        margin          = dict(l=10, r=10, t=40, b=10),
        xaxis = dict(
            gridcolor    = "#2d3748",
            showgrid     = True,
        ),
        yaxis = dict(
            gridcolor    = "#2d3748",
            showgrid     = True,
        )
    )

    return fig


def create_world_map(country_df):
    """
    Creates an interactive choropleth world map showing
    where malicious IPs originate geographically.
    
    Darker/more intense color = more malicious IPs from that country.
    
    Input:
        country_df — DataFrame with columns:
            - country (str, ISO country code e.g. "US", "CN", "RU")
            - count   (int)
    
    Returns:
        plotly Figure object
    """
    if country_df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No geographic data available yet.",
            x=0.5, y=0.5, showarrow=False,
            font=dict(color=COLORS["text"], size=14)
        )
        fig.update_layout(
            paper_bgcolor=COLORS["card"],
            plot_bgcolor=COLORS["card"],
            height=400
        )
        return fig

    # Convert 2-letter codes → 3-letter codes for Plotly
    df = country_df.copy()
    df["country"] = df["country"].str.upper().map(ISO2_TO_ISO3)
    df = df.dropna(subset=["country"])  # Drop rows with unrecognized codes

    fig = px.choropleth(
        df,
        locations              = "country",       # ISO-3 country codes
        locationmode           = "ISO-3",
        color                  = "count",
        color_continuous_scale = "Reds",
        title                  = "🌍 Geographic Distribution of Malicious IPs",
        labels                 = {"count": "Malicious IPs", "country": "Country"}
    )

    fig.update_layout(
        paper_bgcolor   = COLORS["card"],
        font_color      = COLORS["text"],
        title_font_size = 16,
        geo = dict(
            showframe        = False,
            showcoastlines   = True,
            coastlinecolor   = "#2d3748",
            bgcolor          = COLORS["card"],
            landcolor        = "#1a2035",
            oceancolor       = "#0e1117",
            showocean        = True,
            projection_type  = "natural earth"
        ),
        coloraxis_colorbar = dict(
            title_font_color = COLORS["text"],
            tickfont_color   = COLORS["text"]
        ),
        margin = dict(l=0, r=0, t=40, b=0),
        height = 450
    )

    return fig


def create_source_pie_chart(source_df):
    """
    Creates a donut pie chart showing which data source
    contributed the most IOCs.
    
    Input:
        source_df — DataFrame with columns:
            - source (str)
            - count  (int)
    
    Returns:
        plotly Figure object
    """
    if source_df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No source data yet.",
            x=0.5, y=0.5, showarrow=False,
            font=dict(color=COLORS["text"], size=14)
        )
        fig.update_layout(
            paper_bgcolor=COLORS["card"],
            plot_bgcolor=COLORS["card"],
            height=300
        )
        return fig

    fig = px.pie(
        source_df,
        values  = "count",
        names   = "source",
        title   = "📊 IOCs by Data Source",
        color_discrete_sequence = CHART_COLORS,
        hole    = 0.45           # Donut chart (more modern look)
    )

    fig.update_traces(
        textfont_color = COLORS["text"],
        textinfo       = "percent+label"
    )

    fig.update_layout(
        paper_bgcolor   = COLORS["card"],
        font_color      = COLORS["text"],
        title_font_size = 16,
        legend = dict(
            font_color  = COLORS["text"],
            bgcolor     = COLORS["card"]
        ),
        margin = dict(l=10, r=10, t=40, b=10),
        height = 320
    )

    return fig


def create_cve_severity_chart(cve_df):
    """
    Creates a bar chart showing the distribution of CVE severity levels.
    
    Severity levels:
        CRITICAL (9.0-10.0) → Red
        HIGH     (7.0-8.9)  → Orange
        MEDIUM   (4.0-6.9)  → Yellow
        LOW      (0.1-3.9)  → Green
    
    Input:
        cve_df — DataFrame from get_all_cves()
    
    Returns:
        plotly Figure object
    """
    if cve_df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No CVE data available yet. Fetch CVE feed first.",
            x=0.5, y=0.5, showarrow=False,
            font=dict(color=COLORS["text"], size=14)
        )
        fig.update_layout(
            paper_bgcolor=COLORS["card"],
            plot_bgcolor=COLORS["card"],
            height=300
        )
        return fig

    # Count CVEs per severity level
    severity_counts = cve_df["severity"].value_counts().reset_index()
    severity_counts.columns = ["severity", "count"]

    # Define color per severity (matches cybersecurity conventions)
    color_map = {
        "CRITICAL": "#ff0000",
        "HIGH":     "#ff6600",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#00cc44",
        "UNKNOWN":  "#888888"
    }

    # Add color column
    severity_counts["color"] = severity_counts["severity"].map(color_map).fillna("#888888")

    fig = go.Figure()

    for _, row in severity_counts.iterrows():
        fig.add_trace(go.Bar(
            x            = [row["severity"]],
            y            = [row["count"]],
            name         = row["severity"],
            marker_color = row["color"],
            text         = [row["count"]],
            textposition = "outside",
            textfont     = dict(color=COLORS["text"])
        ))

    fig.update_layout(
        title           = "🛡️ CVE Severity Distribution",
        paper_bgcolor   = COLORS["card"],
        plot_bgcolor    = COLORS["card"],
        font_color      = COLORS["text"],
        title_font_size = 16,
        showlegend      = False,
        xaxis = dict(
            title      = "Severity Level",
            gridcolor  = "#2d3748"
        ),
        yaxis = dict(
            title      = "Number of CVEs",
            gridcolor  = "#2d3748"
        ),
        margin = dict(l=10, r=10, t=40, b=10),
        height = 320
    )

    return fig


def create_indicator_type_chart(type_df):
    """
    Creates a simple bar chart showing the breakdown of
    IOC types: IPs vs Domains vs Hashes.
    
    Input:
        type_df — DataFrame with columns:
            - indicator_type (str)
            - count          (int)
    
    Returns:
        plotly Figure object
    """
    if type_df.empty:
        return go.Figure()

    fig = px.bar(
        type_df,
        x                    = "indicator_type",
        y                    = "count",
        title                = "🔍 IOC Type Breakdown",
        color                = "indicator_type",
        color_discrete_map   = {
            "IP":     COLORS["danger"],
            "Domain": COLORS["warning"],
            "Hash":   COLORS["accent"]
        },
        text = "count"
    )

    fig.update_traces(textposition="outside", textfont_color=COLORS["text"])

    fig.update_layout(
        paper_bgcolor   = COLORS["card"],
        plot_bgcolor    = COLORS["card"],
        font_color      = COLORS["text"],
        title_font_size = 16,
        showlegend      = False,
        xaxis           = dict(gridcolor="#2d3748", title=""),
        yaxis           = dict(gridcolor="#2d3748", title="Count"),
        margin          = dict(l=10, r=10, t=40, b=10),
        height          = 300
    )

    return fig
