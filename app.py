import streamlit as st
import pandas as pd
import requests
import folium
from streamlit_folium import st_folium
import time
import os
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 1. CONFIGURATION ---
# Load API key from environment variable — never hardcode secrets in source.
# On Mac: export VT_API_KEY='your_key_here'  (or add to ~/.zshrc)
# On EC2: export VT_API_KEY='your_key_here'
VT_API_KEY = os.environ.get("VT_API_KEY")

# Configure logging for server-side diagnostics
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Session state init
if "df_ips" not in st.session_state:
    st.session_state.df_ips = None

st.set_page_config(
    page_title="The Breadcrumb Engine",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- 2. STYLING ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inconsolata:wght@200..900&display=swap');

    /* 1. Global Font */
    html, body, .stApp, .stMarkdown, p, label, li, .stDataFrame,
    [data-testid="stTable"], h1, h2, h3, h4, h5, h6, .stTextArea textarea {
        font-family: 'Inconsolata', monospace !important;
    }

    /* 2. Hamburger icon swap */
    [data-testid="stSidebarCollapseButton"] span:not(.st-emotion-cache-10oheav) {
        font-family: 'Material Symbols Outlined' !important;
        visibility: hidden;
        position: relative;
    }
    [data-testid="stSidebarCollapseButton"] span::before {
        content: '☰';
        visibility: visible;
        position: absolute;
        left: 0;
        font-family: 'Material Symbols Outlined' !important;
        font-feature-settings: 'liga' !important;
    }

    /* 3. Protect all icons */
    [data-testid="stIconChild"], .notranslate, i {
        font-family: 'Material Symbols Outlined' !important;
        font-feature-settings: 'liga' !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 3. SIDEBAR INPUT ---
with st.sidebar:
    st.header("Intelligence Input")

    # Warn early if API key is missing — avoids silent failures mid-run
    if not VT_API_KEY:
        st.warning(
            "⚠️ `VT_API_KEY` environment variable is not set. "
            "Risk scores will be unavailable until it is configured."
        )

    ip_input = st.text_area(
        "IP List:",
        height=250,
        placeholder="8.8.8.8\n141.98.10.210",
    )
    process_btn = st.button("Generate Intelligence Map", type="primary")

    if st.button("Clear Investigation"):
        st.session_state.df_ips = None
        st.rerun()

# --- 4. HELPERS ---

def is_valid_ip(ip: str) -> bool:
    """Validates IPv4 addresses to prevent malformed input reaching external APIs."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def get_abuse_score(ip: str) -> int:
    """
    Fetches a 0-100 risk score for a given IP from the VirusTotal API.
    Score is calculated as: (malicious votes / total votes) * 100.
    Returns 0 if the key is missing, no votes exist, or the request fails.
    """
    if not VT_API_KEY:
        return 0
    try:
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=8,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())
            if total == 0:
                return 0
            # Combine malicious + suspicious votes for a conservative risk score
            return round(((malicious + suspicious) / total) * 100)
        else:
            logger.warning("VirusTotal returned %s for IP %s", resp.status_code, ip)
    except requests.exceptions.Timeout:
        logger.warning("VirusTotal request timed out for %s", ip)
    except requests.exceptions.RequestException as e:
        logger.error("VirusTotal request error for %s: %s", ip, e)
    return 0


def geolocate_single_ip(ip: str) -> dict | None:
    """
    Geolocates a single IP via ipinfo.io (HTTPS) and enriches it with an abuse score.
    Returns a result dict on success, or None on failure.

    Uses ipinfo.io instead of ip-api.com because:
    - ipinfo.io supports HTTPS on the free tier, preventing MITM attacks
    - ip-api.com only supports HTTPS on paid plans
    """
    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",  # HTTPS — encrypted in transit
            timeout=8,
        )
        data = resp.json()

        # ipinfo.io returns coords as "lat,lon" string in a "loc" field
        if "loc" in data and "ip" in data:
            lat, lon = data["loc"].split(",")
            return {
                "query":      data.get("ip"),
                "country":    data.get("country"),
                "city":       data.get("city"),
                "org":        data.get("org"),
                "lat":        float(lat),
                "lon":        float(lon),
                "risk_score": get_abuse_score(ip),
                # "status" field deliberately excluded — avoids tooling fingerprinting in CSV exports
            }
        else:
            logger.warning("ipinfo.io returned incomplete data for %s: %s", ip, data)
    except requests.exceptions.Timeout:
        logger.warning("ipinfo.io timed out for %s", ip)
    except requests.exceptions.RequestException as e:
        logger.error("Geo request error for %s: %s", ip, e)
    return None


def geolocate_ips(raw_ips: list[str]) -> pd.DataFrame:
    """
    Cleans, validates, deduplicates, and geolocates a list of IP strings.
    Uses a small thread pool to keep the UI responsive while respecting rate limits.
    """
    # Deduplicate while preserving order; strip whitespace; validate format
    seen = {}
    invalid = []
    for raw in raw_ips:
        ip = raw.strip()
        if not ip:
            continue
        if not is_valid_ip(ip):
            invalid.append(ip)
            continue
        seen[ip] = None  # dict preserves insertion order in Python 3.7+

    ip_list = list(seen.keys())

    if invalid:
        st.sidebar.warning(
            f"⚠️ Skipped {len(invalid)} invalid entr{'y' if len(invalid) == 1 else 'ies'}: "
            + ", ".join(invalid[:5])
            + ("..." if len(invalid) > 5 else "")
        )

    if not ip_list:
        st.sidebar.error("No valid IPs to process.")
        return pd.DataFrame()

    # ipinfo.io free tier: 50,000 req/month (~1.6 req/sec sustained).
    # A 1.4s delay between requests keeps us well within limits.
    # We use 2 threads so the UI stays responsive without hammering the API.
    RATE_LIMIT_DELAY = 1.4  # seconds between requests per thread
    MAX_WORKERS = 2          # Conservative: 2 threads × 1 req/1.4s ≈ ~85 req/min

    results = []
    errors = []
    progress_bar = st.progress(0, text="Initialising...")
    completed = 0

    def fetch_with_delay(ip: str):
        result = geolocate_single_ip(ip)
        time.sleep(RATE_LIMIT_DELAY)
        return ip, result

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(fetch_with_delay, ip): ip for ip in ip_list}
            for future in as_completed(futures):
                ip = futures[future]
                completed += 1
                progress_pct = completed / len(ip_list)
                progress_bar.progress(
                    progress_pct,
                    text=f"Processing {completed}/{len(ip_list)}: {ip}",
                )
                try:
                    _, result = future.result()
                    if result:
                        results.append(result)
                    else:
                        errors.append(ip)
                except Exception as e:
                    logger.error("Unexpected error processing %s: %s", ip, e)
                    errors.append(ip)
    finally:
        # Always clear the progress bar, even if something goes wrong mid-run
        progress_bar.empty()

    if errors:
        st.sidebar.warning(
            f"⚠️ Failed to resolve {len(errors)} IP(s): "
            + ", ".join(errors[:5])
            + ("..." if len(errors) > 5 else "")
        )

    return pd.DataFrame(results)


# --- 5. EXECUTION ---
MAX_IPS = 500

if process_btn and ip_input:
    raw_ips = ip_input.split("\n")
    if len([ip for ip in raw_ips if ip.strip()]) > MAX_IPS:
        st.error(f"⚠️ Input exceeds {MAX_IPS} IPs. Please reduce your list size.")
        st.stop()
    st.session_state.df_ips = geolocate_ips(raw_ips)

# --- 6. DISPLAY ---
if st.session_state.df_ips is not None and not st.session_state.df_ips.empty:
    df = st.session_state.df_ips.copy()

    # Guard: only render map if the required columns actually exist
    required_cols = {"lat", "lon", "query", "risk_score"}
    if required_cols.issubset(df.columns):
        m = folium.Map(
            location=[df["lat"].mean(), df["lon"].mean()],
            zoom_start=2,
            tiles="CartoDB dark_matter",
        )

        for _, row in df.iterrows():
            score = row["risk_score"]
            if score >= 15:
                color = "red"
            elif score >= 5:
                color = "orange"
            else:
                color = "green"

            folium.CircleMarker(
                location=[row["lat"], row["lon"]],
                radius=10,
                color=color,
                fill=True,
                fill_color=color,
                popup=folium.Popup(
                    f"<b>IP:</b> {row['query']}<br>"
                    f"<b>City:</b> {row.get('city', 'N/A')}<br>"
                    f"<b>Country:</b> {row.get('country', 'N/A')}<br>"
                    f"<b>ISP:</b> {row.get('isp', 'N/A')}<br>"
                    f"<b>Risk Score:</b> {score}%",
                    max_width=250,
                ),
            ).add_to(m)

        st_folium(m, use_container_width=True, height=600)
    else:
        st.warning("Map skipped: geolocation data is incomplete.")

    st.write("### Intelligence Table")
    st.dataframe(df, use_container_width=True)  # use_container_width replaces width='stretch'

    st.download_button(
        label="⬇ Download as CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="breadcrumb_investigation.csv",
        mime="text/csv",
    )

elif st.session_state.df_ips is not None and st.session_state.df_ips.empty:
    st.info("No geolocation results were returned. Check your IP list and try again.")
