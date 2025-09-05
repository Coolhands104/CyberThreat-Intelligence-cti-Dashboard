# Cyber Threat Intelligence (CTI) Dashboard — Streamlit app
# ----------------------------------------------------------
# Features
# - Look up IPs, Domains, URLs, and File Hashes against VirusTotal, AbuseIPDB, and AlienVault OTX
# - Simple risk summary + raw JSON evidence
# - Downloadable JSON report
#
# WARNING: Keys are hardcoded here only for demo/submission.
#          Do NOT commit real API keys to public repositories.
# ----------------------------------------------------------

import base64
import json
import ipaddress
import re
from urllib.parse import urlparse
from datetime import datetime

import requests
import pandas as pd
import streamlit as st

# --------------- 🔑 API KEYS (embed here) --------------- #
VT_API_KEY = "YOUR_KEY"
ABUSEIPDB_API_KEY = "YOUR_KEY"
OTX_API_KEY = "YOUR_KEY"  # optional

# --------------- Helpers --------------- #

def indicator_type(ioc: str) -> str:
    ioc = ioc.strip()
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except Exception:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]{32}", ioc):
        return "md5"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", ioc):
        return "sha1"
    if re.fullmatch(r"[A-Fa-f0-9]{64}", ioc):
        return "sha256"
    parsed = urlparse(ioc if re.match(r"^\w+://", ioc) else f"http://{ioc}")
    if parsed.scheme and parsed.netloc and "." in parsed.netloc:
        return "url" if re.match(r"^\w+://", ioc) else "domain"
    return "unknown"

# --------------- API Clients --------------- #

@st.cache_data(ttl=600, show_spinner=False)
def vt_lookup_ip(ip: str):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=20)
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}", "body": r.text}
    data = r.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "type": "ip",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "raw": data,
    }

@st.cache_data(ttl=600, show_spinner=False)
def vt_lookup_domain(domain: str):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=20)
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}", "body": r.text}
    data = r.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "type": "domain",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "raw": data,
    }

@st.cache_data(ttl=600, show_spinner=False)
def vt_lookup_url(url_value: str):
    url_id = base64.urlsafe_b64encode(url_value.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=20)
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}", "body": r.text}
    data = r.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "type": "url",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "raw": data,
    }

@st.cache_data(ttl=600, show_spinner=False)
def vt_lookup_hash(file_hash: str):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=20)
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}", "body": r.text}
    data = r.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "type": "hash",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "raw": data,
    }

@st.cache_data(ttl=600, show_spinner=False)
def abuseipdb_check_ip(ip: str):
    if not ABUSEIPDB_API_KEY:
        return {"error": "Missing AbuseIPDB API key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    r = requests.get(url, params=params, headers=headers, timeout=20)
    if r.status_code != 200:
        return {"error": f"AbuseIPDB HTTP {r.status_code}", "body": r.text}
    data = r.json().get("data", {})
    return {
        "source": "AbuseIPDB",
        "type": "ip",
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "raw": r.json(),
    }

@st.cache_data(ttl=600, show_spinner=False)
def otx_ip_general(ip: str):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code != 200:
        return {"error": f"OTX HTTP {r.status_code}", "body": r.text}
    data = r.json()
    pulses = data.get("pulse_info", {}).get("count", 0)
    return {
        "source": "AlienVault OTX",
        "type": "ip",
        "pulses": pulses,
        "asn": data.get("asn"),
        "geo": data.get("geo"),
        "raw": data,
    }

# --------------- Risk Scoring --------------- #

def compute_risk(findings: list[dict]) -> tuple[str, int]:
    score = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        if f.get("source") == "VirusTotal":
            score += int(f.get("malicious", 0)) * 10 + int(f.get("suspicious", 0)) * 5
        if f.get("source") == "AbuseIPDB":
            score += int(f.get("abuse_confidence", 0))
        if f.get("source") == "AlienVault OTX":
            score += int(f.get("pulses", 0)) * 2
    if score >= 80:
        return "High", score
    if score >= 30:
        return "Medium", score
    return "Low", score

# --------------- Streamlit UI --------------- #

st.set_page_config(page_title="CTI Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Cyber Threat Intelligence Dashboard")
st.caption("Lookup IPs, domains, URLs and hashes against public threat feeds.")

col1, col2 = st.columns([2, 1])
with col1:
    st.subheader("Indicator Lookup")
    ioc_value = st.text_input("Enter IP / Domain / URL / Hash", placeholder="e.g., 8.8.8.8 or example.com or sha256...")
    auto_type = indicator_type(ioc_value) if ioc_value else "unknown"
    itype = st.selectbox("Indicator type", ["auto", "ip", "domain", "url", "md5", "sha1", "sha256"], index=0)
    run = st.button("🔎 Lookup", use_container_width=True)

with col2:
    st.subheader("About")
    st.write("This dashboard queries VirusTotal, AbuseIPDB, and OTX. Results are cached for 10 minutes.")
    st.write("Risk score is a simple heuristic for demo purposes.")

results = []

if run and ioc_value:
    resolved_type = auto_type if itype == "auto" else itype

    with st.spinner(f"Querying feeds for {resolved_type}…"):
        try:
            if resolved_type == "ip":
                results.append(vt_lookup_ip(ioc_value))
                results.append(abuseipdb_check_ip(ioc_value))
                results.append(otx_ip_general(ioc_value))
            elif resolved_type == "domain":
                results.append(vt_lookup_domain(ioc_value))
            elif resolved_type == "url":
                results.append(vt_lookup_url(ioc_value))
            elif resolved_type in {"md5", "sha1", "sha256"}:
                results.append(vt_lookup_hash(ioc_value))
            else:
                st.error("Unrecognized indicator. Please choose the correct type.")
        except Exception as e:
            st.error(f"Lookup failed: {e}")

    clean_results = [r for r in results if isinstance(r, dict) and not r.get("error")]
    errors = [r for r in results if isinstance(r, dict) and r.get("error")]

    if clean_results:
        risk_label, risk_score = compute_risk(clean_results)
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("Risk", risk_label)
        with m2:
            st.metric("Score", risk_score)
        with m3:
            st.metric("Sources", len(clean_results))

        t1, t2 = st.tabs(["Summary", "Raw Evidence"])
        with t1:
            rows = []
            for r in clean_results:
                if r.get("source") == "VirusTotal":
                    rows.append({
                        "Source": r.get("source"),
                        "Type": r.get("type"),
                        "Malicious": r.get("malicious"),
                        "Suspicious": r.get("suspicious"),
                        "Harmless": r.get("harmless"),
                        "Undetected": r.get("undetected"),
                    })
                elif r.get("source") == "AbuseIPDB":
                    rows.append({
                        "Source": r.get("source"),
                        "Type": r.get("type"),
                        "AbuseConfidence": r.get("abuse_confidence"),
                        "TotalReports": r.get("total_reports"),
                        "Country": r.get("country"),
                    })
                elif r.get("source") == "AlienVault OTX":
                    rows.append({
                        "Source": r.get("source"),
                        "Type": r.get("type"),
                        "Pulses": r.get("pulses"),
                    })
            if rows:
                df = pd.DataFrame(rows)
                st.dataframe(df, use_container_width=True)

        with t2:
            for r in clean_results:
                with st.expander(f"{r.get('source')} raw JSON"):
                    st.json(r.get("raw", {}))

        report = {
            "indicator": ioc_value,
            "type": resolved_type,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "risk": {"label": risk_label, "score": risk_score},
            "findings": clean_results,
            "errors": errors,
        }
        st.download_button(
            label="⬇️ Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"cti_report_{resolved_type}.json",
            mime="application/json",
        )

    if errors:
        st.warning("Some sources returned errors. Expand to see details below.")
        for e in errors:
            with st.expander(f"{e.get('error')}"):
                st.code(e.get("body", ""))

elif run and not ioc_value:
    st.error("Please enter an indicator to look up.")

st.markdown("---")
st.caption("Educational demo. Do not push real API keys to public GitHub repos.")

