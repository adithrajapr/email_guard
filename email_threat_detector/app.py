"""Streamlit dashboard:  streamlit run app.py"""
import json
import pandas as pd
import streamlit as st
from analyzer import analyze, report_text

st.set_page_config(page_title="Email Threat Detector", page_icon="🛡️", layout="wide")
st.title("🛡️ AI Email Threat & Scam Detector")
st.caption("Header forensics + ML scam detection + URL/attachment analysis + route tracing")

up = st.file_uploader("Upload an .eml file", type=["eml"])
samples = {"-": None, "Bank phishing": "samples/01_bank_phishing.eml", "Hinglish lottery scam": "samples/02_hinglish_lottery_scam.eml",
           "Malicious invoice": "samples/03_malicious_invoice.eml", "Legitimate email": "samples/04_legit_meeting.eml"}
choice = st.selectbox("...or try a sample", list(samples))
raw = up.read() if up else (open(samples[choice], "rb").read() if samples[choice] else None)

if raw:
    r = analyze(raw)
    color = {"LIKELY SAFE": "🟢", "SUSPICIOUS": "🟠"}.get(r["verdict"], "🔴")
    c1, c2 = st.columns([1, 2])
    c1.metric("Risk score", f"{r['risk_score']}/100")
    c1.progress(r["risk_score"] / 100)
    c2.subheader(f"{color} {r['verdict']}")
    c2.write(f"**From:** {r['from']}  \n**Subject:** {r['subject']}  \n**Date:** {r['date']}")

    st.subheader("Score breakdown")
    st.bar_chart(pd.Series(r["breakdown"]))

    st.subheader("Why was it flagged?")
    for x in r["reasons"] or ["No suspicious indicators found."]:
        st.write("• " + x)
    if r["top_words"]:
        st.write("**Top scam-indicating words (ML explainability):** " + ", ".join(f"`{w}`" for w, _ in r["top_words"]))

    t1, t2, t3 = st.tabs(["🔗 URLs", "📎 Attachments", "🗺️ Route / Geolocation"])
    with t1:
        st.dataframe(pd.DataFrame(r["urls"]) if r["urls"] else pd.DataFrame({"info": ["No URLs"]}), use_container_width=True)
    with t2:
        st.dataframe(pd.DataFrame(r["attachments"]) if r["attachments"] else pd.DataFrame({"info": ["No attachments"]}), use_container_width=True)
    with t3:
        st.dataframe(pd.DataFrame(r["route"]) if r["route"] else pd.DataFrame({"info": ["No hops found"]}), use_container_width=True)
        pts = [h for h in r["route"] if h["lat"] is not None]
        if pts:
            st.map(pd.DataFrame(pts)[["lat", "lon"]])
        else:
            st.info("Add MaxMind GeoLite2-City.mmdb to ./data/ to see the map.")

    st.download_button("⬇️ Forensic report (.txt)", report_text(r), "forensic_report.txt")
    st.download_button("⬇️ Report (.json)", json.dumps(r, indent=2), "report.json")
