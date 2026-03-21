"""
pages/scan_history.py - Scan History Page
"""
import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime

from utils.database import get_scan_history, get_email_history
from utils.pdf_export import generate_scan_history_report


def show_scan_history():
    user = st.session_state["user"]
    is_admin = user.get("role") == "admin"

    st.markdown("""
    <h2 style='color: #00d4aa; margin-bottom: 4px;'>📋 Scan History</h2>
    <p style='color: #7eb8d4; margin-bottom: 24px;'>Complete log of all URL and email scans with risk analysis and verdicts.</p>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔗  URL Scans", "📧  Email Scans"])

    with tab1:
        _show_url_history(user, is_admin)

    with tab2:
        _show_email_history(user, is_admin)


def _show_url_history(user, is_admin):
    uid = None if is_admin else user["id"]
    scans = get_scan_history(user_id=uid, limit=200)

    if not scans:
        st.info("No URL scans yet. Use the URL Scanner to analyze URLs.")
        return

    # Stats row
    total = len(scans)
    phishing = sum(1 for s in scans if s.get("verdict") == "Phishing")
    suspicious = sum(1 for s in scans if s.get("verdict") == "Suspicious")
    safe = sum(1 for s in scans if s.get("verdict") == "Safe")
    avg_risk = sum(s.get("risk_score", 0) for s in scans) / max(total, 1)

    cols = st.columns(5)
    for col, label, val, color in [
        (cols[0], "Total Scans", total, "#00d4aa"),
        (cols[1], "Phishing", phishing, "#ff3860"),
        (cols[2], "Suspicious", suspicious, "#ff9f43"),
        (cols[3], "Safe", safe, "#00e676"),
        (cols[4], "Avg Risk", f"{avg_risk:.1f}%", "#7eb8d4"),
    ]:
        with col:
            st.markdown(f"""
            <div class='metric-box'>
                <div class='metric-value' style='color:{color}; font-size: 1.6em;'>{val}</div>
                <div class='metric-label'>{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Filters
    col_f1, col_f2, col_f3 = st.columns([2, 1, 1])
    with col_f1:
        search = st.text_input("🔍 Search URLs", placeholder="Filter by URL...", key="hist_search")
    with col_f2:
        verdict_filter = st.selectbox("Verdict", ["All", "Phishing", "Suspicious", "Moderate Risk", "Safe"], key="hist_verdict")
    with col_f3:
        limit = st.selectbox("Show", [25, 50, 100, 200], key="hist_limit")

    # Apply filters
    filtered = scans
    if search:
        filtered = [s for s in filtered if search.lower() in s.get("url", "").lower()]
    if verdict_filter != "All":
        filtered = [s for s in filtered if s.get("verdict") == verdict_filter]
    filtered = filtered[:limit]

    # Export button
    col_exp1, col_exp2 = st.columns([3, 1])
    with col_exp2:
        if st.button("📥 Export PDF Report", use_container_width=True, key="export_history"):
            export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
            os.makedirs(export_dir, exist_ok=True)
            fname = f"phishguard_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            fpath = os.path.join(export_dir, fname)
            try:
                generate_scan_history_report(filtered, user["username"], fpath)
                with open(fpath, "rb") as f:
                    st.download_button("💾 Save PDF", f.read(), fname, "application/pdf", key="dl_hist")
            except Exception as e:
                st.error(f"Export error: {e}")

    # Scan list
    verdict_icon = {"Phishing": "🚨", "Suspicious": "⚠️", "Moderate Risk": "🟡", "Safe": "✅"}
    verdict_colors = {"Phishing": "#ff3860", "Suspicious": "#ff9f43", "Moderate Risk": "#ffd32a", "Safe": "#00e676"}

    st.markdown(f"**Showing {len(filtered)} of {total} scans**")
    for scan in filtered:
        verdict = scan.get("verdict", "Unknown")
        risk = scan.get("risk_score", 0)
        color = verdict_colors.get(verdict, "#aaa")
        icon = verdict_icon.get(verdict, "❓")
        url = scan.get("url", "")
        scanned_at = str(scan.get("scanned_at", ""))[:16]
        username = scan.get("username", "")

        st.markdown(f"""
        <div style='display: grid; grid-template-columns: 32px 1fr auto auto auto; gap: 12px;
                    align-items: center; padding: 10px 16px;
                    background: rgba(13,33,55,0.5); border: 1px solid rgba(255,255,255,0.05);
                    border-left: 3px solid {color}40; border-radius: 0 8px 8px 0; margin: 3px 0;
                    transition: all 0.2s;'>
            <span style='font-size: 1.1em;'>{icon}</span>
            <span style='font-family: monospace; color: #7eb8d4; font-size: 0.82em; word-break: break-all;'
                  title='{url}'>{url[:70]}{'...' if len(url) > 70 else ''}</span>
            {'<span style="color: #3a5a7a; font-size: 0.72em;">' + username + '</span>' if is_admin else ''}
            <span style='color: #3a5a7a; font-size: 0.75em; white-space: nowrap;'>{scanned_at}</span>
            <span style='color: {color}; font-weight: 800; font-family: monospace; min-width: 48px; text-align: right;'>{risk:.0f}%</span>
        </div>
        """, unsafe_allow_html=True)


def _show_email_history(user, is_admin):
    uid = None if is_admin else user["id"]
    scans = get_email_history(user_id=uid, limit=100)

    if not scans:
        st.info("No email scans yet. Use the Email Detector to analyze emails.")
        return

    verdict_colors = {"Phishing Email": "#ff3860", "Suspicious Email": "#ff9f43",
                      "Moderate Risk": "#ffd32a", "Likely Safe": "#00e676"}

    for scan in scans:
        verdict = scan.get("verdict", "Unknown")
        risk = scan.get("risk_score", 0)
        color = verdict_colors.get(verdict, "#aaa")
        subject = scan.get("email_subject", "No subject")[:60]
        scanned_at = str(scan.get("scanned_at", ""))[:16]

        st.markdown(f"""
        <div style='display: flex; gap: 12px; align-items: center; padding: 10px 16px;
                    background: rgba(13,33,55,0.5); border: 1px solid rgba(255,255,255,0.05);
                    border-left: 3px solid {color}40; border-radius: 0 8px 8px 0; margin: 3px 0;'>
            <span style='flex: 1; color: #e0f0ff; font-size: 0.85em;'>📧 {subject}</span>
            <span style='color: {color}; font-size: 0.8em; font-weight: 700;'>{verdict}</span>
            <span style='color: #3a5a7a; font-size: 0.75em; white-space: nowrap;'>{scanned_at}</span>
            <span style='color: {color}; font-weight: 800; font-family: monospace; min-width: 48px; text-align: right;'>{risk:.0f}%</span>
        </div>
        """, unsafe_allow_html=True)
