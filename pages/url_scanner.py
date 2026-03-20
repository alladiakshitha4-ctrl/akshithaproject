"""
pages/url_scanner.py - URL Phishing Detection Page
"""
import streamlit as st
import os
from datetime import datetime

from utils.ml_model import predict_url
from utils.threat_intel import get_threat_intelligence_summary
from utils.database import save_url_scan
from utils.pdf_export import generate_url_report


def show_url_scanner():
    user = st.session_state["user"]
    model = st.session_state["model"]
    scaler = st.session_state["scaler"]

    st.markdown("""
    <h2 style='color: #00d4aa; margin-bottom: 4px;'>🔍 URL Phishing Scanner</h2>
    <p style='color: #7eb8d4; margin-bottom: 24px;'>Analyze any URL using AI and 22+ security features to detect phishing threats.</p>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([4, 1])
    with col1:
        url_input = st.text_input(
            "Enter URL to scan",
            placeholder="https://example.com  or  http://suspicious-site.tk/login",
            label_visibility="collapsed",
            key="url_input_field"
        )
    with col2:
        scan_clicked = st.button("🔍  Scan Now", use_container_width=True)

    with st.expander("📋  Bulk URL Scan (multiple URLs)"):
        bulk_text = st.text_area(
            "Enter URLs (one per line)",
            height=120,
            placeholder="https://site1.com\nhttp://suspicious.tk/login\nhttps://another.com",
        )
        bulk_btn = st.button("🚀  Scan All URLs", key="bulk_scan")

    if scan_clicked and url_input:
        with st.spinner("AI analyzing URL..."):
            result = predict_url(url_input, model, scaler)
            ti = get_threat_intelligence_summary(url_input)
            save_url_scan(user["id"], url_input, result["risk_score"], result["verdict"], result["features"])
        _display_scan_result(result, ti, user)

    if bulk_btn and bulk_text:
        urls = [u.strip() for u in bulk_text.strip().splitlines() if u.strip()]
        if urls:
            st.markdown(f"### Scanning {len(urls)} URLs...")
            results = []
            progress = st.progress(0)
            for i, url in enumerate(urls):
                r = predict_url(url, model, scaler)
                save_url_scan(user["id"], url, r["risk_score"], r["verdict"], r["features"])
                results.append(r)
                progress.progress((i + 1) / len(urls))
            progress.empty()
            _display_bulk_results(results)


def _display_scan_result(result, ti, user):
    verdict = result["verdict"]
    risk = result["risk_score"]
    features = result["features"]

    color_map = {
        "Phishing":      ("#ff3860", "risk-critical", "🚨"),
        "Suspicious":    ("#ff9f43", "risk-high",     "⚠️"),
        "Moderate Risk": ("#ffd32a", "risk-medium",   "🟡"),
        "Safe":          ("#00e676", "risk-low",       "✅"),
    }
    color, meter_cls, icon = color_map.get(verdict, ("#aaa", "risk-low", "❓"))

    st.markdown(f"""
    <div class='phish-card' style='border-color: {color}40;'>
        <div style='display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px;'>
            <div style='flex:1; min-width:200px;'>
                <div style='color:#3a5a7a; font-size:0.7em; text-transform:uppercase; letter-spacing:2px; margin-bottom:6px;'>Analysis Result</div>
                <div style='font-size:2em; font-weight:800; color:{color};'>{icon} {verdict}</div>
                <div style='font-family:monospace; color:#7eb8d4; font-size:0.85em; margin-top:6px; word-break:break-all;'>{result['url'][:80]}{'...' if len(result['url'])>80 else ''}</div>
            </div>
            <div style='text-align:center; min-width:120px;'>
                <div style='font-size:3.5em; font-weight:900; color:{color}; font-family:monospace; line-height:1;'>{risk:.0f}%</div>
                <div style='color:#3a5a7a; font-size:0.7em; text-transform:uppercase; letter-spacing:1px;'>Risk Score</div>
            </div>
        </div>
        <div style='margin-top:16px;'>
            <div class='risk-meter-container'>
                <div class='risk-meter-fill {meter_cls}' style='width:{risk}%;'></div>
            </div>
            <div style='display:flex; justify-content:space-between; color:#3a5a7a; font-size:0.7em; margin-top:4px;'>
                <span>0% Safe</span><span>50% Suspicious</span><span>100% Critical</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1.2, 1, 1])

    with col1:
        st.markdown("**🚨 Risk Factors**")
        risk_factors = result.get("risk_factors", [])
        if risk_factors:
            for f in risk_factors:
                st.markdown(f"<div class='risk-factor'>⚠ {f}</div>", unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style='background:rgba(0,230,118,0.05); border-left:3px solid #00e676;
                        padding:10px 14px; border-radius:0 6px 6px 0; color:#80ffc0;'>
                ✓ No significant risk factors detected
            </div>
            """, unsafe_allow_html=True)

    with col2:
        st.markdown("**🔬 URL Features**")
        feature_display = [
            ("🔗 URL Length",       features["url_length"],              features["url_length"] > 100),
            ("🔒 HTTPS",            "YES" if features["is_https"] else "NO",  not features["is_https"]),
            ("📍 IP Address",       "YES" if features["has_ip_address"] else "NO", features["has_ip_address"]),
            ("🌐 Subdomains",       features["num_subdomains"],           features["num_subdomains"] > 2),
            ("🔑 Phish Keywords",   features["phishing_keyword_count"],   features["phishing_keyword_count"] > 0),
            ("🏷️ Suspicious TLD",  "YES" if features["suspicious_tld"] else "NO", features["suspicious_tld"]),
            ("⚡ Brand Squatting",  "YES" if features["brand_squatting"] else "NO", features["brand_squatting"]),
            ("🔀 Redirects",        "YES" if features["has_redirect"] else "NO",   features["has_redirect"]),
            ("✂️ Shortened URL",    "YES" if features["is_shortened"] else "NO",   features["is_shortened"]),
        ]
        for label, val, is_risky in feature_display:
            fc = "#ff8fa0" if is_risky else "#80ffc0"
            fi = "⚠" if is_risky else "✓"
            st.markdown(f"""
            <div style='display:flex; justify-content:space-between; padding:4px 8px;
                        border-bottom:1px solid rgba(255,255,255,0.04); font-size:0.82em;'>
                <span style='color:#7eb8d4;'>{label}</span>
                <span style='color:{fc}; font-weight:700;'>{fi} {val}</span>
            </div>""", unsafe_allow_html=True)

    with col3:
        st.markdown("**🌐 Threat Intelligence**")
        rep = ti.get("reputation", {})
        dom_age = ti.get("domain_age", {})
        trust = rep.get("trust_score", "N/A")
        threat_lvl = rep.get("threat_level", "Unknown")
        lvl_colors = {"LOW": "#00e676", "MEDIUM": "#ffd32a", "HIGH": "#ff9f43", "MINIMAL": "#00e676"}
        lvl_color = lvl_colors.get(threat_lvl, "#aaa")

        st.markdown(f"""
        <div class='phish-card' style='padding:14px; margin:0;'>
            <div style='display:flex; justify-content:space-between; margin-bottom:10px;'>
                <span style='color:#7eb8d4; font-size:0.8em;'>Trust Score</span>
                <span style='color:#00d4aa; font-size:1.3em; font-weight:800; font-family:monospace;'>{trust}/100</span>
            </div>
            <div style='display:flex; justify-content:space-between; margin-bottom:10px;'>
                <span style='color:#7eb8d4; font-size:0.8em;'>Threat Level</span>
                <span style='color:{lvl_color}; font-weight:700;'>⬤ {threat_lvl}</span>
            </div>
            <div style='display:flex; justify-content:space-between; margin-bottom:10px;'>
                <span style='color:#7eb8d4; font-size:0.8em;'>Domain Age</span>
                <span style='color:#e0f0ff; font-size:0.85em;'>{f"{dom_age.get('age_days')} days" if dom_age.get('age_days') else "Unknown"}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        for note in rep.get("notes", [])[:3]:
            st.markdown(f"<div style='font-size:0.75em; color:#ff9f43; padding:2px 0;'>⚠ {note}</div>", unsafe_allow_html=True)

        if dom_age.get("risk_note"):
            st.markdown(f"<div style='font-size:0.75em; color:#7eb8d4; padding:4px 0;'>{dom_age['risk_note']}</div>", unsafe_allow_html=True)

    st.markdown("---")
    col_prev, col_export = st.columns([2, 1])

    with col_prev:
        st.markdown("**🖼️ Website Preview Analyzer**")
        if verdict in ("Phishing", "Suspicious"):
            st.markdown(f"""
            <div style='background:rgba(255,56,96,0.08); border:1px solid rgba(255,56,96,0.3);
                        border-radius:10px; padding:16px; color:#ff8fa0;'>
                🚫 <strong>Preview Blocked</strong> — URL flagged as {verdict}.<br>
                <span style='font-size:0.85em; color:#7eb8d4;'>Loading this URL could expose your system to threats.</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style='background:rgba(0,212,170,0.05); border:1px solid rgba(0,212,170,0.2);
                        border-radius:10px; padding:16px;'>
                ✅ <strong>URL appears safe for preview</strong><br>
                <a href="{result['url']}" target="_blank" style='color:#00d4aa; font-size:0.9em;'>
                    🔗 Open in new tab (manual verification)
                </a>
            </div>
            """, unsafe_allow_html=True)

    with col_export:
        st.markdown("**📄 Export Report**")
        if st.button("📥 Download PDF Report", use_container_width=True):
            export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
            os.makedirs(export_dir, exist_ok=True)
            fname = f"phishguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            fpath = os.path.join(export_dir, fname)
            try:
                generate_url_report(result, user["username"], fpath)
                with open(fpath, "rb") as f:
                    st.download_button(
                        label="💾 Save PDF",
                        data=f.read(),
                        file_name=fname,
                        mime="application/pdf",
                        use_container_width=True,
                    )
            except Exception as e:
                st.error(f"PDF error: {e}")


def _display_bulk_results(results):
    st.markdown("### 📊 Bulk Scan Results")

    total = len(results)
    phishing = sum(1 for r in results if r["verdict"] == "Phishing")
    suspicious = sum(1 for r in results if r["verdict"] == "Suspicious")
    safe = sum(1 for r in results if r["verdict"] == "Safe")

    col1, col2, col3, col4 = st.columns(4)
    for col, label, val, color in [
        (col1, "Total Scanned", total,     "#00d4aa"),
        (col2, "Phishing",      phishing,  "#ff3860"),
        (col3, "Suspicious",    suspicious,"#ff9f43"),
        (col4, "Safe",          safe,      "#00e676"),
    ]:
        with col:
            st.markdown(f"""
            <div class='metric-box'>
                <div class='metric-value' style='color:{color};'>{val}</div>
                <div class='metric-label'>{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    verdict_icon   = {"Phishing": "🚨", "Suspicious": "⚠️", "Moderate Risk": "🟡", "Safe": "✅"}
    verdict_colors = {"Phishing": "#ff3860", "Suspicious": "#ff9f43", "Moderate Risk": "#ffd32a", "Safe": "#00e676"}

    for r in results:
        color = verdict_colors.get(r["verdict"], "#aaa")
        icon  = verdict_icon.get(r["verdict"], "❓")
        st.markdown(f"""
        <div style='display:flex; align-items:center; gap:16px; padding:10px 16px;
                    background:rgba(13,33,55,0.6); border:1px solid rgba(255,255,255,0.05);
                    border-left:3px solid {color}; border-radius:0 8px 8px 0; margin:4px 0;'>
            <span style='font-size:1.3em;'>{icon}</span>
            <span style='font-family:monospace; color:#7eb8d4; font-size:0.85em; flex:1; word-break:break-all;'>{r['url'][:80]}</span>
            <span style='color:{color}; font-weight:700; font-size:0.9em; white-space:nowrap;'>{r['verdict']}</span>
            <span style='color:{color}; font-family:monospace; font-weight:800; min-width:50px; text-align:right;'>{r['risk_score']:.0f}%</span>
        </div>
        """, unsafe_allow_html=True)