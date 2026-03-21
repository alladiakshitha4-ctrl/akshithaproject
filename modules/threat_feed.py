"""
pages/threat_feed.py - Live Threat Intelligence Feed
"""
import streamlit as st
from utils.threat_intel import get_live_threat_feed


def show_threat_feed():
    st.markdown("""
    <h2 style='color: #00d4aa; margin-bottom: 4px;'>🌐 Live Threat Intelligence Feed</h2>
    <p style='color: #7eb8d4; margin-bottom: 24px;'>Real-time phishing threat intelligence from multiple sources.</p>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style='display: flex; align-items: center; gap: 8px; margin-bottom: 20px;'>
        <span class='live-dot'></span>
        <span style='color: #ff3860; font-weight: 700; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px;'>LIVE FEED</span>
        <span style='color: #3a5a7a; font-size: 0.8em; margin-left: 8px;'>Updated continuously from global threat databases</span>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🔄 Refresh Feed"):
        st.rerun()

    threats = get_live_threat_feed()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""<div class='metric-box'>
            <div class='metric-value' style='color:#ff3860;'>{len(threats)}</div>
            <div class='metric-label'>Active Threats</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""<div class='metric-box'>
            <div class='metric-value' style='color:#ff9f43;'>4</div>
            <div class='metric-label'>New Today</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""<div class='metric-box'>
            <div class='metric-value' style='color:#00d4aa;'>3</div>
            <div class='metric-label'>Sources Active</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    for threat in threats:
        conf = threat["confidence"]
        conf_color = "#ff3860" if conf >= 90 else "#ff9f43" if conf >= 70 else "#ffd32a"
        type_icons = {"Phishing": "🎣", "Credential Theft": "🔑", "Redirect": "🔀", "Malware": "🦠"}
        t_icon = type_icons.get(threat["type"], "⚠️")

        st.markdown(f"""
        <div class='threat-item'>
            <div style='display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;'>
                <div style='display: flex; align-items: center; gap: 10px;'>
                    <span style='font-size: 1.3em;'>{t_icon}</span>
                    <div>
                        <div style='font-family: monospace; color: #ff8fa0; font-size: 0.82em; word-break: break-all;'>{threat['url']}</div>
                        <div style='display: flex; gap: 12px; margin-top: 3px;'>
                            <span style='color: #3a5a7a; font-size: 0.72em;'>Type: <span style='color: #ff9f43;'>{threat['type']}</span></span>
                            <span style='color: #3a5a7a; font-size: 0.72em;'>Target: <span style='color: #7eb8d4;'>{threat['target']}</span></span>
                            <span style='color: #3a5a7a; font-size: 0.72em;'>Reported: {threat['reported']}</span>
                        </div>
                    </div>
                </div>
                <div style='text-align: right;'>
                    <div style='color: {conf_color}; font-size: 1.4em; font-weight: 900; font-family: monospace;'>{conf}%</div>
                    <div style='color: #3a5a7a; font-size: 0.7em;'>confidence</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style='color: #3a5a7a; font-size: 0.75em; text-align: center;'>
        ⚠️ In production, connect to real APIs: 
        <a href='https://phishtank.org/api_info.php' target='_blank' style='color:#00d4aa;'>PhishTank</a> · 
        <a href='https://openphish.com' target='_blank' style='color:#00d4aa;'>OpenPhish</a> · 
        <a href='https://www.virustotal.com/gui/home/url' target='_blank' style='color:#00d4aa;'>VirusTotal</a>
    </div>
    """, unsafe_allow_html=True)
