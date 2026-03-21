"""
pages/email_detector.py - Email Phishing Detection
"""
import streamlit as st
from utils.ml_model import analyze_email
from utils.database import save_email_scan


def show_email_detector():
    user = st.session_state["user"]

    st.markdown("""
    <h2 style='color: #00d4aa; margin-bottom: 4px;'>📧 Email Phishing Detector</h2>
    <p style='color: #7eb8d4; margin-bottom: 24px;'>Analyze email content to detect phishing attempts, suspicious phrases, and malicious links.</p>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1.5, 1])

    with col1:
        st.markdown("**📝 Email Details**")
        sender = st.text_input("Sender Email", placeholder="noreply@paypal-secure.tk", key="email_sender")
        subject = st.text_input("Email Subject", placeholder="URGENT: Verify your account immediately!", key="email_subject")
        body = st.text_area("Email Body", height=250,
            placeholder="Dear Customer,\n\nWe have detected unusual activity on your account. Click here to verify your identity immediately or your account will be suspended.\n\nhttp://paypal-secure.tk/verify?cmd=login\n\nThank you,\nSecurity Team",
            key="email_body")

        if st.button("🔍  Analyze Email", use_container_width=True):
            if subject or body:
                with st.spinner("Analyzing email content..."):
                    result = analyze_email(subject, body, sender)
                    save_email_scan(user["id"], subject, result["risk_score"],
                                    result["verdict"], result["indicators"])
                _show_email_result(result)
            else:
                st.warning("Please enter at least a subject or email body to analyze.")

    with col2:
        st.markdown("**🎯 Common Phishing Indicators**")
        indicators_info = [
            ("🔴", "Urgent action required", "Pressure tactics to act fast"),
            ("🔴", "Verify your account", "Credential harvesting attempt"),
            ("🔴", "Account suspended", "Fear-based manipulation"),
            ("🟠", "Dear Customer", "Impersonal greeting (not your name)"),
            ("🟠", "Click here immediately", "Suspicious call-to-action"),
            ("🟠", "Winner / Prize / Free", "Social engineering lure"),
            ("🟡", "Unusual activity", "Vague security claim"),
            ("🟡", "Password expired", "Fake urgency"),
            ("🟡", "Final warning", "Pressure tactic"),
        ]
        for icon, phrase, desc in indicators_info:
            st.markdown(f"""
            <div style='display: flex; gap: 10px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,0.04);'>
                <span style='font-size: 1em;'>{icon}</span>
                <div>
                    <div style='color: #e0f0ff; font-size: 0.82em; font-weight: 600;'>"{phrase}"</div>
                    <div style='color: #3a5a7a; font-size: 0.72em;'>{desc}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("**📋 Quick Test Templates**")
        if st.button("🚨 Load Phishing Example", use_container_width=True):
            st.session_state["email_sender"] = "security@paypal-support.tk"
            st.session_state["email_subject"] = "URGENT: Your PayPal account has been suspended!"
            st.session_state["email_body"] = "Dear Customer,\n\nWe have detected unauthorized access to your PayPal account. You must verify your account immediately or it will be permanently suspended.\n\nClick here to verify: http://paypal-secure-verify.tk/login?cmd=verify\n\nAct NOW — Final Warning!\n\nPayPal Security Team"
            st.rerun()

        if st.button("✅ Load Safe Example", use_container_width=True):
            st.session_state["email_sender"] = "updates@github.com"
            st.session_state["email_subject"] = "Your GitHub monthly digest"
            st.session_state["email_body"] = "Hi there,\n\nHere's your monthly summary of activity on GitHub. You had 42 commits, 3 pull requests merged, and 5 issues closed this month.\n\nVisit your dashboard: https://github.com/dashboard\n\nThanks,\nThe GitHub Team"
            st.rerun()


def _show_email_result(result):
    verdict = result["verdict"]
    risk = result["risk_score"]
    indicators = result.get("indicators", [])
    suspicious_urls = result.get("suspicious_urls", [])

    verdict_cfg = {
        "Phishing Email": ("#ff3860", "🚨", "rgba(255,56,96,0.08)", "rgba(255,56,96,0.3)"),
        "Suspicious Email": ("#ff9f43", "⚠️", "rgba(255,159,67,0.08)", "rgba(255,159,67,0.3)"),
        "Moderate Risk": ("#ffd32a", "🟡", "rgba(255,211,42,0.06)", "rgba(255,211,42,0.3)"),
        "Likely Safe": ("#00e676", "✅", "rgba(0,230,118,0.05)", "rgba(0,230,118,0.3)"),
    }
    color, icon, bg, border = verdict_cfg.get(verdict, ("#aaa", "❓", "rgba(0,0,0,0.1)", "rgba(100,100,100,0.3)"))

    st.markdown(f"""
    <div style='background: {bg}; border: 1px solid {border}; border-radius: 12px; padding: 20px; margin-top: 20px;'>
        <div style='display: flex; justify-content: space-between; align-items: center;'>
            <div>
                <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase; letter-spacing: 2px;'>Email Analysis Result</div>
                <div style='font-size: 1.8em; font-weight: 800; color: {color}; font-family: Exo 2;'>{icon} {verdict}</div>
            </div>
            <div style='text-align: center;'>
                <div style='font-size: 3em; font-weight: 900; color: {color}; font-family: monospace; line-height: 1;'>{risk:.0f}%</div>
                <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase;'>Risk Score</div>
            </div>
        </div>
        <div style='background: rgba(0,0,0,0.3); border-radius: 6px; height: 10px; margin-top: 16px; overflow: hidden;'>
            <div style='height: 100%; width: {risk}%; background: {color}; border-radius: 6px; transition: width 0.8s;'></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if indicators:
        st.markdown("**🚩 Detected Phishing Phrases**")
        cols = st.columns(2)
        for i, ind in enumerate(indicators):
            with cols[i % 2]:
                st.markdown(f"""
                <div style='background: rgba(255,56,96,0.06); border: 1px solid rgba(255,56,96,0.2);
                            border-radius: 8px; padding: 8px 12px; margin: 4px 0;
                            display: flex; justify-content: space-between; align-items: center;'>
                    <span style='color: #ff8fa0; font-size: 0.82em;'>⚠ "{ind['phrase']}"</span>
                    <span style='color: #ff3860; font-weight: 700; font-family: monospace; font-size: 0.85em;'>+{ind['weight']}pts</span>
                </div>
                """, unsafe_allow_html=True)

    if suspicious_urls:
        st.markdown("**🔗 Suspicious URLs Found in Email**")
        for url in suspicious_urls:
            st.markdown(f"""
            <div style='background: rgba(255,56,96,0.08); border-left: 3px solid #ff3860;
                        padding: 8px 14px; margin: 4px 0; border-radius: 0 8px 8px 0;
                        font-family: monospace; color: #ff8fa0; font-size: 0.85em; word-break: break-all;'>
                🔗 {url}
            </div>
            """, unsafe_allow_html=True)

    # Recommendations
    st.markdown("**🛡️ Recommendations**")
    if verdict in ("Phishing Email", "Suspicious Email"):
        recs = [
            "Do NOT click any links in this email.",
            "Do NOT download any attachments.",
            "Mark as spam/phishing and delete immediately.",
            "Report to your IT/security team.",
            "If you already clicked, change passwords immediately.",
        ]
        for rec in recs:
            st.markdown(f"<div class='risk-factor'>🚫 {rec}</div>", unsafe_allow_html=True)
    else:
        st.success("✅ Email appears legitimate. Always verify sender identity for sensitive requests.")
