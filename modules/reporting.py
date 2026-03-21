"""
pages/reporting.py - Phishing Report Submission
"""
import streamlit as st
from utils.database import submit_report, get_reports


def show_reporting():
    user = st.session_state["user"]

    st.markdown("""
    <h2 style='color: #00d4aa; margin-bottom: 4px;'>🚨 Report a Phishing Threat</h2>
    <p style='color: #7eb8d4; margin-bottom: 24px;'>Submit suspicious URLs to help protect the community from phishing attacks.</p>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1.4, 1])

    with col1:
        st.markdown("**📝 Submit Phishing Report**")

        with st.form("report_form"):
            url = st.text_input("Suspicious URL *", placeholder="http://phishing-site.tk/login")
            reason = st.selectbox("Report Reason *", [
                "Phishing website — stealing credentials",
                "Fake login page — brand impersonation",
                "Malware distribution site",
                "Email phishing link",
                "Cryptocurrency scam",
                "Fake tech support",
                "Romance/social engineering scam",
                "Other suspicious activity",
            ])
            additional = st.text_area("Additional Details",
                placeholder="Describe how you encountered this URL, what happened, any additional context...",
                height=120)

            col_a, col_b = st.columns(2)
            with col_a:
                submitted = st.form_submit_button("🚨 Submit Report", use_container_width=True)
            with col_b:
                st.form_submit_button("🔍 Scan First", use_container_width=True)

        if submitted:
            if not url:
                st.error("Please enter a URL to report.")
            else:
                submit_report(user["id"], url, reason, additional)
                st.success("✅ Report submitted successfully! Thank you for helping protect the community.")

    with col2:
        st.markdown("**📊 Your Reports**")
        reports = get_reports()
        user_reports = [r for r in reports if r.get("user_id") == user["id"]]

        if not user_reports:
            st.info("You haven't submitted any reports yet.")
        else:
            status_colors = {"pending": "#ff9f43", "reviewed": "#00d4aa", "confirmed": "#ff3860", "dismissed": "#3a5a7a"}
            for r in user_reports[:10]:
                status = r.get("status", "pending")
                color = status_colors.get(status, "#aaa")
                url_d = str(r.get("url", ""))[:50]
                st.markdown(f"""
                <div style='padding: 10px 14px; background: rgba(13,33,55,0.5);
                            border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; margin: 4px 0;'>
                    <div style='font-family: monospace; color: #7eb8d4; font-size: 0.8em;'>{url_d}...</div>
                    <div style='display: flex; justify-content: space-between; margin-top: 4px;'>
                        <span style='color: #3a5a7a; font-size: 0.72em;'>{str(r.get("reported_at",""))[:10]}</span>
                        <span style='color: {color}; font-size: 0.72em; font-weight: 700; text-transform: uppercase;'>⬤ {status}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class='phish-card' style='padding: 14px;'>
            <div style='color: #00d4aa; font-weight: 700; margin-bottom: 8px;'>🛡️ Reporting Guidelines</div>
            <div style='color: #7eb8d4; font-size: 0.8em; line-height: 1.6;'>
                • Only report URLs you believe are malicious<br>
                • Include as much context as possible<br>
                • Reports are reviewed by administrators<br>
                • False reports may result in account suspension<br>
                • You can also report to: PhishTank, Google Safe Browsing, APWG
            </div>
        </div>
        """, unsafe_allow_html=True)
