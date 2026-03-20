"""
pages/settings.py - User Settings
"""
import streamlit as st
from utils.database import get_connection
import bcrypt


def show_settings():
    user = st.session_state["user"]

    st.markdown("""
    <h2 style='color: #00d4aa; margin-bottom: 4px;'>⚙️ Settings</h2>
    <p style='color: #7eb8d4; margin-bottom: 24px;'>Manage your account and application preferences.</p>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**👤 Account Information**")
        st.markdown(f"""
        <div class='phish-card'>
            <div style='display: flex; gap: 16px; align-items: center; margin-bottom: 16px;'>
                <div style='width: 56px; height: 56px; border-radius: 50%; background: linear-gradient(135deg, #00d4aa, #0080ff);
                            display: flex; align-items: center; justify-content: center; font-size: 1.5em;'>
                    👤
                </div>
                <div>
                    <div style='color: #00d4aa; font-size: 1.1em; font-weight: 700;'>{user['username']}</div>
                    <div style='color: #7eb8d4; font-size: 0.85em;'>{user.get('email','')}</div>
                    <div style='color: #3a5a7a; font-size: 0.75em;'>Role: {'Administrator' if user.get('role') == 'admin' else 'Analyst'}</div>
                </div>
            </div>
            <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 12px;'>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px;'>Member Since</div>
                    <div style='color: #e0f0ff; font-size: 0.85em;'>{str(user.get('created_at',''))[:10]}</div>
                </div>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px;'>Last Login</div>
                    <div style='color: #e0f0ff; font-size: 0.85em;'>{str(user.get('last_login',''))[:16]}</div>
                </div>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px;'>Total Scans</div>
                    <div style='color: #00d4aa; font-size: 1.1em; font-weight: 700; font-family: monospace;'>{user.get('scan_count',0)}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("**🔐 Change Password**")
        with st.form("change_pw"):
            current = st.text_input("Current Password", type="password")
            new_pw = st.text_input("New Password", type="password")
            confirm_pw = st.text_input("Confirm New Password", type="password")
            if st.form_submit_button("Update Password", use_container_width=True):
                if not all([current, new_pw, confirm_pw]):
                    st.error("Please fill in all fields.")
                elif new_pw != confirm_pw:
                    st.error("New passwords do not match.")
                elif len(new_pw) < 6:
                    st.error("Password must be at least 6 characters.")
                else:
                    conn = get_connection()
                    c = conn.cursor()
                    c.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],))
                    row = c.fetchone()
                    if row and bcrypt.checkpw(current.encode(), row["password_hash"].encode()):
                        new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                        c.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user["id"]))
                        conn.commit()
                        st.success("✅ Password updated successfully!")
                    else:
                        st.error("❌ Current password is incorrect.")
                    conn.close()

    with col2:
        st.markdown("**🤖 AI Model Configuration**")
        st.markdown(f"""
        <div class='phish-card'>
            <div style='color: #00d4aa; font-weight: 700; margin-bottom: 12px;'>Current Model Settings</div>
            <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 8px;'>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase;'>Algorithm</div>
                    <div style='color: #e0f0ff; font-size: 0.85em;'>Voting Ensemble</div>
                </div>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase;'>Sub-models</div>
                    <div style='color: #e0f0ff; font-size: 0.85em;'>RF + GBM + LR</div>
                </div>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase;'>Features</div>
                    <div style='color: #00d4aa; font-size: 0.85em; font-weight: 700;'>22 URL features</div>
                </div>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase;'>Training Set</div>
                    <div style='color: #e0f0ff; font-size: 0.85em;'>6,000 samples</div>
                </div>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase;'>Status</div>
                    <div style='color: #00e676; font-size: 0.85em;'>⬤ Active</div>
                </div>
                <div>
                    <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase;'>Accuracy</div>
                    <div style='color: #00d4aa; font-weight: 700; font-family: monospace;'>~96%</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🔄 Retrain AI Model", use_container_width=True):
            with st.spinner("Training model on fresh data..."):
                from utils.ml_model import train_model
                model, scaler, metrics = train_model(force=True)
                st.session_state["model"] = model
                st.session_state["scaler"] = scaler
                st.session_state["model_metrics"] = metrics
            st.success(f"✅ Model retrained! Accuracy: {metrics['accuracy']}%")

        st.markdown("**📋 About PhishGuard AI**")
        st.markdown("""
        <div class='phish-card' style='padding: 14px;'>
            <div style='color: #00d4aa; font-weight: 700; margin-bottom: 8px;'>PhishGuard AI v1.0</div>
            <div style='color: #7eb8d4; font-size: 0.8em; line-height: 1.7;'>
                An AI-powered phishing detection system built with Python, Streamlit, and Scikit-learn.<br><br>
                <strong style='color: #e0f0ff;'>Features:</strong> URL scanning · Email detection · ML risk scoring · 
                Threat intel · PDF reports · Admin dashboard · Scan history<br><br>
                <strong style='color: #e0f0ff;'>Tech Stack:</strong> Python 3.10+ · Streamlit · Scikit-learn · 
                SQLite · Plotly · FPDF2
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("**🔗 Useful Resources**")
        resources = [
            ("PhishTank", "https://phishtank.org"),
            ("OpenPhish", "https://openphish.com"),
            ("APWG eCrime", "https://apwg.org"),
            ("Google Safe Browsing", "https://safebrowsing.google.com"),
            ("VirusTotal", "https://virustotal.com"),
        ]
        for name, url in resources:
            st.markdown(f"""
            <a href='{url}' target='_blank' style='display: block; padding: 6px 12px; 
               background: rgba(0,128,255,0.05); border: 1px solid rgba(0,128,255,0.2);
               border-radius: 6px; color: #00d4aa; text-decoration: none; font-size: 0.85em; 
               margin: 3px 0; transition: all 0.2s;'>
               🔗 {name}
            </a>""", unsafe_allow_html=True)
