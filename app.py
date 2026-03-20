"""
app.py - PhishGuard AI | Main Entry Point
Run with: streamlit run app.py
"""
import streamlit as st
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from utils.database import init_db, login_user, register_user
from utils.ml_model import train_model

# ── Page Config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;800&display=swap');

:root {
    --bg-primary: #050e1a;
    --bg-secondary: #0a1929;
    --bg-card: #0d2137;
    --accent-cyan: #00d4aa;
    --accent-blue: #0080ff;
    --accent-red: #ff3860;
    --accent-orange: #ff9f43;
    --accent-green: #00e676;
    --text-primary: #e0f0ff;
    --text-secondary: #7eb8d4;
    --text-dim: #3a5a7a;
    --border: #1a3a5c;
    --glow-cyan: 0 0 20px rgba(0,212,170,0.3);
    --glow-blue: 0 0 20px rgba(0,128,255,0.3);
    --glow-red: 0 0 20px rgba(255,56,96,0.4);
}

html, body, [class*="css"] {
    font-family: 'Exo 2', sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
}

/* Hide default streamlit elements */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }

/* Main background */
.stApp {
    background: 
        radial-gradient(ellipse at 10% 20%, rgba(0,128,255,0.06) 0%, transparent 50%),
        radial-gradient(ellipse at 90% 80%, rgba(0,212,170,0.05) 0%, transparent 50%),
        linear-gradient(180deg, #050e1a 0%, #071422 100%);
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #050e1a 0%, #071830 100%);
    border-right: 1px solid var(--border);
}

/* Cards */
.phish-card {
    background: linear-gradient(135deg, rgba(13,33,55,0.95) 0%, rgba(10,25,40,0.95) 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 16px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.03);
    transition: all 0.3s ease;
}
.phish-card:hover {
    border-color: rgba(0,212,170,0.3);
    box-shadow: 0 4px 32px rgba(0,0,0,0.5), var(--glow-cyan);
}

/* Risk badges */
.badge-safe { background: linear-gradient(135deg, #004d2e, #006644); border: 1px solid #00e676; color: #00e676; }
.badge-phishing { background: linear-gradient(135deg, #5c0011, #7a0018); border: 1px solid #ff3860; color: #ff8fa0; }
.badge-suspicious { background: linear-gradient(135deg, #5c3000, #7a4000); border: 1px solid #ff9f43; color: #ffbe76; }
.badge-moderate { background: linear-gradient(135deg, #4a4000, #5c5000); border: 1px solid #ffd32a; color: #ffe66d; }
.badge { padding: 6px 18px; border-radius: 20px; font-weight: 700; font-size: 13px; display: inline-block; letter-spacing: 1px; }

/* Risk meter */
.risk-meter-container { background: rgba(0,0,0,0.4); border-radius: 8px; height: 12px; overflow: hidden; margin: 8px 0; border: 1px solid var(--border); }
.risk-meter-fill { height: 100%; border-radius: 8px; transition: width 0.8s ease; }
.risk-low { background: linear-gradient(90deg, #00b868, #00e676); }
.risk-medium { background: linear-gradient(90deg, #e6a817, #ffd32a); }
.risk-high { background: linear-gradient(90deg, #e65c00, #ff9f43); }
.risk-critical { background: linear-gradient(90deg, #c0001a, #ff3860); box-shadow: 0 0 8px rgba(255,56,96,0.5); }

/* Metric boxes */
.metric-box {
    background: rgba(13,33,55,0.8);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    text-align: center;
}
.metric-value { font-size: 2em; font-weight: 800; color: var(--accent-cyan); font-family: 'Share Tech Mono', monospace; }
.metric-label { font-size: 0.75em; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1.5px; margin-top: 4px; }

/* Top navigation bar */
.topbar {
    background: linear-gradient(90deg, rgba(5,14,26,0.98) 0%, rgba(10,25,40,0.98) 100%);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

/* Scan input */
.stTextInput > div > div > input {
    background: rgba(13,33,55,0.9) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-primary) !important;
    border-radius: 8px !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 14px !important;
    padding: 12px 16px !important;
}
.stTextInput > div > div > input:focus {
    border-color: var(--accent-cyan) !important;
    box-shadow: var(--glow-cyan) !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #006644, #00a368) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'Exo 2', sans-serif !important;
    font-weight: 700 !important;
    letter-spacing: 0.5px !important;
    padding: 10px 24px !important;
    transition: all 0.3s ease !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #00a368, #00c87f) !important;
    box-shadow: var(--glow-cyan) !important;
    transform: translateY(-1px) !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: rgba(5,14,26,0.8);
    border-radius: 10px;
    border: 1px solid var(--border);
    gap: 0;
}
.stTabs [data-baseweb="tab"] {
    color: var(--text-secondary) !important;
    font-family: 'Exo 2', sans-serif !important;
    font-weight: 600 !important;
    padding: 10px 20px !important;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(0,212,170,0.15), rgba(0,128,255,0.1)) !important;
    color: var(--accent-cyan) !important;
    border-bottom: 2px solid var(--accent-cyan) !important;
}

/* Alerts */
.stAlert { border-radius: 10px !important; border-left-width: 4px !important; }

/* Tables */
.stDataFrame { background: rgba(13,33,55,0.8) !important; border-radius: 10px !important; border: 1px solid var(--border) !important; }

/* Selectbox */
.stSelectbox > div > div {
    background: rgba(13,33,55,0.9) !important;
    border-color: var(--border) !important;
    color: var(--text-primary) !important;
}

/* Textarea */
.stTextArea > div > div > textarea {
    background: rgba(13,33,55,0.9) !important;
    border-color: var(--border) !important;
    color: var(--text-primary) !important;
    font-family: 'Exo 2', sans-serif !important;
}
/* ── Mobile Responsive ─────────────────────────────────────────── */
@media (max-width: 768px) {

    /* Stack all columns vertically */
    [data-testid="column"] {
        width: 100% !important;
        flex: 1 1 100% !important;
        min-width: 100% !important;
    }

    /* Sidebar auto-collapse on mobile */
    section[data-testid="stSidebar"] {
        width: 80vw !important;
        min-width: 0 !important;
    }

    /* Metric boxes — 2 per row on mobile */
    .metric-box {
        padding: 10px 8px !important;
    }
    .metric-value {
        font-size: 1.4em !important;
    }
    .metric-label {
        font-size: 0.65em !important;
    }

    /* Cards full width */
    .phish-card {
        padding: 14px !important;
        margin-bottom: 10px !important;
    }

    /* Risk score number smaller on mobile */
    .phish-card div[style*="3.5em"] {
        font-size: 2.2em !important;
    }

    /* Verdict text smaller */
    .phish-card div[style*="2.2em"] {
        font-size: 1.4em !important;
    }

    /* Tables scroll horizontally */
    [data-testid="stDataFrame"] {
        overflow-x: auto !important;
        max-width: 100vw !important;
    }

    /* Threat items wrap */
    .threat-item > div {
        flex-wrap: wrap !important;
    }

    /* Hide long URLs — truncate more */
    .phish-card div[style*="word-break"] {
        font-size: 0.75em !important;
    }

    /* Buttons full width */
    .stButton > button {
        width: 100% !important;
        padding: 10px 12px !important;
        font-size: 0.9em !important;
    }

    /* Input fields */
    .stTextInput > div > div > input {
        font-size: 16px !important; /* Prevents iOS zoom on focus */
    }
    .stTextArea > div > div > textarea {
        font-size: 16px !important;
    }

    /* Tabs scrollable on mobile */
    .stTabs [data-baseweb="tab-list"] {
        overflow-x: auto !important;
        flex-wrap: nowrap !important;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 12px !important;
        font-size: 0.8em !important;
        white-space: nowrap !important;
    }

    /* Reduce page title size */
    h2 { font-size: 1.3em !important; }
    h3 { font-size: 1.1em !important; }

    /* Scan history rows wrap */
    div[style*="grid-template-columns"] {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 6px !important;
    }

    /* Login page padding */
    .login-container {
        margin: 20px auto !important;
        padding: 24px 16px !important;
    }

    /* Plotly charts full width */
    .js-plotly-plot {
        max-width: 100vw !important;
    }

    /* Admin table scroll */
    .stDataFrame {
        font-size: 0.75em !important;
    }
}

@media (max-width: 480px) {
    .metric-value { font-size: 1.2em !important; }
    .metric-label { font-size: 0.6em !important; }
    .phish-card { padding: 12px !important; }
    h2 { font-size: 1.1em !important; }
}
/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-cyan); }

/* Login page */
.login-container {
    max-width: 460px;
    margin: 60px auto;
    background: linear-gradient(135deg, rgba(13,33,55,0.98) 0%, rgba(10,25,40,0.98) 100%);
    border: 1px solid rgba(0,212,170,0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.6), var(--glow-cyan);
}

/* Glowing title text */
.glow-text { text-shadow: 0 0 20px rgba(0,212,170,0.5), 0 0 40px rgba(0,212,170,0.2); }

/* Risk factor items */
.risk-factor { 
    background: rgba(255,56,96,0.05); 
    border-left: 3px solid var(--accent-red); 
    padding: 8px 12px; 
    margin: 4px 0; 
    border-radius: 0 6px 6px 0;
    font-size: 13px;
    color: #ffb3c0;
}

/* Feature chip */
.feature-chip {
    display: inline-block;
    background: rgba(0,128,255,0.1);
    border: 1px solid rgba(0,128,255,0.3);
    border-radius: 16px;
    padding: 3px 10px;
    font-size: 11px;
    color: #80c0ff;
    margin: 2px;
}

/* Threat feed item */
.threat-item {
    background: rgba(255,56,96,0.05);
    border: 1px solid rgba(255,56,96,0.2);
    border-radius: 8px;
    padding: 10px 14px;
    margin: 6px 0;
}

/* Pulse animation */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}
.live-dot {
    display: inline-block;
    width: 8px; height: 8px;
    background: var(--accent-red);
    border-radius: 50%;
    animation: pulse 1.5s infinite;
    margin-right: 6px;
}

/* Section headers */
h1, h2, h3 { font-family: 'Exo 2', sans-serif !important; }
.section-header {
    color: var(--accent-cyan);
    font-size: 0.7em;
    text-transform: uppercase;
    letter-spacing: 3px;
    font-weight: 600;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
}

/* Progress bars */
.stProgress > div > div > div { background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue)) !important; }
</style>
""", unsafe_allow_html=True)

# ── Initialize ─────────────────────────────────────────────────────────────────
init_db()

# Train/load model
if "model" not in st.session_state:
    with st.spinner("🤖 Loading AI model..."):
        model, scaler, metrics = train_model()
        st.session_state["model"] = model
        st.session_state["scaler"] = scaler
        st.session_state["model_metrics"] = metrics

# ── Auth State ─────────────────────────────────────────────────────────────────
if "user" not in st.session_state:
    st.session_state["user"] = None

# ── Login/Register UI ──────────────────────────────────────────────────────────
def show_auth_page():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div style='text-align:center; padding: 40px 0 20px;'>
            <div style='font-size: 4em; margin-bottom: 10px;'>🛡️</div>
            <h1 class='glow-text' style='color: #00d4aa; font-size: 2.5em; margin: 0; font-family: Exo 2;'>PhishGuard AI</h1>
            <p style='color: #7eb8d4; margin: 8px 0 32px; font-size: 1.1em; letter-spacing: 2px; text-transform: uppercase;'>AI-Powered Phishing Detection</p>
        </div>
        """, unsafe_allow_html=True)

        tab_login, tab_register = st.tabs(["🔑  Sign In", "✨  Create Account"])

        with tab_login:
            st.markdown("<br>", unsafe_allow_html=True)
            username = st.text_input("Username", placeholder="Enter username", key="login_user")
            password = st.text_input("Password", type="password", placeholder="Enter password", key="login_pass")
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🔐  Sign In", use_container_width=True):
                if username and password:
                    ok, user = login_user(username, password)
                    if ok:
                        st.session_state["user"] = user
                        st.success(f"Welcome back, **{username}**!")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password.")
                else:
                    st.warning("Please enter your credentials.")
            st.markdown("""
            <p style='text-align:center; color: #3a5a7a; font-size: 0.85em; margin-top: 20px;'>
                Default admin: <code style='color:#00d4aa'>admin</code> / <code style='color:#00d4aa'>admin123</code>
            </p>
            """, unsafe_allow_html=True)

        with tab_register:
            st.markdown("<br>", unsafe_allow_html=True)
            new_user = st.text_input("Username", placeholder="Choose a username", key="reg_user")
            new_email = st.text_input("Email", placeholder="your@email.com", key="reg_email")
            new_pass = st.text_input("Password", type="password", placeholder="Minimum 6 characters", key="reg_pass")
            new_pass2 = st.text_input("Confirm Password", type="password", placeholder="Repeat password", key="reg_pass2")
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🚀  Create Account", use_container_width=True):
                if not all([new_user, new_email, new_pass, new_pass2]):
                    st.warning("Please fill in all fields.")
                elif new_pass != new_pass2:
                    st.error("❌ Passwords do not match.")
                elif len(new_pass) < 6:
                    st.error("❌ Password must be at least 6 characters.")
                else:
                    ok, msg = register_user(new_user, new_pass, new_email)
                    if ok:
                        st.success(f"✅ Account created! You can now sign in.")
                    else:
                        st.error(f"❌ {msg}")


# ── Main App ───────────────────────────────────────────────────────────────────
def show_main_app():
    from pages.url_scanner import show_url_scanner
    from pages.email_detector import show_email_detector
    from pages.scan_history import show_scan_history
    from pages.statistics import show_statistics
    from pages.threat_feed import show_threat_feed
    from pages.reporting import show_reporting
    from pages.admin import show_admin
    from pages.settings import show_settings

    user = st.session_state["user"]
    is_admin = user.get("role") == "admin"

    # ── Sidebar ────────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown(f"""
        <div style='text-align:center; padding: 20px 0;'>
            <div style='font-size: 2.5em;'>🛡️</div>
            <div style='color: #00d4aa; font-size: 1.4em; font-weight: 800; font-family: Exo 2;'>PhishGuard</div>
            <div style='color: #3a5a7a; font-size: 0.7em; letter-spacing: 2px; text-transform: uppercase;'>AI Security Suite</div>
        </div>
        <div style='background: rgba(0,212,170,0.08); border: 1px solid rgba(0,212,170,0.2); border-radius: 10px; padding: 12px; margin: 8px 0 20px;'>
            <div style='color: #7eb8d4; font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px;'>Logged in as</div>
            <div style='color: #00d4aa; font-weight: 700; font-size: 1em;'>👤 {user['username']}</div>
            <div style='color: #3a5a7a; font-size: 0.75em;'>{'🔴 Administrator' if is_admin else '🔵 Analyst'}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<p class='section-header'>Navigation</p>", unsafe_allow_html=True)

        pages = [
            ("🔍", "URL Scanner", "url"),
            ("📧", "Email Detector", "email"),
            ("📋", "Scan History", "history"),
            ("📊", "Statistics", "stats"),
            ("🌐", "Threat Feed", "threat"),
            ("🚨", "Report Threat", "report"),
            ("⚙️", "Settings", "settings"),
        ]
        if is_admin:
            pages.insert(-1, ("👑", "Admin Panel", "admin"))

        if "page" not in st.session_state:
            st.session_state["page"] = "url"

        for icon, label, key in pages:
            active = st.session_state["page"] == key
            btn_style = "background: linear-gradient(135deg, rgba(0,212,170,0.15), rgba(0,128,255,0.1)); border-left: 3px solid #00d4aa;" if active else ""
            if st.button(f"{icon}  {label}", use_container_width=True, key=f"nav_{key}"):
                st.session_state["page"] = key
                st.rerun()

        st.markdown("---")

        # Model status
        metrics = st.session_state.get("model_metrics")
        st.markdown(f"""
        <div style='background: rgba(0,0,0,0.3); border-radius: 10px; padding: 12px; margin: 8px 0;'>
            <div style='color: #3a5a7a; font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;'>AI Model Status</div>
            <div style='color: #00e676; font-size: 0.85em;'>⬤ Active & Ready</div>
            <div style='color: #7eb8d4; font-size: 0.75em; margin-top: 4px;'>Ensemble (RF + GBM + LR)</div>
            <div style='color: #00d4aa; font-size: 0.8em; font-weight: 700; font-family: monospace;'>22 features analyzed</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚪  Sign Out", use_container_width=True):
            st.session_state["user"] = None
            st.rerun()

    # ── Page Routing ───────────────────────────────────────────────────────────
    page = st.session_state.get("page", "url")

    if page == "url":
        show_url_scanner()
    elif page == "email":
        show_email_detector()
    elif page == "history":
        show_scan_history()
    elif page == "stats":
        show_statistics()
    elif page == "threat":
        show_threat_feed()
    elif page == "report":
        show_reporting()
    elif page == "admin" and is_admin:
        show_admin()
    elif page == "settings":
        show_settings()


# ── Entry ──────────────────────────────────────────────────────────────────────
if st.session_state["user"] is None:
    show_auth_page()
else:
    show_main_app()
