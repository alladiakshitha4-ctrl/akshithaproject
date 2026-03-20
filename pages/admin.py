"""
pages/admin.py - Admin Dashboard
"""
import streamlit as st
import pandas as pd
from utils.database import get_admin_stats, get_all_users, get_reports, update_report_status, get_scan_history


def show_admin():
    st.markdown("""
    <h2 style='color: #ff9f43; margin-bottom: 4px;'>👑 Admin Control Panel</h2>
    <p style='color: #7eb8d4; margin-bottom: 24px;'>System-wide administration, user management, and report review.</p>
    """, unsafe_allow_html=True)

    stats = get_admin_stats()

    # System stats
    cols = st.columns(6)
    metrics = [
        ("Total Users", stats["total_users"], "#00d4aa"),
        ("Total Scans", stats["total_scans"], "#0080ff"),
        ("Phishing Found", stats["phishing_detected"], "#ff3860"),
        ("Email Scans", stats["email_scans"], "#ff9f43"),
        ("Pending Reports", stats["pending_reports"], "#ffd32a"),
        ("Avg Risk", f"{stats['avg_risk']}%", "#7eb8d4"),
    ]
    for col, (label, val, color) in zip(cols, metrics):
        with col:
            st.markdown(f"""
            <div class='metric-box' style='border-color: {color}30;'>
                <div class='metric-value' style='color:{color}; font-size: 1.4em;'>{val}</div>
                <div class='metric-label'>{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["👥 User Management", "🚨 Report Review", "📋 All Scans"])

    with tab1:
        st.markdown("**Registered Users**")
        users = get_all_users()
        if users:
            df = pd.DataFrame(users)
            df = df[["id", "username", "email", "role", "scan_count", "last_login", "created_at"]]
            df.columns = ["ID", "Username", "Email", "Role", "Scans", "Last Login", "Created"]
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No users found.")

    with tab2:
        st.markdown("**Pending Reports**")
        reports = get_reports()
        pending = [r for r in reports if r.get("status") == "pending"]

        if not pending:
            st.success("✅ No pending reports.")
        else:
            for r in pending:
                with st.expander(f"🚨 Report #{r['id']} — {str(r.get('url',''))[:60]}"):
                    st.markdown(f"""
                    <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;'>
                        <div>
                            <div style='color: #3a5a7a; font-size: 0.72em;'>URL</div>
                            <div style='color: #7eb8d4; font-family: monospace; font-size: 0.82em; word-break: break-all;'>{r.get('url','')}</div>
                        </div>
                        <div>
                            <div style='color: #3a5a7a; font-size: 0.72em;'>Reported by</div>
                            <div style='color: #e0f0ff;'>{r.get('username','Unknown')}</div>
                        </div>
                        <div>
                            <div style='color: #3a5a7a; font-size: 0.72em;'>Reason</div>
                            <div style='color: #ff9f43;'>{r.get('report_reason','')}</div>
                        </div>
                        <div>
                            <div style='color: #3a5a7a; font-size: 0.72em;'>Reported at</div>
                            <div style='color: #e0f0ff;'>{str(r.get('reported_at',''))[:16]}</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    if r.get("additional_info"):
                        st.markdown(f"**Details:** {r['additional_info']}")
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        if st.button("✅ Confirm Threat", key=f"confirm_{r['id']}"):
                            update_report_status(r["id"], "confirmed")
                            st.success("Marked as confirmed threat.")
                            st.rerun()
                    with col_b:
                        if st.button("🔍 Under Review", key=f"review_{r['id']}"):
                            update_report_status(r["id"], "reviewed")
                            st.rerun()
                    with col_c:
                        if st.button("❌ Dismiss", key=f"dismiss_{r['id']}"):
                            update_report_status(r["id"], "dismissed")
                            st.rerun()

        if reports:
            st.markdown("**All Reports**")
            df_r = pd.DataFrame(reports)[["id", "username", "url", "report_reason", "status", "reported_at"]]
            df_r.columns = ["ID", "User", "URL", "Reason", "Status", "Reported At"]
            df_r["URL"] = df_r["URL"].str[:50] + "..."
            st.dataframe(df_r, use_container_width=True, hide_index=True)

    with tab3:
        st.markdown("**All System Scans**")
        scans = get_scan_history(limit=100)
        if scans:
            df_s = pd.DataFrame(scans)[["id", "username", "url", "risk_score", "verdict", "scanned_at"]]
            df_s.columns = ["ID", "User", "URL", "Risk %", "Verdict", "Scanned At"]
            df_s["URL"] = df_s["URL"].str[:60] + "..."
            df_s["Risk %"] = df_s["Risk %"].round(1)
            st.dataframe(df_s, use_container_width=True, hide_index=True)
