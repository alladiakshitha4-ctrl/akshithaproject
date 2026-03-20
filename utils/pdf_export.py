"""
utils/pdf_export.py - PDF Security Report Generator
"""
from fpdf import FPDF
from datetime import datetime
import os


class PhishGuardReport(FPDF):
    def header(self):
        # Dark header bar
        self.set_fill_color(10, 25, 47)
        self.rect(0, 0, 210, 30, 'F')
        self.set_text_color(0, 212, 170)
        self.set_font("Helvetica", "B", 18)
        self.set_y(8)
        self.cell(0, 10, "PhishGuard AI", align="L", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(180, 200, 220)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 5, "AI-Powered Phishing Detection System | Security Report", align="L")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_fill_color(10, 25, 47)
        self.rect(0, self.get_y(), 210, 20, 'F')
        self.set_text_color(100, 140, 180)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10,
                  f"PhishGuard AI Security Report | Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | Page {self.page_no()}",
                  align="C")

    def section_title(self, title):
        self.set_fill_color(15, 40, 70)
        self.set_text_color(0, 212, 170)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def verdict_badge(self, verdict, risk_score):
        color_map = {
            "Phishing": (220, 50, 50),
            "Suspicious": (220, 130, 0),
            "Moderate Risk": (180, 140, 0),
            "Safe": (0, 180, 100),
        }
        color = color_map.get(verdict, (100, 100, 100))
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 14)
        self.cell(60, 12, f"  {verdict.upper()}", fill=True)
        self.set_text_color(50, 50, 50)
        self.set_font("Helvetica", "", 12)
        self.cell(0, 12, f"   Risk Score: {risk_score}%")
        self.ln(6)


def generate_url_report(scan_result: dict, username: str, output_path: str) -> str:
    pdf = PhishGuardReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    # Report metadata
    pdf.set_y(38)
    pdf.set_text_color(60, 80, 100)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Report Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}    |    Analyst: {username}    |    Report Type: URL Security Scan", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Verdict Section
    pdf.section_title("SCAN VERDICT")
    pdf.set_text_color(30, 40, 60)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(30, 7, "Target URL:", new_x="RIGHT", new_y="LAST")
    pdf.set_font("Helvetica", "B", 10)
    url = scan_result.get("url", "")
    pdf.multi_cell(0, 7, url[:120] + ("..." if len(url) > 120 else ""))
    pdf.ln(2)
    pdf.verdict_badge(scan_result.get("verdict", "Unknown"), scan_result.get("risk_score", 0))

    # Risk Gauge (text-based)
    pdf.ln(2)
    risk = scan_result.get("risk_score", 0)
    bar_total = 40
    filled = int(bar_total * risk / 100)
    bar = "█" * filled + "░" * (bar_total - filled)
    pdf.set_font("Courier", "", 9)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, f"Risk Level: [{bar}] {risk}%", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Risk Factors
    pdf.section_title("DETECTED RISK FACTORS")
    risk_factors = scan_result.get("risk_factors", [])
    if risk_factors:
        for i, factor in enumerate(risk_factors, 1):
            pdf.set_fill_color(250, 235, 235) if i % 2 == 0 else pdf.set_fill_color(255, 245, 245)
            pdf.set_text_color(180, 30, 30)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(6, 7, f"{i}.", fill=False)
            pdf.set_text_color(60, 60, 60)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 7, factor, new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_text_color(0, 150, 80)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, "  ✓ No significant risk factors detected.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Feature Analysis Table
    pdf.section_title("URL FEATURE ANALYSIS")
    features = scan_result.get("features", {})
    feature_labels = {
        "url_length": "URL Length",
        "domain_length": "Domain Length",
        "num_dots": "Dot Count",
        "num_hyphens": "Hyphen Count",
        "has_ip_address": "IP Address Used",
        "is_https": "HTTPS Enabled",
        "num_subdomains": "Subdomains",
        "suspicious_tld": "Suspicious TLD",
        "phishing_keyword_count": "Phishing Keywords",
        "has_redirect": "Redirect Detected",
        "brand_squatting": "Brand Squatting",
        "is_shortened": "URL Shortened",
        "url_entropy": "URL Entropy",
        "digit_ratio": "Digit Ratio",
    }

    # Table header
    pdf.set_fill_color(20, 50, 80)
    pdf.set_text_color(200, 220, 240)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(80, 7, "  Feature", fill=True)
    pdf.cell(40, 7, "Value", fill=True)
    pdf.cell(0, 7, "Risk Level", fill=True, new_x="LMARGIN", new_y="NEXT")

    row = 0
    for key, label in feature_labels.items():
        val = features.get(key, "N/A")
        if isinstance(val, float):
            val_str = f"{val:.3f}"
        elif isinstance(val, bool) or val in (0, 1):
            val_str = "YES" if val else "NO"
        else:
            val_str = str(val)

        # Determine risk
        is_risky = False
        if key in ("has_ip_address", "suspicious_tld", "has_redirect", "brand_squatting", "is_shortened") and val:
            is_risky = True
        elif key == "phishing_keyword_count" and (val or 0) > 0:
            is_risky = True
        elif key == "url_length" and (val or 0) > 100:
            is_risky = True

        bg = (255, 245, 245) if is_risky else (245, 250, 255) if row % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_text_color(60, 60, 60)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(80, 6, f"  {label}", fill=True)
        pdf.cell(40, 6, val_str, fill=True)
        risk_txt = "⚠ HIGH" if is_risky else "✓ OK"
        pdf.set_text_color(180, 30, 30) if is_risky else pdf.set_text_color(0, 140, 70)
        pdf.cell(0, 6, risk_txt, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(60, 60, 60)
        row += 1

    pdf.ln(4)

    # Recommendations
    pdf.section_title("SECURITY RECOMMENDATIONS")
    verdict = scan_result.get("verdict", "")
    recs = []
    if verdict == "Phishing":
        recs = [
            "DO NOT visit this URL — it is likely a phishing website.",
            "Report this URL to your IT security team immediately.",
            "If credentials were entered, change passwords immediately.",
            "Enable multi-factor authentication on all affected accounts.",
            "Run a malware scan on your device.",
        ]
    elif verdict == "Suspicious":
        recs = [
            "Exercise extreme caution before visiting this URL.",
            "Verify the source through official channels before proceeding.",
            "Do not enter personal information or credentials.",
            "Report to your security team for further investigation.",
        ]
    elif verdict == "Moderate Risk":
        recs = [
            "Verify this URL through official channels before visiting.",
            "Check the domain age and registration details.",
            "Avoid entering sensitive information.",
        ]
    else:
        recs = [
            "URL appears safe based on current analysis.",
            "Always stay vigilant — keep software and browsers updated.",
            "Enable browser phishing protection for additional safety.",
        ]

    for i, rec in enumerate(recs, 1):
        pdf.set_text_color(40, 40, 100)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, f"  {i}. {rec}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.section_title("DISCLAIMER")
    pdf.set_text_color(100, 100, 100)
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(0, 5,
        "This report is generated by PhishGuard AI and is intended for informational purposes only. "
        "AI-based detection may not be 100% accurate. Always consult your cybersecurity team for "
        "critical decisions. PhishGuard AI is not responsible for actions taken based on this report.")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    return output_path


def generate_scan_history_report(scans: list, username: str, output_path: str) -> str:
    pdf = PhishGuardReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    pdf.set_y(38)
    pdf.set_text_color(60, 80, 100)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5,
             f"Bulk Scan History Report | User: {username} | {datetime.now().strftime('%B %d, %Y')} | {len(scans)} scans",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.section_title("SCAN HISTORY SUMMARY")

    # Stats
    phishing = sum(1 for s in scans if s.get("verdict") == "Phishing")
    suspicious = sum(1 for s in scans if s.get("verdict") == "Suspicious")
    safe = sum(1 for s in scans if s.get("verdict") == "Safe")
    avg_risk = sum(s.get("risk_score", 0) for s in scans) / max(len(scans), 1)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 60)
    stats = [
        ("Total Scans", str(len(scans))),
        ("Phishing Detected", str(phishing)),
        ("Suspicious URLs", str(suspicious)),
        ("Safe URLs", str(safe)),
        ("Average Risk Score", f"{avg_risk:.1f}%"),
    ]
    for label, val in stats:
        pdf.cell(70, 7, f"  {label}:")
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, val, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
    pdf.ln(4)

    # Table
    pdf.section_title("INDIVIDUAL SCAN RESULTS")
    pdf.set_fill_color(20, 50, 80)
    pdf.set_text_color(200, 220, 240)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(80, 6, "  URL", fill=True)
    pdf.cell(20, 6, "Risk", fill=True)
    pdf.cell(35, 6, "Verdict", fill=True)
    pdf.cell(0, 6, "Scanned At", fill=True, new_x="LMARGIN", new_y="NEXT")

    for i, scan in enumerate(scans[:50]):  # limit to 50 in PDF
        bg = (255, 245, 245) if scan.get("verdict") == "Phishing" else \
             (255, 250, 235) if scan.get("verdict") == "Suspicious" else \
             (245, 255, 248) if scan.get("verdict") == "Safe" else (248, 250, 255)
        pdf.set_fill_color(*bg)
        pdf.set_text_color(60, 60, 60)
        pdf.set_font("Helvetica", "", 7)
        url = str(scan.get("url", ""))[:50] + ("..." if len(str(scan.get("url", ""))) > 50 else "")
        pdf.cell(80, 5, f"  {url}", fill=True)
        pdf.cell(20, 5, f"{scan.get('risk_score', 0):.1f}%", fill=True)
        pdf.cell(35, 5, scan.get("verdict", ""), fill=True)
        scanned = str(scan.get("scanned_at", ""))[:16]
        pdf.cell(0, 5, scanned, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.output(output_path)
    return output_path
