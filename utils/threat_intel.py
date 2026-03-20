"""
utils/threat_intel.py - Domain analysis, WHOIS, threat intelligence
"""
import re
import socket
import hashlib
from datetime import datetime, timedelta


def analyze_domain_age(domain: str) -> dict:
    """
    Attempt WHOIS lookup. Falls back to heuristic estimation if unavailable.
    """
    result = {
        "domain": domain,
        "age_days": None,
        "creation_date": None,
        "expiry_date": None,
        "registrar": None,
        "country": None,
        "risk_note": "",
        "whois_available": False,
    }

    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if isinstance(creation, str):
                creation = datetime.strptime(creation[:10], "%Y-%m-%d")
            age = (datetime.now() - creation).days
            result["age_days"] = age
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            result["whois_available"] = True
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry:
                result["expiry_date"] = expiry.strftime("%Y-%m-%d") if hasattr(expiry, 'strftime') else str(expiry)[:10]
            result["registrar"] = str(w.registrar)[:60] if w.registrar else "Unknown"

            if age < 30:
                result["risk_note"] = "CRITICAL: Domain created within the last 30 days — very high phishing risk."
            elif age < 180:
                result["risk_note"] = "WARNING: Domain is less than 6 months old."
            elif age < 365:
                result["risk_note"] = "NOTICE: Domain is less than 1 year old."
            else:
                result["risk_note"] = f"Domain is {age // 365} year(s) old — generally trustworthy."
    except Exception:
        # Heuristic fallback based on domain characteristics
        result["whois_available"] = False
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"}
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        if tld in suspicious_tlds:
            result["risk_note"] = "WHOIS unavailable. Suspicious TLD typically used for short-lived phishing domains."
            result["age_days"] = 15  # estimated
        else:
            result["risk_note"] = "WHOIS lookup unavailable (network restriction or private registration)."

    return result


def check_domain_reputation(domain: str) -> dict:
    """
    Heuristic reputation check (no live API required).
    Checks against known patterns and generates a trust score.
    """
    domain = domain.lower().replace("www.", "")

    # Known safe domains (abbreviated list)
    trusted_domains = {
        "google.com", "github.com", "stackoverflow.com", "wikipedia.org",
        "amazon.com", "microsoft.com", "apple.com", "youtube.com",
        "linkedin.com", "reddit.com", "twitter.com", "facebook.com",
        "cloudflare.com", "stripe.com", "shopify.com", "paypal.com",
        "ebay.com", "netflix.com", "instagram.com", "tiktok.com",
    }

    if domain in trusted_domains:
        return {
            "trust_score": 95,
            "category": "Trusted",
            "notes": ["Domain is on the trusted whitelist", "Globally recognized service"],
            "threat_level": "MINIMAL",
        }

    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".site"}
    tld = "." + domain.split(".")[-1]

    trust_score = 70
    notes = []
    threats = []

    if tld in suspicious_tlds:
        trust_score -= 30
        notes.append(f"Suspicious TLD '{tld}' commonly used in phishing")
        threats.append("Suspicious TLD")

    brands = ["paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix"]
    brand_in_domain = [b for b in brands if b in domain and not domain.endswith(f"{b}.com")]
    if brand_in_domain:
        trust_score -= 35
        notes.append(f"Brand name '{brand_in_domain[0]}' in domain — possible spoofing")
        threats.append("Brand Impersonation")

    if re.search(r'\d{4,}', domain):
        trust_score -= 10
        notes.append("Domain contains long numeric sequence")

    hyphens = domain.count("-")
    if hyphens > 2:
        trust_score -= 10 * (hyphens - 2)
        notes.append(f"Domain has {hyphens} hyphens — unusual for legitimate sites")
        threats.append("Excessive Hyphens")

    if len(domain) > 40:
        trust_score -= 10
        notes.append("Unusually long domain name")

    trust_score = max(0, min(100, trust_score))

    if trust_score >= 70:
        category = "Likely Safe"
        threat_level = "LOW"
    elif trust_score >= 40:
        category = "Suspicious"
        threat_level = "MEDIUM"
    else:
        category = "Malicious"
        threat_level = "HIGH"

    return {
        "trust_score": trust_score,
        "category": category,
        "notes": notes,
        "threats": threats,
        "threat_level": threat_level,
    }


def get_threat_intelligence_summary(url: str) -> dict:
    """Aggregate threat intelligence for a URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.replace("www.", "")
    except Exception:
        domain = url

    domain_age = analyze_domain_age(domain)
    reputation = check_domain_reputation(domain)

    # Combined threat score
    combined_risk = 0
    if domain_age.get("age_days") is not None:
        age = domain_age["age_days"]
        if age < 30:
            combined_risk += 40
        elif age < 180:
            combined_risk += 20
        elif age < 365:
            combined_risk += 10

    combined_risk += (100 - reputation["trust_score"]) * 0.6
    combined_risk = min(100, combined_risk)

    return {
        "domain": domain,
        "domain_age": domain_age,
        "reputation": reputation,
        "combined_risk": round(combined_risk, 1),
        "summary": _build_summary(domain_age, reputation),
    }


def _build_summary(domain_age, reputation):
    lines = []
    if domain_age.get("creation_date"):
        lines.append(f"Domain registered: {domain_age['creation_date']}")
    if domain_age.get("registrar") and domain_age["registrar"] != "None":
        lines.append(f"Registrar: {domain_age['registrar']}")
    lines.append(f"Trust Score: {reputation['trust_score']}/100")
    lines.append(f"Threat Level: {reputation['threat_level']}")
    return lines


def get_live_threat_feed() -> list:
    """
    Returns simulated recent threat intelligence.
    In production, replace with real feeds like PhishTank API, OpenPhish, etc.
    """
    now = datetime.now()
    threats = [
        {"url": "http://secure-paypal-login.tk/verify", "type": "Phishing", "confidence": 97, "reported": (now - timedelta(minutes=12)).strftime("%H:%M"), "target": "PayPal"},
        {"url": "http://amazon-billing-update.ml/account", "type": "Phishing", "confidence": 94, "reported": (now - timedelta(minutes=35)).strftime("%H:%M"), "target": "Amazon"},
        {"url": "http://apple-id-suspended.xyz/login", "type": "Phishing", "confidence": 91, "reported": (now - timedelta(hours=1, minutes=5)).strftime("%H:%M"), "target": "Apple ID"},
        {"url": "http://microsoft-verify.top/office365", "type": "Phishing", "confidence": 89, "reported": (now - timedelta(hours=2, minutes=18)).strftime("%H:%M"), "target": "Microsoft"},
        {"url": "http://192.168.1.254/banking/login", "type": "Credential Theft", "confidence": 98, "reported": (now - timedelta(hours=3)).strftime("%H:%M"), "target": "Banking"},
        {"url": "http://netflix-payment.site/billing", "type": "Phishing", "confidence": 86, "reported": (now - timedelta(hours=4, minutes=22)).strftime("%H:%M"), "target": "Netflix"},
        {"url": "http://bit.ly/3xPhish-reward", "type": "Redirect", "confidence": 78, "reported": (now - timedelta(hours=5)).strftime("%H:%M"), "target": "Unknown"},
        {"url": "http://google-account-verify.gq/signin", "type": "Phishing", "confidence": 93, "reported": (now - timedelta(hours=6, minutes=10)).strftime("%H:%M"), "target": "Google"},
    ]
    return threats
