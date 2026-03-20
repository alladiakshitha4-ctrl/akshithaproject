"""
utils/ml_model.py - AI Phishing Detection Model
Trains on synthetic + rule-based dataset, provides feature extraction and prediction.
"""
import os
import re
import json
import math
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings("ignore")

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "phish_model.pkl")
SCALER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "scaler.pkl")

# ── Suspicious keywords ────────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "paypal", "ebay", "amazon", "apple", "google",
    "microsoft", "netflix", "facebook", "instagram", "confirm", "password", "credential",
    "wallet", "crypto", "bitcoin", "urgent", "alert", "suspended", "limited", "access",
    "click", "free", "winner", "prize", "lucky", "offer", "discount", "deal",
    "support", "helpdesk", "customer", "service", "refund", "claim", "reward",
    "webscr", "cmd=", "dispatch=", "track", "redirect", "checkout", "billing"
]

SAFE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".uk", ".de", ".fr"}
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
                   ".online", ".site", ".website", ".space", ".live", ".stream", ".download"}

# ── Feature Extraction ─────────────────────────────────────────────────────────

def extract_url_features(url: str) -> dict:
    """Extract 20+ features from a URL for ML model."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    features = {}

    # 1. URL length
    features["url_length"] = len(url)

    # 2. Domain length
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
    except Exception:
        domain = url
    features["domain_length"] = len(domain)

    # 3. Number of dots
    features["num_dots"] = url.count(".")

    # 4. Number of hyphens
    features["num_hyphens"] = url.count("-")

    # 5. Number of underscores
    features["num_underscores"] = url.count("_")

    # 6. Number of slashes
    features["num_slashes"] = url.count("/")

    # 7. Number of @ symbols (phishing trick)
    features["has_at_symbol"] = int("@" in url)

    # 8. Has IP address instead of domain
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features["has_ip_address"] = int(bool(ip_pattern.search(domain)))

    # 9. HTTPS
    features["is_https"] = int(url.startswith("https://"))

    # 10. Number of subdomains
    parts = domain.split(".")
    features["num_subdomains"] = max(0, len(parts) - 2)

    # 11. URL has port
    features["has_port"] = int(":" in domain and not domain.endswith(":80") and not domain.endswith(":443"))

    # 12. Suspicious TLD
    tld = "." + parts[-1] if parts else ""
    features["suspicious_tld"] = int(tld.lower() in SUSPICIOUS_TLDS)

    # 13. Phishing keyword count
    url_lower = url.lower()
    kw_count = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
    features["phishing_keyword_count"] = kw_count

    # 14. Has redirect (multiple http in URL)
    features["has_redirect"] = int(url_lower.count("http") > 1)

    # 15. URL entropy (high entropy = suspicious)
    features["url_entropy"] = _calc_entropy(url)

    # 16. Digit ratio
    digits = sum(c.isdigit() for c in url)
    features["digit_ratio"] = digits / max(len(url), 1)

    # 17. Special char count
    special = sum(c in "!#$%^&*()+=[]{}|;:,<>?" for c in url)
    features["special_char_count"] = special

    # 18. Domain has numbers
    features["domain_has_numbers"] = int(bool(re.search(r'\d', domain)))

    # 19. URL depth (path segments)
    try:
        path = urlparse(url).path
        features["url_depth"] = len([p for p in path.split("/") if p])
    except Exception:
        features["url_depth"] = 0

    # 20. Query parameter count
    try:
        query = urlparse(url).query
        features["query_param_count"] = len(query.split("&")) if query else 0
    except Exception:
        features["query_param_count"] = 0

    # 21. Brand name squatting (brand name in non-brand domain)
    brands = ["paypal", "amazon", "google", "microsoft", "apple", "facebook",
              "netflix", "ebay", "instagram", "twitter", "linkedin", "bank"]
    brand_in_url = any(b in url_lower for b in brands)
    # If brand keyword in URL but domain doesn't belong to brand
    brand_squatting = brand_in_url and not any(
        domain.endswith(f"{b}.com") or domain == f"{b}.com" for b in brands
    )
    features["brand_squatting"] = int(brand_squatting)

    # 22. Shortener service
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly"]
    features["is_shortened"] = int(any(s in domain for s in shorteners))

    return features


def _calc_entropy(text):
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def get_feature_names():
    return [
        "url_length", "domain_length", "num_dots", "num_hyphens", "num_underscores",
        "num_slashes", "has_at_symbol", "has_ip_address", "is_https", "num_subdomains",
        "has_port", "suspicious_tld", "phishing_keyword_count", "has_redirect",
        "url_entropy", "digit_ratio", "special_char_count", "domain_has_numbers",
        "url_depth", "query_param_count", "brand_squatting", "is_shortened"
    ]


# ── Dataset Generation ─────────────────────────────────────────────────────────

def generate_training_dataset(n_samples=5000):
    """Generate a realistic labeled dataset for training."""
    np.random.seed(42)
    records = []

    # Safe URL patterns
    safe_domains = [
        "google.com", "github.com", "stackoverflow.com", "wikipedia.org",
        "amazon.com", "microsoft.com", "apple.com", "youtube.com",
        "linkedin.com", "reddit.com", "twitter.com", "facebook.com",
        "nytimes.com", "bbc.com", "cnn.com", "cloudflare.com",
        "stripe.com", "shopify.com", "wordpress.com", "medium.com"
    ]

    phishing_patterns = [
        "paypal-secure-{r}.tk/login/verify",
        "amazon-account-{r}.ml/update/billing",
        "microsoft-{r}-support.xyz/security/alert",
        "apple-id-{r}.top/verify/account",
        "secure-banking-{r}.gq/login",
        "192.168.{r}.1/phishing/login",
        "bit.ly/{r}phish",
        "google-login-{r}.tk/signin",
        "netflix-{r}.site/billing/update",
        "{r}-paypal.com.evil.tk/cmd=login",
    ]

    for _ in range(n_samples // 2):
        # Safe
        domain = np.random.choice(safe_domains)
        paths = ["", "/about", "/products", "/contact", "/blog/post-123",
                 "/search?q=test", "/user/profile", "/docs/api"]
        url = f"https://{domain}{np.random.choice(paths)}"
        feats = extract_url_features(url)
        feats["label"] = 0
        records.append(feats)

    for _ in range(n_samples // 2):
        # Phishing
        r = np.random.randint(100, 9999)
        pattern = np.random.choice(phishing_patterns)
        url = f"http://{pattern.format(r=r)}"
        feats = extract_url_features(url)
        feats["label"] = 1
        records.append(feats)

    df = pd.DataFrame(records)
    return df


# ── Model Training ─────────────────────────────────────────────────────────────

def train_model(force=False):
    """Train ensemble model. Returns (model, scaler, metrics)."""
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    if not force and os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler, None

    print("Training phishing detection model...")
    df = generate_training_dataset(6000)

    feature_cols = get_feature_names()
    X = df[feature_cols].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # Ensemble: RF + GBM + LR
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    gbm = GradientBoostingClassifier(n_estimators=100, random_state=42)
    lr = LogisticRegression(max_iter=500, random_state=42)

    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gbm", gbm), ("lr", lr)],
        voting="soft"
    )
    ensemble.fit(X_train_s, y_train)

    y_pred = ensemble.predict(X_test_s)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)

    joblib.dump(ensemble, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"Model trained. Accuracy: {accuracy:.4f}")

    metrics = {
        "accuracy": round(accuracy * 100, 2),
        "precision": round(report["1"]["precision"] * 100, 2),
        "recall": round(report["1"]["recall"] * 100, 2),
        "f1": round(report["1"]["f1-score"] * 100, 2),
        "training_samples": 6000,
        "features": len(feature_cols),
    }
    return ensemble, scaler, metrics


# ── Prediction ─────────────────────────────────────────────────────────────────

def predict_url(url: str, model, scaler) -> dict:
    """Run full prediction pipeline on a URL."""
    features = extract_url_features(url)
    feature_cols = get_feature_names()
    X = np.array([[features[col] for col in feature_cols]])
    X_scaled = scaler.transform(X)

    proba = model.predict_proba(X_scaled)[0]
    phishing_prob = proba[1]
    risk_score = round(phishing_prob * 100, 1)

    if risk_score >= 75:
        verdict = "Phishing"
        severity = "CRITICAL"
    elif risk_score >= 50:
        verdict = "Suspicious"
        severity = "HIGH"
    elif risk_score >= 25:
        verdict = "Moderate Risk"
        severity = "MEDIUM"
    else:
        verdict = "Safe"
        severity = "LOW"

    # Identify top risk factors
    risk_factors = []
    if features["has_ip_address"]:
        risk_factors.append("IP address used instead of domain name")
    if features["suspicious_tld"]:
        risk_factors.append(f"Suspicious top-level domain detected")
    if features["phishing_keyword_count"] > 0:
        risk_factors.append(f"{features['phishing_keyword_count']} phishing keywords found in URL")
    if features["brand_squatting"]:
        risk_factors.append("Brand name squatting detected (impersonating known brand)")
    if features["has_at_symbol"]:
        risk_factors.append("@ symbol in URL (common phishing trick)")
    if features["has_redirect"]:
        risk_factors.append("Multiple redirects detected in URL")
    if features["is_shortened"]:
        risk_factors.append("URL shortener used (hides true destination)")
    if features["url_length"] > 100:
        risk_factors.append(f"Unusually long URL ({features['url_length']} characters)")
    if features["num_hyphens"] > 3:
        risk_factors.append(f"Excessive hyphens in domain ({features['num_hyphens']})")
    if not features["is_https"]:
        risk_factors.append("No HTTPS — connection is not encrypted")
    if features["url_entropy"] > 4.5:
        risk_factors.append("High URL entropy — randomized characters detected")

    return {
        "url": url,
        "risk_score": risk_score,
        "verdict": verdict,
        "severity": severity,
        "risk_factors": risk_factors,
        "features": features,
        "phishing_prob": phishing_prob,
        "safe_prob": proba[0],
    }


# ── Email Phishing Detection ───────────────────────────────────────────────────

EMAIL_PHISHING_PHRASES = [
    ("urgent action required", 20),
    ("verify your account", 18),
    ("click here immediately", 15),
    ("your account has been suspended", 20),
    ("confirm your identity", 15),
    ("unusual activity", 12),
    ("update your payment", 18),
    ("you have won", 20),
    ("dear customer", 8),
    ("limited time offer", 10),
    ("act now", 10),
    ("free gift", 12),
    ("password expired", 15),
    ("unauthorized access", 12),
    ("verify your email", 15),
    ("account will be closed", 20),
    ("click the link below", 10),
    ("do not ignore", 12),
    ("final warning", 18),
    ("congratulations you have been selected", 20),
    ("bank account", 10),
    ("wire transfer", 15),
    ("your paypal", 15),
    ("ssn", 15),
    ("social security", 15),
]

def analyze_email(subject: str, body: str, sender: str = "") -> dict:
    """Analyze email content for phishing indicators."""
    full_text = f"{subject} {body} {sender}".lower()
    indicators = []
    score = 0

    for phrase, weight in EMAIL_PHISHING_PHRASES:
        if phrase in full_text:
            indicators.append({"phrase": phrase, "weight": weight})
            score += weight

    # URL checks in email body
    url_pattern = re.compile(r'https?://\S+')
    urls_found = url_pattern.findall(body)
    suspicious_urls = []
    for u in urls_found:
        f = extract_url_features(u)
        if f["phishing_keyword_count"] > 0 or f["suspicious_tld"] or f["has_ip_address"]:
            suspicious_urls.append(u)
            score += 25

    # Sender domain mismatch
    if sender:
        sender_match = re.search(r'@([\w.-]+)', sender)
        if sender_match:
            sender_domain = sender_match.group(1).lower()
            brands = ["paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix"]
            for brand in brands:
                if brand in subject.lower() and brand not in sender_domain:
                    indicators.append({"phrase": f"Sender domain mismatch for {brand}", "weight": 30})
                    score += 30
                    break

    # Normalize to 0–100
    risk_score = min(100, score)

    if risk_score >= 70:
        verdict = "Phishing Email"
    elif risk_score >= 40:
        verdict = "Suspicious Email"
    elif risk_score >= 20:
        verdict = "Moderate Risk"
    else:
        verdict = "Likely Safe"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "indicators": indicators,
        "suspicious_urls": suspicious_urls,
        "urls_found": urls_found,
    }
