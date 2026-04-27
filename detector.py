import os
import re
import joblib
from urllib.parse import unquote, urlparse

MODEL_PATH = "models/malicious_url_model.joblib"


def basic_features(url: str) -> dict:
    raw = str(url).strip()
    decoded = unquote(raw).lower()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    special_ratio = sum(not c.isalnum() for c in raw) / max(len(raw), 1)
    query_params = raw.count("&") + 1 if "?" in raw else 0

    return {
        "length": len(raw),
        "domain": parsed.netloc,
        "path": parsed.path,
        "encoded_patterns": encoded_count,
        "special_character_ratio": round(special_ratio, 4),
        "query_parameter_count": query_params,
    }


def detect_defacement(url: str):
    raw = str(url).strip()
    decoded = unquote(raw).lower()

    score = 0
    reasons = []

    defacement_patterns = [
        (r"hacked\s+by", 45, "Defacement phrase detected: hacked by"),
        (r"owned\s+by", 40, "Defacement phrase detected: owned by"),
        (r"pwned\s+by", 40, "Defacement phrase detected: pwned by"),
        (r"defaced\s+by", 45, "Defacement phrase detected: defaced by"),
        (r"cyber\s+army", 30, "Defacement group-style keyword detected"),
        (r"anonymous", 20, "Possible defacement actor keyword"),
        (r"index\.html", 10, "Suspicious replaced index page reference"),
        (r"shell|webshell|wso|c99|r57", 30, "Web shell related keyword detected"),
        (r"fuck\s+admin|admin\s+owned", 35, "Hostile admin takeover phrase detected"),
        (r"site\s+hacked|website\s+hacked", 40, "Website hacked phrase detected"),
        (r"your\s+security\s+is\s+low", 35, "Typical defacement warning phrase"),
    ]

    for pattern, weight, reason in defacement_patterns:
        if re.search(pattern, decoded):
            score += weight
            reasons.append(reason)

    return min(score / 100, 1.0), reasons


def detect_malicious(url: str):
    raw = str(url).strip()
    decoded = unquote(raw).lower()

    score = 0
    reasons = []

    malicious_patterns = [
        (r"union\s+select", 40, "SQL injection pattern: UNION SELECT"),
        (r"or\s+1\s*=\s*1", 35, "SQL injection bypass pattern: OR 1=1"),
        (r"select\s+.*\s+from", 30, "SQL query structure detected"),
        (r"drop\s+table", 40, "Dangerous SQL command detected"),
        (r"insert\s+into", 25, "SQL insert command detected"),
        (r"information_schema", 35, "Database metadata access pattern"),
        (r"xp_cmdshell", 45, "High-risk SQL Server command execution"),

        (r"<script|%3cscript", 40, "XSS script pattern detected"),
        (r"onerror\s*=", 30, "XSS event handler detected"),
        (r"onload\s*=", 30, "XSS event handler detected"),
        (r"javascript:", 30, "JavaScript URL injection pattern"),

        (r"\.\./|\.\.\\", 35, "Path traversal pattern detected"),
        (r"etc/passwd", 45, "Sensitive Linux file path detected"),
        (r"boot\.ini", 35, "Sensitive Windows file path detected"),

        (r"cmd=|exec=|system\(|passthru\(|shell_exec\(", 40, "Command execution pattern detected"),
        (r"wget\s|curl\s", 30, "Remote command download pattern detected"),
        (r"base64_decode|eval\(", 35, "Code execution pattern detected"),
        (r"php://input|php://filter", 35, "PHP wrapper abuse pattern detected"),
    ]

    for pattern, weight, reason in malicious_patterns:
        if re.search(pattern, decoded):
            score += weight
            reasons.append(reason)

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    special_ratio = sum(not c.isalnum() for c in raw) / max(len(raw), 1)
    query_params = raw.count("&") + 1 if "?" in raw else 0

    if encoded_count >= 4:
        score += 15
        reasons.append("Heavy URL encoding detected")

    if special_ratio > 0.38:
        score += 10
        reasons.append("High special-character density")

    if query_params > 8:
        score += 8
        reasons.append("Large number of query parameters")

    if len(raw) > 200:
        score += 6
        reasons.append("Unusually long request")

    return min(score / 100, 1.0), reasons


def ml_score(url: str):
    if not os.path.exists(MODEL_PATH):
        return None

    try:
        model_bundle = joblib.load(MODEL_PATH)
        pipeline = model_bundle["pipeline"]
        return float(pipeline.predict_proba([url])[0][1])
    except Exception:
        return None


def predict_url(url: str) -> dict:
    raw = str(url).strip()

    if not raw:
        raise ValueError("URL is empty.")

    malicious_score, malicious_reasons = detect_malicious(raw)
    defacement_score, defacement_reasons = detect_defacement(raw)
    model_probability = ml_score(raw)

    if model_probability is not None:
        malicious_score = max(malicious_score, model_probability)

    if defacement_score >= 0.35 and defacement_score >= malicious_score:
        label = "Defacement"
        is_malicious = True
        confidence = defacement_score
        reasons = defacement_reasons

    elif malicious_score >= 0.35:
        label = "Malicious"
        is_malicious = True
        confidence = malicious_score
        reasons = malicious_reasons

    else:
        label = "Safe"
        is_malicious = False
        confidence = max(malicious_score, defacement_score)
        reasons = ["No strong malicious or defacement pattern detected"]

    return {
        "url": raw,
        "label": label,
        "is_malicious": bool(is_malicious),
        "confidence": round(confidence, 4),
        "ml_score": round(model_probability, 4) if model_probability is not None else None,
        "malicious_rule_score": round(malicious_score, 4),
        "defacement_rule_score": round(defacement_score, 4),
        "threshold": 0.35,
        "reasons": reasons,
        "features": basic_features(raw),
    }
