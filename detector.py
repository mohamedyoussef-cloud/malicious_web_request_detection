import os
import re
from urllib.parse import unquote
import joblib

MODEL_PATH = "models/malicious_url_model.joblib"


def rule_predict(url: str) -> dict:
    raw = str(url).strip()
    decoded = unquote(raw).lower()

    score = 0
    reasons = []

    checks = [
        (r"union\s+select", 35, "SQL injection pattern: UNION SELECT"),
        (r"or\s+1\s*=\s*1", 30, "SQL injection bypass pattern: OR 1=1"),
        (r"select\s+.*\s+from", 25, "SQL query structure detected"),
        (r"drop\s+table", 35, "Dangerous SQL command detected"),
        (r"<script|%3cscript", 35, "XSS script pattern detected"),
        (r"onerror\s*=", 25, "XSS event handler detected"),
        (r"\.\./|\.\.\\", 30, "Path traversal pattern detected"),
        (r"etc/passwd", 35, "Sensitive Linux file path detected"),
        (r"cmd=|exec=|system\(", 30, "Command execution pattern detected"),
        (r"information_schema|xp_cmdshell", 40, "High-risk database attack pattern"),
        (r"base64", 15, "Base64-related suspicious pattern"),
    ]

    for pattern, weight, reason in checks:
        if re.search(pattern, decoded):
            score += weight
            reasons.append(reason)

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    special_ratio = sum(not c.isalnum() for c in raw) / max(len(raw), 1)
    query_params = raw.count("&") + 1 if "?" in raw else 0

    if encoded_count >= 4:
        score += 15
        reasons.append("Heavy URL encoding detected")

    if special_ratio > 0.35:
        score += 10
        reasons.append("High special-character density")

    if query_params > 8:
        score += 8
        reasons.append("Large number of query parameters")

    if len(raw) > 180:
        score += 6
        reasons.append("Unusually long URL/request")

    confidence = min(score / 100, 1.0)
    is_malicious = confidence >= 0.35

    if not reasons:
        reasons.append("No strong suspicious pattern detected")

    return {
        "url": raw,
        "label": "Malicious" if is_malicious else "Safe",
        "is_malicious": bool(is_malicious),
        "confidence": round(confidence, 4),
        "ml_score": None,
        "rule_score": round(confidence, 4),
        "threshold": 0.35,
        "reasons": reasons,
        "features": {
            "length": len(raw),
            "encoded_patterns": encoded_count,
            "special_character_ratio": round(special_ratio, 4),
            "query_parameter_count": query_params,
            "model_used": os.path.exists(MODEL_PATH),
        },
    }


def predict_url(url: str) -> dict:
    raw = str(url).strip()

    if not raw:
        raise ValueError("URL is empty.")

    if not os.path.exists(MODEL_PATH):
        return rule_predict(raw)

    try:
        model_bundle = joblib.load(MODEL_PATH)
        pipeline = model_bundle["pipeline"]
        threshold = model_bundle.get("threshold", 0.5)

        ml_score = float(pipeline.predict_proba([raw])[0][1])
        rule_result = rule_predict(raw)

        final_score = max(ml_score, rule_result["rule_score"])
        is_malicious = final_score >= threshold

        return {
            "url": raw,
            "label": "Malicious" if is_malicious else "Safe",
            "is_malicious": bool(is_malicious),
            "confidence": round(final_score, 4),
            "ml_score": round(ml_score, 4),
            "rule_score": rule_result["rule_score"],
            "threshold": threshold,
            "reasons": rule_result["reasons"],
            "features": rule_result["features"],
        }

    except Exception:
        return rule_predict(raw)
