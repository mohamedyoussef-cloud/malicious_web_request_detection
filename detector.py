import os
import re
import math
import joblib
from urllib.parse import urlparse, unquote


MODEL_PATH = "models/malicious_url_model.joblib"


SUSPICIOUS_KEYWORDS = [
    "select", "union", "insert", "drop", "delete", "update",
    "script", "alert", "onerror", "onload", "cmd", "exec",
    "passwd", "etc/passwd", "../", "..\\", "base64",
    "sleep", "benchmark", "eval", "document.cookie",
    "<script", "%3cscript", "wget", "curl", " OR ", "' OR",
    "\" OR", "--", "#", "information_schema", "xp_cmdshell"
]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(text)

    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_features(url: str) -> dict:
    raw = str(url).strip()
    decoded = unquote(raw).lower()

    safe_url = raw if "://" in raw else "http://" + raw
    parsed = urlparse(safe_url)

    query = parsed.query or ""
    path = parsed.path or ""

    length = len(raw)
    digit_count = sum(c.isdigit() for c in raw)
    special_count = sum(not c.isalnum() for c in raw)
    encoded_triplets = len(re.findall(r"%[0-9a-fA-F]{2}", raw))

    suspicious_hits = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in decoded:
            suspicious_hits += 1

    delimiter_count = sum(
        raw.count(x) for x in ["/", "?", "&", "=", ".", "-", "_", "%", ";", ":"]
    )

    features = {
        "url_length": length,
        "digit_count": digit_count,
        "slash_count": raw.count("/"),
        "backslash_count": raw.count("\\"),
        "question_count": raw.count("?"),
        "ampersand_count": raw.count("&"),
        "equals_count": raw.count("="),
        "percent_count": raw.count("%"),
        "dot_count": raw.count("."),
        "dotdot_count": raw.count(".."),
        "dash_count": raw.count("-"),
        "underscore_count": raw.count("_"),
        "colon_count": raw.count(":"),
        "semicolon_count": raw.count(";"),
        "open_parenthesis_count": raw.count("("),
        "close_parenthesis_count": raw.count(")"),
        "whitespace_count": sum(c.isspace() for c in raw),
        "special_char_count": special_count,
        "entropy": shannon_entropy(raw),
        "encoded_triplet_count": encoded_triplets,
        "suspicious_keyword_count": suspicious_hits,
        "path_depth": path.count("/"),
        "query_param_count": query.count("&") + 1 if query else 0,
        "digit_ratio": digit_count / max(length, 1),
        "special_char_ratio": special_count / max(length, 1),
        "encoding_ratio": raw.count("%") / max(length, 1),
        "delimiter_ratio": delimiter_count / max(length, 1),
    }

    return features


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "Model file not found. Run train_model.py first, then upload "
            "models/malicious_url_model.joblib."
        )

    return joblib.load(MODEL_PATH)


def rule_based_score(url: str) -> float:
    raw = str(url).strip()
    decoded = unquote(raw).lower()

    score = 0.0

    high_risk_patterns = [
        r"union\s+select",
        r"select\s+.*\s+from",
        r"or\s+1\s*=\s*1",
        r"drop\s+table",
        r"<script",
        r"onerror\s*=",
        r"onload\s*=",
        r"\.\./",
        r"\.\.\\",
        r"etc/passwd",
        r"cmd=",
        r"exec",
        r"base64",
        r"information_schema",
        r"xp_cmdshell",
    ]

    for pattern in high_risk_patterns:
        if re.search(pattern, decoded):
            score += 0.18

    features = extract_features(raw)

    if features["encoded_triplet_count"] >= 3:
        score += 0.12

    if features["suspicious_keyword_count"] >= 2:
        score += 0.18

    if features["special_char_ratio"] > 0.35:
        score += 0.08

    if features["dotdot_count"] > 0:
        score += 0.15

    if features["query_param_count"] > 8:
        score += 0.05

    return min(score, 1.0)


def explain_detection(url: str, features: dict) -> list:
    raw = str(url).strip()
    decoded = unquote(raw).lower()

    reasons = []

    if re.search(r"union\s+select", decoded):
        reasons.append("SQL injection pattern detected: UNION SELECT")

    if re.search(r"or\s+1\s*=\s*1", decoded):
        reasons.append("SQL injection bypass pattern detected: OR 1=1")

    if "<script" in decoded or "onerror=" in decoded or "onload=" in decoded:
        reasons.append("Possible XSS script pattern detected")

    if features["dotdot_count"] > 0:
        reasons.append("Path traversal pattern detected")

    if "etc/passwd" in decoded:
        reasons.append("Sensitive Linux file path detected")

    if features["encoded_triplet_count"] >= 3:
        reasons.append("Heavy URL encoding detected")

    if features["suspicious_keyword_count"] > 0:
        reasons.append("Suspicious security-related keywords found")

    if features["special_char_ratio"] > 0.35:
        reasons.append("High special-character density")

    if features["query_param_count"] > 8:
        reasons.append("Large number of query parameters")

    if not reasons:
        reasons.append("No strong suspicious pattern detected")

    return reasons


def predict_url(url: str) -> dict:
    if not str(url).strip():
        raise ValueError("URL is empty.")

    model_bundle = load_model()

    pipeline = model_bundle["pipeline"]
    threshold = model_bundle.get("threshold", 0.5)

    ml_probability = float(pipeline.predict_proba([url])[0][1])
    rules_probability = rule_based_score(url)

    final_score = max(ml_probability, rules_probability)
    is_malicious = final_score >= threshold

    features = extract_features(url)
    reasons = explain_detection(url, features)

    return {
        "url": url,
        "label": "Malicious" if is_malicious else "Safe",
        "is_malicious": bool(is_malicious),
        "confidence": round(final_score, 4),
        "ml_score": round(ml_probability, 4),
        "rule_score": round(rules_probability, 4),
        "threshold": threshold,
        "reasons": reasons,
        "features": features,
    }
