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
    "<script", "%3cscript", "wget", "curl"
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
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def extract_features(url: str) -> dict:
    raw = str(url).strip()
    decoded = unquote(raw.lower())

    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    query = parsed.query or ""
    path = parsed.path or ""

    length = len(raw)
    digit_count = sum(c.isdigit() for c in raw)
    special_count = sum(not c.isalnum() for c in raw)
    suspicious_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in decoded)

    return {
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
        "encoded_triplet_count": len(re.findall(r"%[0-9a-fA-F]{2}", raw)),
        "suspicious_keyword_count": suspicious_hits,
        "path_depth": path.count("/"),
        "query_param_count": query.count("&") + 1 if query else 0,
        "digit_ratio": digit_count / max(length, 1),
        "special_char_ratio": special_count / max(length, 1),
        "encoding_ratio": raw.count("%") / max(length, 1),
        "delimiter_ratio": sum(raw.count(x) for x in ["/", "?", "&", "=", ".", "-", "_"]) / max(length, 1),
    }


def load_model():
    return joblib.load(MODEL_PATH)


def predict_url(url: str):
    model_bundle = load_model()
    pipeline = model_bundle["pipeline"]
    threshold = model_bundle.get("threshold", 0.5)

    probability = pipeline.predict_proba([url])[0][1]
    label = int(probability >= threshold)
    features = extract_features(url)

    reasons = []
    if features["suspicious_keyword_count"] > 0:
        reasons.append("Contains suspicious attack-related keywords")
    if features["encoded_triplet_count"] > 2:
        reasons.append("Contains heavy URL encoding")
    if features["dotdot_count"] > 0:
        reasons.append("Contains path traversal pattern")
    if features["special_char_ratio"] > 0.35:
        reasons.append("High special-character density")
    if features["query_param_count"] > 8:
        reasons.append("Large number of query parameters")
    if not reasons:
        reasons.append("No strong suspicious pattern detected")

    return {
        "url": url,
        "label": "Malicious" if label == 1 else "Safe",
        "is_malicious": bool(label),
        "confidence": round(float(probability), 4),
        "threshold": threshold,
        "reasons": reasons,
        "features": features,
    }
