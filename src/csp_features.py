"""Feature engineering and rule-based labeling for CSP headers."""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


FEATURE_COLUMNS = [
    "unsafe_inline",
    "unsafe_eval",
    "strict_dynamic",
    "has_nonce",
    "has_sha256",
    "has_wildcard",
    "has_http",
    "has_https",
    "has_blob",
    "has_data",
    "has_ws_wss",
    "directive_count",
    "csp_length",
]


LABEL_ORDER = ["Weak", "Medium", "Strong"]


def normalize_csp(csp: object) -> str:
    """Return a safe lowercase CSP string."""
    if csp is None:
        return ""
    return str(csp).strip()


def extract_csp_features(csp: object) -> Dict[str, int]:
    """Extract binary and numeric security features from a CSP header."""
    text = normalize_csp(csp)
    lower = text.lower()
    directives = [part.strip() for part in text.split(";") if part.strip()]

    return {
        "unsafe_inline": int("'unsafe-inline'" in lower or "unsafe-inline" in lower),
        "unsafe_eval": int("'unsafe-eval'" in lower or "unsafe-eval" in lower),
        "strict_dynamic": int("'strict-dynamic'" in lower or "strict-dynamic" in lower),
        "has_nonce": int(bool(re.search(r"nonce-[a-z0-9+/_=-]+", lower))),
        "has_sha256": int("sha256-" in lower),
        "has_wildcard": int("*" in lower),
        "has_http": int(bool(re.search(r"(^|[\s;])http:", lower))),
        "has_https": int("https:" in lower),
        "has_blob": int("blob:" in lower),
        "has_data": int("data:" in lower),
        "has_ws_wss": int("ws:" in lower or "wss:" in lower),
        "directive_count": len(directives),
        "csp_length": len(text),
    }


def calculate_security_score(csp: object) -> int:
    """Score a CSP from 0 to 100 using the project rule system."""
    features = extract_csp_features(csp)
    score = 75

    if features["unsafe_inline"]:
        score -= 25
    if features["unsafe_eval"]:
        score -= 25
    if features["has_wildcard"]:
        score -= 15
    if features["has_http"]:
        score -= 10
    if features["has_nonce"]:
        score += 10
    if features["strict_dynamic"]:
        score += 10

    return max(0, min(100, score))


def label_from_score(score: int) -> str:
    """Convert a numeric security score into Weak, Medium, or Strong."""
    if score <= 40:
        return "Weak"
    if score <= 70:
        return "Medium"
    return "Strong"


def label_csp(csp: object) -> Tuple[int, str]:
    """Return the rule-based score and label for one CSP string."""
    score = calculate_security_score(csp)
    return score, label_from_score(score)


def explain_csp(csp: object) -> List[str]:
    """Generate beginner-friendly explanations for detected CSP risks."""
    features = extract_csp_features(csp)
    messages: List[str] = []

    if not normalize_csp(csp):
        return ["No CSP header was provided, so the page has no browser-enforced CSP protection."]
    if features["unsafe_inline"]:
        messages.append("Uses unsafe-inline, which allows inline scripts/styles and weakens XSS protection.")
    if features["unsafe_eval"]:
        messages.append("Uses unsafe-eval, which allows dynamic JavaScript evaluation and increases XSS risk.")
    if features["has_wildcard"]:
        messages.append("Uses wildcard sources, which can allow content from too many origins.")
    if features["has_http"]:
        messages.append("Allows plain HTTP sources, which can expose content to network tampering.")
    if features["has_data"]:
        messages.append("Allows data: sources, which can be risky for scripts or objects.")
    if features["has_blob"]:
        messages.append("Allows blob: sources; this may be needed, but should be limited carefully.")
    if features["has_nonce"]:
        messages.append("Includes nonce-based protection, which is a strong CSP practice.")
    if features["strict_dynamic"]:
        messages.append("Includes strict-dynamic, which can strengthen script loading when paired with nonces/hashes.")
    if features["has_sha256"]:
        messages.append("Includes SHA-256 hashes, which can safely allow specific inline content.")
    if not messages:
        messages.append("No major high-risk patterns were detected in this CSP string.")

    return messages
