"""Explainable-AI attribution.

For a linear model the log-odds contribution of every feature is exact
(coefficient x standardised value). Those contributions are converted into
*score points* by proportional allocation, which stays stable even when the
classifier is saturated (p close to 0 or 1):

  * Risk-raising signals (contribution > 0) share the points the model added
    above the Zero-Trust floor:  SCALE * p
  * Risk-lowering signals (contribution < 0) share the points that kept the
    score from rising further:  -SCALE * (1 - p)

Positive impact = raises risk, negative = lowers it.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from .features import FEATURE_NAMES, FeatureSet
from .model import Decomposition
from .registry import BRAND_DOMAINS

MIN_THREAT_IMPACT = 1.5   # points
MIN_SAFE_IMPACT = 1.5     # points (absolute)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _brand_label(ctx: dict[str, Any]) -> str:
    brands = ctx.get("brands") or []
    return brands[0].upper() if brands else "a trusted brand"


# feature -> function(raw, ctx) returning threat text, or None when the raw
# value is not actually remarkable (guards against "mean-level" noise).
THREAT_TEXT: dict[str, Callable[[dict[str, float], dict[str, Any]], Optional[str]]] = {
    "url_length": lambda r, c: f"Unusually long URL ({int(r['url_length'])} characters)" if r["url_length"] >= 75 else None,
    "host_length": lambda r, c: f"Very long hostname ({int(r['host_length'])} characters)" if r["host_length"] >= 28 else None,
    "host_dot_count": lambda r, c: f"Hostname has {int(r['host_dot_count'])} dots, a sign of stacked subdomains" if r["host_dot_count"] >= 4 else None,
    "subdomain_depth": lambda r, c: f"Deep subdomain nesting ({_plural(int(r['subdomain_depth']), 'level')}), a common disguise tactic" if r["subdomain_depth"] >= 2 else None,
    "is_ip_host": lambda r, c: "Site is served from a raw IP address instead of a domain name" if r["is_ip_host"] else None,
    "host_entropy": lambda r, c: f"Domain name looks randomly generated (entropy {r['host_entropy']:.2f} bits)" if r["host_entropy"] >= 3.3 else None,
    "host_hyphen_count": lambda r, c: f"Hostname contains {_plural(int(r['host_hyphen_count']), 'hyphen')}, typical of look-alike domains" if r["host_hyphen_count"] >= 2 else None,
    "host_digit_ratio": lambda r, c: f"Digits make up {r['host_digit_ratio'] * 100:.0f}% of the hostname" if r["host_digit_ratio"] >= 0.2 else None,
    "suspicious_tld": lambda r, c: f"High-abuse top-level domain (.{str(c.get('tld', '')).split('.')[-1]})" if r["suspicious_tld"] else None,
    "has_at_symbol": lambda r, c: "URL contains '@' which can disguise the real destination" if r["has_at_symbol"] else None,
    "has_punycode": lambda r, c: "Hostname uses punycode (xn--), enabling look-alike characters" if r["has_punycode"] else None,
    "keyword_hits": lambda r, c: f"Social-engineering keywords in URL: {', '.join(c.get('keywords', [])[:5])}" if c.get("keywords") else None,
    "brand_impersonation": lambda r, c: f"Impersonates trusted brand '{_brand_label(c)}' on an unrelated domain" if r["brand_impersonation"] else None,
    "typosquat": lambda r, c: f"Domain '{c.get('name_label')}' is a look-alike of '{c.get('typosquat_of')}'" if r["typosquat"] else None,
    "is_http": lambda r, c: "Connection is not encrypted (plain HTTP)" if r["is_http"] else None,
    "url_shortener": lambda r, c: "Link shortener hides the real destination" if r["url_shortener"] else None,
    "non_standard_port": lambda r, c: f"Non-standard port :{c.get('port')} in URL" if r["non_standard_port"] else None,
    "path_depth": lambda r, c: f"Deeply nested URL path ({int(r['path_depth'])} levels)" if r["path_depth"] >= 4 else None,
    "special_char_ratio": lambda r, c: "High density of encoded or special characters in path/query" if r["special_char_ratio"] >= 0.12 else None,
    "insecure_form": lambda r, c: f"Page submits {_plural(int(c.get('insecure_form_count', 1)), 'form')} over insecure HTTP" if r["insecure_form"] else None,
    "sensitive_field_count": lambda r, c: f"Page requests sensitive fields: {', '.join(c.get('sensitive_fields', [])) or 'identity/credential inputs'}" if r["sensitive_field_count"] > 0 else None,
    "urgency_count": lambda r, c: f"Urgency pressure tactics on page: {', '.join(c.get('urgency_triggers', [])) or 'pressure language'}" if r["urgency_count"] > 0 else None,
    "has_password_field": lambda r, c: "Page contains a password entry field" if r["has_password_field"] else None,
}

# Reassuring text, only for features where "absence of risk" is meaningful.
SAFE_TEXT: dict[str, Callable[[dict[str, float], dict[str, Any]], Optional[str]]] = {
    "is_http": lambda r, c: "Connection uses HTTPS encryption" if (c.get("scheme") == "https") else None,
    "brand_impersonation": lambda r, c: "No trusted-brand impersonation detected" if not r["brand_impersonation"] else None,
    "keyword_hits": lambda r, c: "No social-engineering keywords in the URL" if not r["keyword_hits"] else None,
}


def attribute(features: FeatureSet, decomposition: Decomposition, scale: float,
              max_threats: int = 6, max_safe: int = 2) -> list[dict[str, Any]]:
    """Return ranked, human-readable evidence items with score-point impacts."""
    p = decomposition.probability
    positives = [max(c, 0.0) for c in decomposition.contributions]
    negatives = [max(-c, 0.0) for c in decomposition.contributions]
    pos_total, neg_total = sum(positives), sum(negatives)
    threats: list[dict[str, Any]] = []
    safes: list[dict[str, Any]] = []

    for index, name in enumerate(FEATURE_NAMES):
        if positives[index] > 0 and pos_total > 0:
            impact = scale * p * positives[index] / pos_total
        elif negatives[index] > 0 and neg_total > 0:
            impact = -scale * (1.0 - p) * negatives[index] / neg_total
        else:
            continue

        if impact >= MIN_THREAT_IMPACT and name in THREAT_TEXT:
            text = THREAT_TEXT[name](features.raw, features.context)
            if text:
                threats.append({"feature": name, "text": text, "severity": "threat",
                                "impact": round(impact, 1), "source": "model"})
        elif impact <= -MIN_SAFE_IMPACT and name in SAFE_TEXT:
            text = SAFE_TEXT[name](features.raw, features.context)
            if text:
                safes.append({"feature": name, "text": text, "severity": "safe",
                              "impact": round(impact, 1), "source": "model"})

    threats.sort(key=lambda item: item["impact"], reverse=True)
    safes.sort(key=lambda item: item["impact"])
    return threats[:max_threats] + safes[:max_safe]


def institution_for_brand(brand: str) -> Optional[str]:
    domains = BRAND_DOMAINS.get(brand)
    return domains[0] if domains else None
