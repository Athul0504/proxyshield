"""Lexical, structural and DOM-telemetry feature extraction.

The same extractor is used for training (synthetic URLs) and for inference, so
the model never sees a feature definition at runtime that it was not trained on.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import unquote, urlsplit

from .registry import BRAND_DOMAINS, BRAND_EXEMPT_REGISTERED, is_legit_for_brand

FEATURE_NAMES: list[str] = [
    "url_length",
    "host_length",
    "host_dot_count",
    "subdomain_depth",
    "is_ip_host",
    "host_entropy",
    "host_hyphen_count",
    "host_digit_ratio",
    "suspicious_tld",
    "has_at_symbol",
    "has_punycode",
    "keyword_hits",
    "brand_impersonation",
    "typosquat",
    "is_http",
    "url_shortener",
    "non_standard_port",
    "path_depth",
    "special_char_ratio",
    "insecure_form",
    "sensitive_field_count",
    "urgency_count",
    "has_password_field",
]

# Hard caps so a single absurd value cannot dominate a linear model.
FEATURE_CAPS: dict[str, float] = {
    "url_length": 300,
    "host_length": 100,
    "host_dot_count": 10,
    "subdomain_depth": 8,
    "host_entropy": 5.0,
    "host_hyphen_count": 8,
    "path_depth": 10,
    "keyword_hits": 6,
    "sensitive_field_count": 6,
    "urgency_count": 6,
}

MULTI_PART_SUFFIXES = {
    "co.in", "gov.in", "org.in", "net.in", "ac.in", "nic.in", "res.in",
    "edu.in", "firm.in", "gen.in", "ind.in", "co.uk", "org.uk", "ac.uk",
    "gov.uk", "com.au", "co.jp", "com.br", "co.za", "co.nz", "com.sg",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "support", "zip", "mov", "country", "kim", "loan", "win", "bid", "icu",
    "cyou", "buzz", "rest", "monster", "cam", "fit", "gdn", "men", "party",
    "review", "stream", "download", "racing", "science", "date", "faith",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "buff.ly",
}

# Matched anywhere in host/path/query.
SUBSTRING_KEYWORDS = (
    "kyc", "verify", "verification", "update-account", "account-update",
    "secure-login", "claim", "aadhaar", "aadhar", "refund", "reward",
    "suspend", "unlock", "bonus", "lottery", "netbanking", "password",
    "login", "signin",
)
# Too short to match as substrings without false positives (e.g. "pan" in "company").
TOKEN_KEYWORDS = {"otp", "pan", "upi", "cvv"}


@dataclass
class ParsedUrl:
    raw: str
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    has_at: bool
    is_ip: bool
    is_private_ip: bool
    registered_domain: str
    name_label: str
    suffix: str
    subdomain_labels: list[str]


@dataclass
class FeatureSet:
    vector: list[float]
    raw: dict[str, float]
    context: dict[str, Any] = field(default_factory=dict)


def parse_url(url: str) -> ParsedUrl:
    raw = (url or "").strip()
    try:
        parts = urlsplit(raw)
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower().strip(".")
        try:
            port = parts.port
        except ValueError:
            port = None
        path, query = parts.path or "", parts.query or ""
        netloc = parts.netloc or ""
    except ValueError:
        scheme, host, port, path, query, netloc = "", "", None, "", "", ""

    has_at = "@" in netloc

    is_ip = False
    is_private = False
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        # Obfuscated numeric hosts such as http://3232235777/ or http://0xC0A80001/
        if re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]{6,8}", host):
            is_ip = True

    registered, name, suffix, subs = split_domain(host) if host and not is_ip else (host, host, "", [])
    return ParsedUrl(raw, scheme, host, port, path, query, has_at, is_ip, is_private,
                     registered, name, suffix, subs)


def split_domain(host: str) -> tuple[str, str, str, list[str]]:
    labels = host.split(".")
    if len(labels) < 2:
        return host, host, "", []
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        suffix, name, used = last_two, labels[-3], 3
    else:
        suffix, name, used = labels[-1], labels[-2], 2
    return f"{name}.{suffix}", name, suffix, labels[: len(labels) - used]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def find_keywords(text: str) -> list[str]:
    lowered = unquote(text).lower()
    tokens = set(re.split(r"[^a-z0-9]+", lowered))
    hits = [k for k in SUBSTRING_KEYWORDS if k in lowered]
    hits += sorted(k for k in TOKEN_KEYWORDS if k in tokens)
    return hits


def find_brands(parsed: ParsedUrl) -> list[str]:
    """Brand tokens present in the hostname of a domain that does not own them."""
    host = parsed.host
    if not host or parsed.is_ip or parsed.registered_domain in BRAND_EXEMPT_REGISTERED:
        return []
    tokens = set(re.split(r"[^a-z]+", host))
    found = []
    for brand in BRAND_DOMAINS:
        present = brand in tokens or (len(brand) >= 5 and brand in host)
        if present and not is_legit_for_brand(host, brand):
            found.append(brand)
    return sorted(found, key=len, reverse=True)


def find_typosquat(parsed: ParsedUrl) -> Optional[str]:
    """Return the brand this domain label is a near-miss of, if any."""
    name = parsed.name_label
    if not name or parsed.is_ip or parsed.registered_domain in BRAND_EXEMPT_REGISTERED:
        return None
    for brand in BRAND_DOMAINS:
        if name == brand or is_legit_for_brand(parsed.host, brand):
            continue
        n = len(brand)
        if abs(len(name) - n) > 2:
            continue
        if n <= 3:
            squat = (name.startswith(brand) or name.endswith(brand)) and len(name) - n <= 2
        elif n <= 6:
            squat = levenshtein(name, brand) <= 1
        else:
            squat = levenshtein(name, brand) <= 2
        if squat:
            return brand
    return None


def _cap(name: str, value: float) -> float:
    cap = FEATURE_CAPS.get(name)
    return float(min(value, cap)) if cap is not None else float(value)


def extract_features(url: str, dom: Optional[dict[str, Any]] = None) -> FeatureSet:
    p = parse_url(url)
    dom = dom or {}
    host_no_dots = p.host.replace(".", "")
    text = f"{p.host}{p.path}?{p.query}"

    keywords = find_keywords(text)
    brands = find_brands(p)
    squat = find_typosquat(p)
    path_segments = [s for s in p.path.split("/") if s]
    tail = p.path + p.query
    special = sum(1 for ch in tail if not (ch.isalnum() or ch in "/-._"))

    raw: dict[str, float] = {
        "url_length": len(p.raw),
        "host_length": len(p.host),
        "host_dot_count": p.host.count("."),
        "subdomain_depth": len(p.subdomain_labels),
        "is_ip_host": 1.0 if (p.is_ip and not p.is_private_ip) else 0.0,
        "host_entropy": shannon_entropy(host_no_dots),
        "host_hyphen_count": p.host.count("-"),
        "host_digit_ratio": (sum(ch.isdigit() for ch in host_no_dots) / len(host_no_dots)) if host_no_dots else 0.0,
        "suspicious_tld": 1.0 if p.suffix.split(".")[-1] in SUSPICIOUS_TLDS else 0.0,
        "has_at_symbol": 1.0 if p.has_at else 0.0,
        "has_punycode": 1.0 if "xn--" in p.host else 0.0,
        "keyword_hits": len(keywords),
        "brand_impersonation": 1.0 if brands else 0.0,
        "typosquat": 1.0 if squat else 0.0,
        "is_http": 1.0 if p.scheme == "http" else 0.0,
        "url_shortener": 1.0 if (p.registered_domain in URL_SHORTENERS or p.host in URL_SHORTENERS) else 0.0,
        "non_standard_port": 1.0 if (p.port is not None and p.port not in (80, 443)) else 0.0,
        "path_depth": len(path_segments),
        "special_char_ratio": (special / len(tail)) if tail else 0.0,
        "insecure_form": 1.0 if int(dom.get("insecure_form_count", 0) or 0) > 0 else 0.0,
        "sensitive_field_count": int(dom.get("sensitive_field_count", 0) or 0),
        "urgency_count": int(dom.get("urgency_trigger_count", 0) or 0),
        "has_password_field": 1.0 if dom.get("has_password_field") else 0.0,
    }
    raw = {name: _cap(name, value) for name, value in raw.items()}

    context = {
        "host": p.host,
        "scheme": p.scheme,
        "port": p.port,
        "tld": p.suffix,
        "name_label": p.name_label,
        "registered_domain": p.registered_domain,
        "is_private_ip": p.is_private_ip,
        "keywords": keywords,
        "brands": brands,
        "typosquat_of": squat,
        "sensitive_fields": list(dom.get("sensitive_fields", []) or []),
        "urgency_triggers": list(dom.get("urgency_triggers", []) or []),
        "insecure_form_count": int(dom.get("insecure_form_count", 0) or 0),
    }
    return FeatureSet(vector=[raw[name] for name in FEATURE_NAMES], raw=raw, context=context)
