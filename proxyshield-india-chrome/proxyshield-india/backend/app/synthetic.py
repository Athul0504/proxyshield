"""Synthetic training data: phishing vs legitimate URL patterns.

This is deliberately a *synthetic* corpus (seeded, reproducible) that encodes
well-documented phishing patterns seen in Indian digital-fraud campaigns:
brand + KYC/OTP keywords on abuse-prone TLDs, look-alike domains, raw-IP hosts,
subdomain tricks, '@' redirection, punycode, shorteners and random-looking
domains. Replace it with a real labelled corpus for production use.
"""
from __future__ import annotations

import random
import string
from typing import Any

from .features import FEATURE_NAMES, extract_features
from .registry import BRAND_DOMAINS, TRUSTED_REGISTRY

WORDS = [
    "shop", "news", "tech", "media", "health", "edu", "travel", "food", "finance",
    "learn", "cloud", "design", "studio", "market", "books", "sports", "weather",
    "careers", "events", "store", "garden", "music", "photo", "recipes", "mobile",
    "energy", "insure", "realty", "agro", "craft", "labs", "global", "city", "daily",
    "village", "kitchen", "fitness", "gadget", "legal", "farm", "metro", "bazaar",
]
LEGIT_TLDS = (["com"] * 40 + ["in"] * 20 + ["org"] * 10 + ["co.in"] * 10 + ["net"] * 5
              + ["edu"] * 3 + ["gov.in"] * 2 + ["io"] * 3 + ["info"] * 2 + ["app"] * 2
              + ["dev"] * 2 + ["blog"] * 1)
LEGIT_SUBS = ["blog", "docs", "mail", "shop", "app", "support", "news", "m", "careers"]
LEGIT_PATH_WORDS = ["products", "about", "contact", "blog", "news", "item", "category",
                    "2024", "2025", "help", "pricing", "search", "careers", "faq",
                    "team", "gallery", "events", "docs", "download", "store"]
SENSITIVE_PATH_WORDS = ["login", "account", "verify", "signin", "claim"]

PHISH_TLDS_BAD = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
                  "support", "icu", "cyou", "buzz", "rest", "monster", "cam", "loan", "win"]
PHISH_TLDS_COMMON = ["com", "in", "net", "online", "site", "info", "co.in", "org"]
PHISH_KEYWORDS = ["kyc", "verify", "update", "secure", "login", "otp", "claim", "refund",
                  "reward", "account", "support", "netbanking", "alert", "unlock",
                  "suspended", "customer", "care", "portal", "helpdesk", "aadhaar"]
PHISH_BRANDS = [b for b in BRAND_DOMAINS if b not in ("github",)] + ["github"]
SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co", "shorturl.at"]
PHISH_PATHS = ["login", "verify", "kyc-update", "secure/login", "account/update", "otp",
               "claim-reward", "netbanking/login", "update-pan", "refund", "unlock-account"]


def _rand_alnum(rng: random.Random, low: int, high: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(low, high)))


def _rand_ip(rng: random.Random) -> str:
    first = rng.choice([13, 34, 45, 52, 64, 103, 104, 139, 157, 185, 194, 203, 223])
    return f"{first}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _mutate(rng: random.Random, word: str) -> str:
    """Typosquat a brand: delete / swap / replace / insert / append a character."""
    if len(word) < 3:
        return word + rng.choice(string.ascii_lowercase)
    i = rng.randrange(1, len(word))
    kind = rng.choice(["delete", "swap", "replace", "insert", "append"])
    if kind == "delete":
        return word[:i] + word[i + 1:]
    if kind == "swap" and i < len(word) - 1:
        return word[:i] + word[i + 1] + word[i] + word[i + 2:]
    if kind == "replace":
        return word[:i] + rng.choice(string.ascii_lowercase) + word[i + 1:]
    if kind == "insert":
        return word[:i] + rng.choice(string.ascii_lowercase) + word[i:]
    return word + rng.choice(["s", "i", "x", "o"])


def _query(rng: random.Random, p: float) -> str:
    if rng.random() > p:
        return ""
    return rng.choice(["?id=%d" % rng.randint(1, 9999), "?ref=home&utm_source=mail",
                       "?q=%s" % rng.choice(WORDS), "?page=%d&sort=new" % rng.randint(1, 20)])


def _legit_dom(rng: random.Random) -> dict[str, Any]:
    has_pw = rng.random() < 0.30
    sensitive = rng.randint(1, 2) if has_pw else (1 if rng.random() < 0.05 else 0)
    urgency = 1 if rng.random() < 0.04 else 0
    return {
        "insecure_form_count": 1 if rng.random() < 0.02 else 0,
        "sensitive_field_count": sensitive,
        "urgency_trigger_count": urgency,
        "has_password_field": has_pw,
    }


def _phish_dom(rng: random.Random) -> dict[str, Any]:
    has_pw = rng.random() < 0.80
    sensitive = rng.randint(1, 4) if (has_pw or rng.random() < 0.7) else 0
    urgency = rng.randint(1, 3) if rng.random() < 0.65 else 0
    return {
        "insecure_form_count": 1 if rng.random() < 0.30 else 0,
        "sensitive_field_count": sensitive,
        "urgency_trigger_count": urgency,
        "has_password_field": has_pw,
    }


def legit_sample(rng: random.Random) -> str:
    roll = rng.random()
    scheme = "https" if rng.random() < 0.93 else "http"
    tld = rng.choice(LEGIT_TLDS)

    if roll < 0.04:  # CDN / cloud hosts look random but are benign
        host = f"d{_rand_alnum(rng, 8, 12)}.{rng.choice(['cloudfront.net', 'amazonaws.com', 'azurewebsites.net'])}"
        return f"https://{host}/{rng.choice(LEGIT_PATH_WORDS)}/{rng.randint(1, 999)}"

    words = rng.sample(WORDS, rng.choice([1, 2]))
    name = ("-" if rng.random() < 0.20 else "").join(words)
    if rng.random() < 0.10:
        name += str(rng.randint(2, 99))
    sub_roll = rng.random()
    sub = "" if sub_roll < 0.55 else ("www." if sub_roll < 0.85 else rng.choice(LEGIT_SUBS) + ".")
    host = f"{sub}{name}.{tld}"

    segments = [rng.choice(LEGIT_PATH_WORDS) for _ in range(rng.choice([0, 1, 1, 2, 3, 4]))]
    if rng.random() < 0.08:
        segments.append(rng.choice(SENSITIVE_PATH_WORDS))
    path = ("/" + "/".join(segments)) if segments else ""
    if segments and rng.random() < 0.20:
        path += rng.choice([".html", ".php", ".aspx"])
    return f"{scheme}://{host}{path}{_query(rng, 0.15)}"


def phishing_sample(rng: random.Random) -> str:
    roll = rng.random()
    brand = rng.choice(PHISH_BRANDS)
    kw1, kw2 = rng.choice(PHISH_KEYWORDS), rng.choice(PHISH_KEYWORDS)
    bad_tld = rng.choice(PHISH_TLDS_BAD)
    any_tld = rng.choice(PHISH_TLDS_BAD if rng.random() < 0.6 else PHISH_TLDS_COMMON)
    scheme = "https" if rng.random() < 0.55 else "http"
    path = "/" + rng.choice(PHISH_PATHS) + rng.choice(["", ".php", ".html", "/index.php"])
    legit_domain = rng.choice(list(TRUSTED_REGISTRY))

    if roll < 0.25:  # brand + keyword
        style = rng.random()
        if style < 0.4:
            host = f"{brand}-{kw1}-{kw2}.{any_tld}"
        elif style < 0.7:
            host = f"{brand}{kw1}.{any_tld}"
        else:
            host = f"{kw1}-{brand}.{any_tld}"
        return f"{scheme}://{host}{path}{_query(rng, 0.2)}"

    if roll < 0.40:  # subdomain trick
        if rng.random() < 0.5:
            host = f"{legit_domain}.{kw1}-{kw2}.{bad_tld}"
        else:
            host = f"{brand}.{kw1}.{rng.choice(WORDS)}.{any_tld}"
        return f"{scheme}://{host}{path}"

    if roll < 0.52:  # raw IP host
        ip = _rand_ip(rng)
        port = rng.choice(["", "", ":8080", ":8443", ":8000"])
        return f"http://{ip}{port}/{brand}{path}"

    if roll < 0.65:  # typosquat
        legit_name = rng.choice(["sbi", "hdfcbank", "icicibank", "uidai", "incometax",
                                 "axisbank", "paytm", "phonepe", "irctc", "npci", "github"])
        squat = _mutate(rng, legit_name)
        tld = rng.choice(["com", "in", "co.in", "net", "org", "gov.in", "online"])
        return f"{scheme}://www.{squat}.{tld}{path}"

    if roll < 0.77:  # random high-entropy domain
        host = f"{_rand_alnum(rng, 8, 14)}.{bad_tld}"
        tail = path if rng.random() < 0.5 else f"/{_rand_alnum(rng, 6, 12)}"
        return f"{scheme}://{host}{tail}"

    if roll < 0.83:  # URL shortener
        return f"https://{rng.choice(SHORTENERS)}/{_rand_alnum(rng, 5, 8)}"

    if roll < 0.88:  # '@' redirection trick
        evil = f"{_rand_alnum(rng, 6, 10)}.{bad_tld}"
        return f"https://www.{legit_domain}@{evil}/{rng.choice(PHISH_PATHS)}"

    if roll < 0.93:  # punycode / IDN look-alike
        return f"{scheme}://xn--{_rand_alnum(rng, 6, 10)}-{rng.choice(['9ua', 'kva', 'q3a'])}.{any_tld}{path}"

    # long suspicious path on a throwaway domain
    host = f"{rng.choice(WORDS)}{rng.randint(10, 999)}.{any_tld}"
    long_path = "/secure/" + "/".join(rng.sample(PHISH_KEYWORDS, 3)) + f"/{brand}/update.php"
    query = f"?acc={_rand_alnum(rng, 8, 14)}&session=%2F{_rand_alnum(rng, 10, 20)}&redirect=%2Flogin"
    return f"{scheme}://{host}{long_path}{query}"


def build_dataset(n_per_class: int = 3000, seed: int = 42, include_samples: bool = False):
    """Return (X, y[, samples]). y: 0 = legitimate, 1 = phishing."""
    rng = random.Random(seed)
    rows: list[list[float]] = []
    labels: list[int] = []
    samples: list[tuple[str, int]] = []

    for _ in range(n_per_class):
        url = legit_sample(rng)
        rows.append(extract_features(url, _legit_dom(rng)).vector)
        labels.append(0)
        if include_samples:
            samples.append((url, 0))

    for _ in range(n_per_class):
        url = phishing_sample(rng)
        rows.append(extract_features(url, _phish_dom(rng)).vector)
        labels.append(1)
        if include_samples:
            samples.append((url, 1))

    assert len(rows[0]) == len(FEATURE_NAMES)
    if include_samples:
        return rows, labels, samples
    return rows, labels
