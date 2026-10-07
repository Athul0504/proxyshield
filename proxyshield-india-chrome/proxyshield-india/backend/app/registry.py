"""Zero-Trust Institutional Registry.

A host is only treated as trusted if it exactly matches a registered domain or
is a true subdomain of one (``login.sbi.co.in`` yes, ``sbi.co.in.evil.com`` no).
Everything not in the registry is *unverified* and must earn its score.
"""
from __future__ import annotations

import os
import ipaddress
import sqlite3
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "proxyshield_domains.db"
)

# domain -> (institution name, category)
TRUSTED_REGISTRY: dict[str, tuple[str, str]] = {
    "sbi.co.in": ("State Bank of India", "Public Sector Bank"),
    "hdfcbank.com": ("HDFC Bank", "Private Bank"),
    "icicibank.com": ("ICICI Bank", "Private Bank"),
    "uidai.gov.in": ("UIDAI (Aadhaar)", "Government Identity"),
    "incometax.gov.in": ("Income Tax Department", "Government Tax"),
    "github.com": ("GitHub", "Developer Platform"),
    "localhost": ("Local development host", "Loopback"),
    "axisbank.com": ("Axis Bank", "Private Bank"),
    "kotak.com": ("Kotak Mahindra Bank", "Private Bank"),
    "pnbindia.in": ("Punjab National Bank", "Public Sector Bank"),
    "bankofbaroda.in": ("Bank of Baroda", "Public Sector Bank"),
    "canarabank.com": ("Canara Bank", "Public Sector Bank"),
    "npci.org.in": ("NPCI (UPI)", "Payments Infrastructure"),
    "rbi.org.in": ("Reserve Bank of India", "Regulator"),
    "irctc.co.in": ("IRCTC", "Government Services"),
    "epfindia.gov.in": ("EPFO", "Government Services"),
    "digilocker.gov.in": ("DigiLocker", "Government Identity"),
    "gst.gov.in": ("GST Portal", "Government Tax"),
    "india.gov.in": ("National Portal of India", "Government Services"),
    "paytm.com": ("Paytm", "Payments"),
    "phonepe.com": ("PhonePe", "Payments"),
    "bankofindia.co.in": ("Bank of India", "Public Sector Bank"),
    "unionbankofindia.co.in": ("Union Bank of India", "Public Sector Bank"),
    "indianbank.in": ("Indian Bank", "Public Sector Bank"),
    "centralbankofindia.co.in": ("Central Bank of India", "Public Sector Bank"),
    "uco.bank.in": ("UCO Bank", "Public Sector Bank"),
    "idbibank.in": ("IDBI Bank", "Private Bank"),
    "indusind.com": ("IndusInd Bank", "Private Bank"),
    "yesbank.in": ("YES Bank", "Private Bank"),
    "federalbank.co.in": ("Federal Bank", "Private Bank"),
    "bandhanbank.com": ("Bandhan Bank", "Private Bank"),

    "amazon.in": ("Amazon India", "E-Commerce"),
    "flipkart.com": ("Flipkart", "E-Commerce"),
    "myntra.com": ("Myntra", "E-Commerce"),

    "google.com": ("Google", "Technology"),
    "microsoft.com": ("Microsoft", "Technology"),
    "apple.com": ("Apple", "Technology"),

    "passportindia.gov.in": ("Passport Seva", "Government Services"),
    "parivahan.gov.in": ("Parivahan", "Government Services"),
    "mygov.in": ("MyGov India", "Government Services"),
    "meity.gov.in": ("MeitY", "Government"),
    "mha.gov.in": ("Ministry of Home Affairs", "Government"),
    "mca.gov.in": ("Ministry of Corporate Affairs", "Government"),
    "esic.gov.in": ("ESIC", "Government Services"),

    "upi.npci.org.in": ("UPI", "Payments Infrastructure"),
    "bhimupi.org.in": ("BHIM", "Payments"),
}

# Brand token -> legitimate registered domains. Used to catch impersonation.
BRAND_DOMAINS: dict[str, list[str]] = {
    "sbi": ["sbi.co.in"],  
    "bankofindia": ["bankofindia.co.in"],
    "unionbank": ["unionbankofindia.co.in"],
    "indianbank": ["indianbank.in"],
    "centralbank": ["centralbankofindia.co.in"],
    "uco": ["uco.bank.in"],
    "idbi": ["idbibank.in"],
    "indusind": ["indusind.com"],
    "yesbank": ["yesbank.in"],
    "federalbank": ["federalbank.co.in"],
    "bandhanbank": ["bandhanbank.com"],
    "amazon": ["amazon.in"],
    "flipkart": ["flipkart.com"],
    "myntra": ["myntra.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "passportindia": ["passportindia.gov.in"],
    "parivahan": ["parivahan.gov.in"],
    "mygov": ["mygov.in"],
    "meity": ["meity.gov.in"],
    "mha": ["mha.gov.in"],
    "mca": ["mca.gov.in"],
    "esic": ["esic.gov.in"],
    "bhim": ["bhimupi.org.in"],
    "hdfc": ["hdfcbank.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "icicibank": ["icicibank.com"],
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"],
    "axisbank": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"],
    "npci": ["npci.org.in"],
    "rbi": ["rbi.org.in"],
    "irctc": ["irctc.co.in"],
    "epfo": ["epfindia.gov.in"],
    "digilocker": ["digilocker.gov.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "github": ["github.com"],
}

# Registered domains that legitimately embed a brand token (hosting platforms).
BRAND_EXEMPT_REGISTERED = {
    "github.io",
    "githubusercontent.com",
    "githubassets.com",
    "github.dev",
    "githubapp.com",
}

@dataclass(frozen=True)
class RegistryMatch:
    verified: bool
    domain: Optional[str] = None
    institution: Optional[str] = None
    category: Optional[str] = None
    trust_level: str = "UNKNOWN"

def normalize_host(host: str) -> str:
    """Normalizes complex strings and URLs down to a raw host."""
    if not host:
        return ""
    host = host.strip().lower()
    if host.startswith("http://") or host.startswith("https://"):
        try:
            host = urlparse(host).hostname or host
        except Exception:
            pass
    return host.split('/')[0].split(':')[0].strip(".")

def is_loopback_host(host: str) -> bool:
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False

def _lookup_in_db(candidates: list[str]) -> Optional[dict]:
    """Fast indexed lookup in SQLite database."""
    if not os.path.exists(DB_PATH):
        return None
    try:
        # Use Read-Only URI mode for fast, lock-free parallel reads
        with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" * len(candidates))
            # Order by length descending ensures we match the most specific subdomain
            query = f"""
                SELECT domain, organization, category, trust_level 
                FROM trusted_domains 
                WHERE domain IN ({placeholders})
                ORDER BY length(domain) DESC
                LIMIT 1
            """
            cursor.execute(query, candidates)
            row = cursor.fetchone()
            if row:
                return {
                    "domain": row[0],
                    "organization": row[1],
                    "category": row[2],
                    "trust_level": row[3]
                }
    except sqlite3.Error:
        return None
    return None

def match_registry(raw_input: str) -> RegistryMatch:
    """Exact or true-subdomain match only. Never substring matching."""
    host = normalize_host(raw_input)
    if not host:
        return RegistryMatch(False)

    if is_loopback_host(host):
        name, category = TRUSTED_REGISTRY["localhost"]
        return RegistryMatch(True, "localhost", name, category, trust_level="VERIFIED")

    # 1. Check existing High-Confidence Memory Registry
    for domain, (name, category) in TRUSTED_REGISTRY.items():
        if host == domain or host.endswith("." + domain):
            return RegistryMatch(True, domain, name, category, trust_level="VERIFIED")
            
    # 2. Check Large Dataset Registry in SQLite
    # Generate true subdomains (e.g., 'a.b.com' -> ['a.b.com', 'b.com', 'com'])
    parts = host.split('.')
    candidates = ['.'.join(parts[i:]) for i in range(len(parts))]
    
    db_match = _lookup_in_db(candidates)
    if db_match:
        # If it found 'google.com' in DB, treat as legitimate match
        return RegistryMatch(
            verified=True,
            domain=db_match["domain"],
            institution=db_match["organization"],
            category=db_match["category"],
            trust_level=db_match["trust_level"]
        )

    return RegistryMatch(False)

def is_legit_for_brand(host: str, brand: str) -> bool:
    """True when ``host`` belongs to a domain that legitimately owns ``brand``."""
    host = normalize_host(host)
    for domain in BRAND_DOMAINS.get(brand, []):
        if host == domain or host.endswith("." + domain):
            return True
    return False