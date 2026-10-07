"""ProxyShield risk engine.

Pipeline:
  1. Zero-Trust Institutional Registry   -> verified hosts short-circuit to LOW
  2. Lexical & structural feature extraction (+ DOM telemetry)
  3. Scikit-learn threat classifier       -> probability of phishing
  4. Zero-Trust scoring                   -> unverified hosts never score LOW
  5. Policy floors                        -> hard-evidence rules that cap how low a score can go
  6. XAI attribution                      -> exact per-signal point impacts
"""
from __future__ import annotations

import time
from typing import Any, Optional

from .features import FEATURE_NAMES, FeatureSet, extract_features, parse_url
from .model import ThreatModel
from .registry import BRAND_DOMAINS, TRUSTED_REGISTRY, match_registry
from .xai import attribute

ENGINE_NAME = "ProxyShield AI Risk Engine"
ENGINE_VERSION = "1.0.0"

ZERO_TRUST_FLOOR = 35          # an unverified domain can never score below MEDIUM
SCALE = 100 - ZERO_TRUST_FLOOR  # points the model can add on top of the floor
VERIFIED_SCORE = 12

STRONG_KEYWORDS = {"kyc", "otp", "aadhaar", "aadhar", "verify", "verification", "claim",
                   "refund", "reward", "update-account", "secure-login"}

VERDICTS = {
    "LOW": "Trusted: domain verified in the institutional registry.",
    "MEDIUM": "Unverified: proceed with caution.",
    "HIGH": "Highly suspicious: avoid entering personal or banking details.",
    "CRITICAL": "Likely phishing or fraud: do not enter credentials or OTPs.",
}


def level_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _dom_dict(dom_signals: Optional[dict[str, Any]]) -> dict[str, Any]:
    return dom_signals or {}


class RiskEngine:
    def __init__(self, n_per_class: int = 3000, seed: int = 42) -> None:
        self.model = ThreatModel(seed=seed, n_per_class=n_per_class)
        self.metrics: dict[str, float] = {}

    def start(self) -> dict[str, float]:
        self.metrics = self.model.train()
        return self.metrics

    # ------------------------------------------------------------------ policy
    def _policy_rules(self, fs: FeatureSet) -> list[dict[str, Any]]:
        raw, ctx = fs.raw, fs.context
        rules: list[dict[str, Any]] = []

        def add(feature: str, floor: int, text: str) -> None:
            rules.append({"feature": feature, "floor": floor, "text": text})

        if raw["brand_impersonation"]:
            brand = ctx["brands"][0]
            owner = BRAND_DOMAINS[brand][0]
            add("brand_impersonation", 88,
                f"Policy rule: uses the '{brand}' brand but is not {owner}")
        if raw["typosquat"]:
            add("typosquat", 85,
                f"Policy rule: look-alike of trusted brand '{ctx['typosquat_of']}'")
        if raw["has_at_symbol"]:
            add("has_at_symbol", 80, "Policy rule: '@' in the address hides the true destination")
        if raw["is_ip_host"]:
            add("is_ip_host", 70, "Policy rule: public IP address used instead of a domain name")
        if raw["has_punycode"]:
            add("has_punycode", 65, "Policy rule: punycode host can imitate a trusted domain")
        if raw["url_shortener"]:
            add("url_shortener", 55, "Policy rule: shortened link hides the final destination")
        strong = [k for k in ctx["keywords"] if k in STRONG_KEYWORDS]
        if strong and (raw["suspicious_tld"] or raw["is_http"] or raw["brand_impersonation"]):
            add("keyword_hits", 80,
                f"Policy rule: unverified domain with KYC/credential keywords ({', '.join(strong[:3])}) "
                "on a risky transport or TLD")
        if raw["insecure_form"] and raw["sensitive_field_count"] > 0:
            add("insecure_form", 75,
                "Policy rule: sensitive fields are submitted over insecure HTTP")
        if raw["sensitive_field_count"] > 0 and raw["urgency_count"] >= 1:
            add("urgency_count", 70,
                "Policy rule: unverified page combines credential fields with urgency pressure")
        return rules

    # ----------------------------------------------------------------- analyze
    def analyze(self, url: str, dom_signals: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        started = time.perf_counter()
        parsed = parse_url(url)
        if parsed.scheme not in ("http", "https", "file"):
            raise ValueError("Only http, https and file URLs can be analysed")

        is_file = parsed.scheme == "file"
        hostname = "local-file" if is_file else parsed.host
        dom = _dom_dict(dom_signals)
        registry = None if is_file else match_registry(parsed.host)

        if registry and registry.verified:
            payload = self._verified_payload(url, hostname, registry, parsed.scheme, dom)
        else:
            payload = self._unverified_payload(url, hostname, dom, is_file)

        payload["dom_signals_used"] = bool(dom_signals)
        payload["analysis_ms"] = round((time.perf_counter() - started) * 1000, 2)
        payload["engine"] = {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "model": "StandardScaler + LogisticRegression (synthetic phishing corpus)",
            "metrics": self.metrics,
        }
        return payload

    # ---------------------------------------------------------------- verified
    def _verified_payload(self, url: str, hostname: str, registry, scheme: str,
                          dom: dict[str, Any]) -> dict[str, Any]:
        score = VERIFIED_SCORE
        evidence: list[dict[str, Any]] = [{
            "text": f"Domain verified in Zero-Trust Institutional Registry: {registry.institution} ({registry.domain})",
            "severity": "safe", "impact": 0.0, "feature": "registry", "source": "registry"}]

        loopback = registry.domain == "localhost"
        if scheme == "https" or loopback:
            evidence.append({"text": "Connection is safe", "severity": "safe", "impact": 0.0,
                             "feature": "is_http", "source": "registry"})
        else:
            score = max(score, 35)
            evidence.append({"text": "Trusted domain served over unencrypted HTTP (possible downgrade attack)",
                             "severity": "warn", "impact": 0.0, "feature": "is_http", "source": "registry"})

        if int(dom.get("insecure_form_count", 0) or 0) > 0:
            score = max(score, 35)
            evidence.append({"text": "Page contains forms that submit over insecure HTTP",
                             "severity": "warn", "impact": 0.0, "feature": "insecure_form", "source": "dom"})

        verdict = None if score <= VERIFIED_SCORE else (
            "Trusted domain, but the connection is not fully safe: verify before proceeding.")
        return self._finish(url, hostname, score, evidence,
                            registry={"verified": True, "domain": registry.domain,
                                      "institution": registry.institution, "category": registry.category},
                            ml=None, features=None, rules=[], verdict=verdict)

    # -------------------------------------------------------------- unverified
    def _unverified_payload(self, url: str, hostname: str, dom: dict[str, Any],
                            is_file: bool) -> dict[str, Any]:
        fs = extract_features(url, dom)
        decomposition = self.model.decompose(fs.vector)
        p = decomposition.probability

        base = ZERO_TRUST_FLOOR + SCALE * p
        rules = self._policy_rules(fs)
        applied_floor = max([r["floor"] for r in rules], default=0)
        final = int(round(min(100.0, max(base, applied_floor))))
        level = level_from_score(final)

        model_items = attribute(fs, decomposition, SCALE)
        covered = {item["feature"] for item in model_items if item["severity"] == "threat"}

        evidence: list[dict[str, Any]] = [{
            "text": ("ZERO TRUST ALERT: Domain NOT in trusted registry" if final >= 60
                     else "Domain NOT found in ProxyShield Trusted Registry"),
            "severity": "threat" if final >= 60 else "warn",
            "impact": float(ZERO_TRUST_FLOOR), "feature": "registry", "source": "registry"}]

        if is_file:
            evidence.append({"text": "Local file (file://) cannot be verified against the registry",
                             "severity": "warn", "impact": 0.0, "feature": "scheme", "source": "registry"})
        if fs.context["is_private_ip"]:
            evidence.append({"text": "Private network address cannot be verified against the registry",
                             "severity": "warn", "impact": 0.0, "feature": "is_ip_host", "source": "registry"})

        # Policy rules: annotate a matching model item, or add their own evidence.
        for rule in sorted(rules, key=lambda r: r["floor"], reverse=True):
            matched = next((i for i in model_items if i["feature"] == rule["feature"]
                            and i["severity"] == "threat"), None)
            if matched:
                matched["policy_floor"] = rule["floor"]
                matched["text"] = f"{matched['text']} (policy floor {rule['floor']})"
            else:
                evidence.append({"text": rule["text"], "severity": "threat", "impact": 0.0,
                                 "feature": rule["feature"], "source": "policy",
                                 "policy_floor": rule["floor"]})
            covered.add(rule["feature"])

        evidence.extend(model_items)

        if not any(e["severity"] == "threat" for e in evidence):
            evidence.append({"text": "No known phishing patterns detected in the URL structure",
                             "severity": "safe", "impact": 0.0, "feature": "summary", "source": "model"})
        evidence.append({"text": "Proceed with caution: Unverified entity" if level in ("LOW", "MEDIUM")
                         else "Treat this site as hostile until verified through an official channel",
                         "severity": "warn" if level in ("LOW", "MEDIUM") else "threat",
                         "impact": 0.0, "feature": "summary", "source": "registry"})

        top = sorted(
            ({"feature": name, "log_odds": round(c, 4), "value": fs.raw[name]}
             for name, c in zip(FEATURE_NAMES, decomposition.contributions)),
            key=lambda item: abs(item["log_odds"]), reverse=True)[:8]

        ml = {
            "phishing_probability": round(p, 4),
            "baseline_probability": round(decomposition.baseline_probability, 4),
            "zero_trust_floor": ZERO_TRUST_FLOOR,
            "model_score": int(round(min(100.0, base))),
            "policy_floor_applied": applied_floor if applied_floor > base else None,
            "top_log_odds_contributions": top,
        }
        return self._finish(url, hostname, final, evidence,
                            registry={"verified": False, "domain": None, "institution": None, "category": None},
                            ml=ml, features={k: round(v, 4) for k, v in fs.raw.items()}, rules=rules)

    # ------------------------------------------------------------------ output
    @staticmethod
    def _finish(url: str, hostname: str, score: int, evidence: list[dict[str, Any]],
                registry: dict[str, Any], ml: Optional[dict[str, Any]],
                features: Optional[dict[str, float]], rules: list[dict[str, Any]],
                verdict: Optional[str] = None) -> dict[str, Any]:
        score = max(0, min(100, int(score)))
        level = level_from_score(score)
        return {
            "url": url,
            "hostname": hostname,
            "score": score,
            "level": level,
            "risk_level": level,
            "verdict": verdict or VERDICTS[level],
            "signals": [e["text"] for e in evidence],
            "evidence": evidence,
            "registry": registry,
            "ml": ml,
            "features": features,
            "policy_rules_triggered": [{"feature": r["feature"], "floor": r["floor"]} for r in rules],
        }


def registry_size() -> int:
    return len(TRUSTED_REGISTRY)
