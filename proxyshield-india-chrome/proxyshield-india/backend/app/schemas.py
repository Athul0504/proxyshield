"""Pydantic v2 request / response models for the ProxyShield API."""
from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["safe", "warn", "threat"]
Level = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

_ALLOWED_URL = re.compile(r"^(https?|file)://", re.IGNORECASE)


class DomSignals(BaseModel):
    """DOM telemetry sent by the extension's content script (camelCase on the wire)."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    protocol: Optional[str] = Field(None, max_length=16)
    form_count: int = Field(0, alias="formCount", ge=0, le=100_000)
    insecure_form_count: int = Field(0, alias="insecureFormCount", ge=0, le=100_000)
    sensitive_fields: list[str] = Field(default_factory=list, alias="sensitiveFields", max_length=20)
    sensitive_field_count: int = Field(0, alias="sensitiveFieldCount", ge=0, le=100_000)
    has_password_field: bool = Field(False, alias="hasPasswordField")
    urgency_triggers: list[str] = Field(default_factory=list, alias="urgencyTriggers", max_length=20)
    urgency_trigger_count: int = Field(0, alias="urgencyTriggerCount", ge=0, le=100_000)
    collected_at: Optional[float] = Field(None, alias="collectedAt")

    @field_validator("sensitive_fields", "urgency_triggers")
    @classmethod
    def _trim_strings(cls, values: list[str]) -> list[str]:
        return [str(v)[:64] for v in values]


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str = Field(..., min_length=1, max_length=4096)
    dom_signals: Optional[DomSignals] = None
    client: Optional[str] = Field(None, max_length=64)
    version: Optional[str] = Field(None, max_length=32)

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str:
        value = value.strip()
        if not _ALLOWED_URL.match(value):
            raise ValueError("url must start with http://, https:// or file://")
        return value


class Evidence(BaseModel):
    text: str
    severity: Severity
    impact: float = 0.0
    feature: str = ""
    source: str = ""
    policy_floor: Optional[int] = None


class RegistryInfo(BaseModel):
    verified: bool
    domain: Optional[str] = None
    institution: Optional[str] = None
    category: Optional[str] = None


class AnalyzeResponse(BaseModel):
    url: str
    hostname: str
    score: int = Field(..., ge=0, le=100)
    level: Level
    risk_level: Level
    verdict: str
    signals: list[str]
    evidence: list[Evidence]
    registry: RegistryInfo
    ml: Optional[dict[str, Any]] = None
    features: Optional[dict[str, float]] = None
    policy_rules_triggered: list[dict[str, Any]] = Field(default_factory=list)
    dom_signals_used: bool = False
    analysis_ms: float = 0.0
    engine: dict[str, Any] = Field(default_factory=dict)
