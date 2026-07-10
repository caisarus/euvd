"""Configuration loading: defaults -> YAML file -> EUVD_WATCH_* environment variables.

One validated Settings object is used everywhere instead of scattered constants (see
plans/implementation_plan.md Step 0.3). Unknown keys are rejected (extra="forbid"): this
config gates a legal reporting trigger, so a typo silently falling back to a default is the
exact "dangerous silence" the test plan warns about.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

ENV_PREFIX = "EUVD_WATCH_"
DEFAULT_CONFIG_PATH = Path("euvd-watch.yaml")


class OrganizationConfig(BaseModel):
    """Identity used later to prefill CRA Article 14 notification drafts (M4)."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    contact_email: str | None = None
    product_name: str | None = None


class CraTriggerConfig(BaseModel):
    """Which signals fire the CRA reporting trigger, and how they combine (Step 4.1)."""

    model_config = ConfigDict(extra="forbid")

    euvd_exploited: bool = True
    cisa_kev: bool = True
    epss_over_threshold: bool = True
    # Below this confidence, a Finding never fires the trigger even if a signal matches -
    # low-confidence matches exist for human review, not automated legal-clock starts.
    min_confidence: Literal["low", "medium", "high"] = "medium"
    # False (default): any one enabled signal firing is enough (disjunction). True: every
    # enabled signal must fire (conjunction).
    require_all: bool = False


class CraStageConfig(BaseModel):
    """One CRA notification deadline stage. The stage list is config, not code, because a
    legal-text change (durations, anchors, or an added/removed stage) must never require a
    code change (plans/implementation_plan.md Step 4.2)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    hours: float = Field(gt=0)
    # What timestamp the deadline counts from. "first_seen" exists the moment the trigger
    # fires; "remediation_available" only exists once a human marks it (docs/cra.md) - a
    # stage anchored on it has no deadline at all until then.
    anchor: Literal["first_seen", "remediation_available"]


# Defaults verified against the real Article 14 text (Regulation (EU) 2024/2847),
# 2026-07-10 - see docs/cra.md for the verbatim source. Overridable in config so a future
# legal amendment never requires a code change.
DEFAULT_CRA_STAGES = [
    CraStageConfig(name="early_warning", hours=24, anchor="first_seen"),
    CraStageConfig(name="vulnerability_notification", hours=72, anchor="first_seen"),
    CraStageConfig(name="final_report", hours=14 * 24, anchor="remediation_available"),
]


class Settings(BaseModel):
    """The single validated configuration object shared across all commands."""

    model_config = ConfigDict(extra="forbid")

    # Verified live 2026-07-10; endpoints documented in docs/euvd-api.md.
    euvd_api_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    epss_api_base_url: str = "https://api.first.org/data/v1/epss"
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    # validate_default so the ~ in the default expands through the same validator user
    # values go through (pydantic skips validators on defaults otherwise).
    cache_dir: Path = Field(default=Path("~/.cache/euvd-watch"), validate_default=True)
    cache_ttl_hours: int = Field(default=24, ge=0)
    # EPSS is a probability on FIRST.org's 0-1 scale (EUVD's 0-100 wire scale is
    # normalized on ingest). Bounded here because this value gates the CRA reporting
    # trigger: a user typing 50 (the 0-100 confusion) would otherwise silently make the
    # EPSS signal unable to ever fire (audit 2026-07-10, finding SEC-002).
    epss_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    min_confidence: Literal["low", "medium", "high"] = "medium"
    organization: OrganizationConfig = OrganizationConfig()
    cra_trigger: CraTriggerConfig = CraTriggerConfig()
    cra_stages: list[CraStageConfig] = Field(default_factory=lambda: list(DEFAULT_CRA_STAGES))

    @field_validator("cache_dir", mode="after")
    @classmethod
    def _expand_user(cls, value: Path) -> Path:
        # A user-supplied "~/..." from YAML or env must expand exactly like the default does;
        # otherwise a literal "./~/" directory gets created the first time the cache writes.
        return value.expanduser()

    @field_validator("cra_stages", mode="after")
    @classmethod
    def _stages_are_usable(cls, value: list[CraStageConfig]) -> list[CraStageConfig]:
        # Duplicate names would collide in Event.stage_completions (one dict key), and an
        # empty stage list would make every event trivially "closed" - both silently
        # neuter the CRA workflow (audit finding SEC-002).
        if not value:
            raise ValueError("cra_stages must contain at least one stage.")
        names = [stage.name for stage in value]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"cra_stages names must be unique; duplicated: {duplicates}")
        return value


class ConfigError(Exception):
    """Raised when configuration fails to load or validate; names the offending field(s)."""


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Config file {path} is not valid UTF-8: {exc}") from exc
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} must contain a YAML mapping at the top level.")
    return data


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _env_overrides() -> dict[str, Any]:
    """Collect EUVD_WATCH_* env vars, mapping `EUVD_WATCH_ORGANIZATION__NAME` to a nested key."""
    overrides: dict[str, Any] = {}
    for env_key, value in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue
        path = env_key[len(ENV_PREFIX) :].lower().split("__")
        cursor = overrides
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path[-1]] = value
    return overrides


def load_settings(config_path: Path | None) -> Settings:
    """Load settings with precedence: defaults -> YAML file -> EUVD_WATCH_* env vars.

    An explicit `config_path` that doesn't exist is an error. The implicit default
    (`./euvd-watch.yaml`) is optional and silently skipped when absent.
    """
    merged: dict[str, Any] = {}

    if config_path is not None:
        merged = _deep_merge(merged, _read_yaml(config_path))
    elif DEFAULT_CONFIG_PATH.exists():
        merged = _deep_merge(merged, _read_yaml(DEFAULT_CONFIG_PATH))

    merged = _deep_merge(merged, _env_overrides())

    try:
        return Settings.model_validate(merged)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in err["loc"]) for err in exc.errors())
        raise ConfigError(f"Invalid configuration for field(s): {fields}\n{exc}") from exc
