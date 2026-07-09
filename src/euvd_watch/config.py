"""Configuration loading: defaults -> YAML file -> EUVD_WATCH_* environment variables.

One validated Settings object is used everywhere instead of scattered constants (see
plans/implementation_plan.md Step 0.3).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ValidationError

ENV_PREFIX = "EUVD_WATCH_"
DEFAULT_CONFIG_PATH = Path("euvd-watch.yaml")


class OrganizationConfig(BaseModel):
    """Identity used later to prefill CRA Article 14 notification drafts (M4)."""

    name: str | None = None
    contact_email: str | None = None
    product_name: str | None = None


class Settings(BaseModel):
    """The single validated configuration object shared across all commands."""

    # Unverified placeholder; the real EUVD API surface is confirmed during M2
    # (plans/implementation_plan.md Step 2.2) and documented in docs/euvd-api.md.
    euvd_api_base_url: str = "https://euvd.enisa.europa.eu"
    cache_dir: Path = Path("~/.cache/euvd-watch").expanduser()
    cache_ttl_hours: int = 24
    epss_threshold: float = 0.5
    min_confidence: Literal["low", "medium", "high"] = "medium"
    organization: OrganizationConfig = OrganizationConfig()


class ConfigError(Exception):
    """Raised when configuration fails to load or validate; names the offending field(s)."""


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text()
    except OSError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
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
