"""Covers implementation_plan.md Step 0.3: config precedence and failure clarity."""

from pathlib import Path

import pytest

from euvd_watch.config import ConfigError, Settings, load_settings

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "config"


def test_defaults_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)  # no ./euvd-watch.yaml here
    settings = load_settings(None)
    assert settings == Settings()


def test_yaml_overrides_defaults() -> None:
    settings = load_settings(FIXTURES / "valid.yaml")
    assert settings.epss_threshold == 0.7
    assert settings.min_confidence == "high"
    assert settings.organization.name == "Example S.R.L."


def test_partial_yaml_falls_back_to_defaults_for_missing_fields() -> None:
    settings = load_settings(FIXTURES / "partial.yaml")
    assert settings.organization.name == "Partial Org"
    assert settings.epss_threshold == Settings().epss_threshold  # untouched default


def test_env_overrides_yaml(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EUVD_WATCH_EPSS_THRESHOLD", "0.9")
    monkeypatch.setenv("EUVD_WATCH_ORGANIZATION__NAME", "Env Org")
    settings = load_settings(FIXTURES / "valid.yaml")
    assert settings.epss_threshold == 0.9
    assert settings.organization.name == "Env Org"
    # untouched by env, still comes from the YAML file
    assert settings.min_confidence == "high"


def test_invalid_config_names_the_bad_fields() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings(FIXTURES / "invalid_type.yaml")
    message = str(excinfo.value)
    assert "epss_threshold" in message
    assert "min_confidence" in message


def test_missing_explicit_config_file_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "does-not-exist.yaml")


def test_implicit_default_config_missing_is_fine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    settings = load_settings(None)
    assert settings == Settings()
