"""Covers implementation_plan.md Step 0.3: config precedence and failure clarity."""

from pathlib import Path

import pytest

from euvd_watch.config import ConfigError, Settings, load_settings

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "config"
EXAMPLE_CONFIG = Path(__file__).resolve().parents[2] / "examples" / "config" / "euvd-watch.yaml"


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


def test_typoed_yaml_key_produces_config_error_naming_the_key(tmp_path: Path) -> None:
    # A typo'd key silently reverting to a default would be "dangerous silence": this
    # config gates the CRA reporting trigger.
    config = tmp_path / "typo.yaml"
    config.write_text("epss_treshold: 0.9\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="epss_treshold"):
        load_settings(config)


def test_tilde_in_user_supplied_cache_dir_is_expanded(tmp_path: Path) -> None:
    config = tmp_path / "tilde.yaml"
    config.write_text("cache_dir: ~/.cache/euvd-watch-test\n", encoding="utf-8")
    settings = load_settings(config)
    assert "~" not in str(settings.cache_dir)
    assert settings.cache_dir.is_absolute()


def test_default_cache_dir_is_expanded() -> None:
    assert "~" not in str(Settings().cache_dir)


def test_api_base_urls_have_verified_defaults() -> None:
    # euvd_api_base_url must point at the verified API host (docs/euvd-api.md), not the
    # website; epss/kev URLs exist so deployments can pin or proxy them.
    s = Settings()
    assert s.euvd_api_base_url == "https://euvdservices.enisa.europa.eu/api"
    assert s.epss_api_base_url.startswith("https://api.first.org/")
    assert s.kev_feed_url.endswith(".json")


def test_documented_example_config_loads() -> None:
    # The README/example config is a public promise; extra="forbid" must not break it.
    settings = load_settings(EXAMPLE_CONFIG)
    assert settings.organization.name == "Example S.R.L."
    assert settings.cra_trigger.euvd_exploited is True


# --- bounds on trigger-gating values (audit 2026-07-10, finding SEC-002) ---
# These values gate a legal reporting trigger; semantically impossible values must fail
# loudly naming the field, never be accepted and silently deaden a signal.


def _expect_config_error(yaml_text: str, tmp_path: Path, field_fragment: str) -> None:
    config = tmp_path / "bad.yaml"
    config.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(ConfigError, match=field_fragment):
        load_settings(config)


def test_epss_threshold_above_one_is_rejected(tmp_path: Path) -> None:
    # The classic 0-100-scale confusion (EUVD's wire scale) would make the EPSS signal
    # unable to ever fire; it must error, not load.
    _expect_config_error("epss_threshold: 50\n", tmp_path, "epss_threshold")


def test_epss_threshold_negative_is_rejected(tmp_path: Path) -> None:
    _expect_config_error("epss_threshold: -0.1\n", tmp_path, "epss_threshold")


def test_negative_cache_ttl_is_rejected(tmp_path: Path) -> None:
    _expect_config_error("cache_ttl_hours: -5\n", tmp_path, "cache_ttl_hours")


def test_cra_stage_with_nonpositive_hours_is_rejected(tmp_path: Path) -> None:
    _expect_config_error(
        "cra_stages:\n  - {name: x, hours: -4, anchor: first_seen}\n", tmp_path, "hours"
    )


def test_duplicate_cra_stage_names_are_rejected(tmp_path: Path) -> None:
    _expect_config_error(
        "cra_stages:\n"
        "  - {name: x, hours: 24, anchor: first_seen}\n"
        "  - {name: x, hours: 72, anchor: first_seen}\n",
        tmp_path,
        "cra_stages",
    )


def test_empty_cra_stage_list_is_rejected(tmp_path: Path) -> None:
    _expect_config_error("cra_stages: []\n", tmp_path, "cra_stages")
