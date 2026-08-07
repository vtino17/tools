import os
from pathlib import Path
import subprocess
import sys

import pytest

from hackerai.config import env_info, get_default_wordlist, load_json_config


def _import_with(**overrides):
    environment = os.environ.copy()
    environment.update(overrides)
    return subprocess.run(
        [sys.executable, "-c", "import hackerai.config"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_environment_summary_is_a_string():
    assert isinstance(env_info(), str)


def test_missing_wordlist_returns_expected_candidate_path():
    assert "nonexistent.txt" in get_default_wordlist("nonexistent.txt")


def test_logger_import_and_name():
    from hackerai.logger import get_logger

    assert get_logger("test").name == "test"


def test_logger_setup_does_not_duplicate_handlers():
    from hackerai.logger import setup_logger

    first = setup_logger("test_dedup")
    before = len(first.handlers)
    second = setup_logger("test_dedup")
    assert len(second.handlers) == before


@pytest.mark.parametrize(
    ("name", "value"),
    [("HAI_THREADS", "0"), ("HAI_THREADS", "1000000"), ("HAI_TIMEOUT", "nope")],
)
def test_invalid_numeric_environment_is_rejected(name, value):
    result = _import_with(**{name: value})
    assert result.returncode != 0
    assert name in result.stderr


def test_invalid_log_level_is_rejected():
    result = _import_with(HAI_LOG_LEVEL="VERBOSE")
    assert result.returncode != 0
    assert "HAI_LOG_LEVEL" in result.stderr


def test_json_config_requires_an_object(tmp_path: Path):
    config = tmp_path / "config.json"
    config.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_json_config(str(config))


def test_json_config_is_size_bounded(tmp_path: Path):
    config = tmp_path / "large.json"
    config.write_text('{"value":"' + ("x" * 1_048_576) + '"}', encoding="utf-8")
    with pytest.raises(ValueError, match="1 MiB"):
        load_json_config(str(config))
