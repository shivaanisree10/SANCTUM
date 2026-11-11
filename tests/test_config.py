import pytest
import yaml
from pathlib import Path
from sanctum.config import load_config, AppConfig
from sanctum.exceptions import ConfigurationError

def test_load_valid_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_data = {"environment": "production", "test_media_path": "/tmp/media.img", "simulation_mode": False}
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
    
    config = load_config(config_file)
    assert config.environment == "production"
    assert config.test_media_path == "/tmp/media.img"
    assert config.simulation_mode is False

def test_load_missing_file() -> None:
    with pytest.raises(ConfigurationError):
        load_config("does_not_exist.yaml")

def test_load_invalid_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    with open(config_file, "w") as f:
        f.write("environment: production\n  invalid: yaml")
    
    with pytest.raises(ConfigurationError):
        load_config(config_file)

def test_load_invalid_schema(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    # test_media_path should be string, let's break it if we can. Actually pydantic converts int to str. 
    # Let's provide a dict where a string is expected.
    config_data = {"environment": {"not": "a string"}}
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
    
    with pytest.raises(ConfigurationError):
        load_config(config_file)
