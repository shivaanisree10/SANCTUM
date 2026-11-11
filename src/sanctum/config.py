import yaml
from pathlib import Path
from pydantic import BaseModel, ValidationError
from sanctum.exceptions import ConfigurationError

class AppConfig(BaseModel):
    """Application configuration schema."""
    environment: str = "development"
    test_media_path: str = "./test_lab/media.img"
    simulation_mode: bool = True

    
def load_config(path: Path | str) -> AppConfig:
    """Load and validate configuration from a YAML file."""
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        if data is None:
            data = {}
        return AppConfig(**data)
    except FileNotFoundError as e:
        raise ConfigurationError(f"Configuration file not found: {path}") from e
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML syntax in {path}") from e
    except ValidationError as e:
        raise ConfigurationError(f"Configuration validation failed: {e}") from e
