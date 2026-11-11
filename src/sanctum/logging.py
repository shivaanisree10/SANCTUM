import logging
import sys

def setup_logging(level: str = "INFO") -> None:
    """Configure structured application logging."""
    logger = logging.getLogger("sanctum")
    
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    logger.setLevel(numeric_level)
    
    # Prevent adding multiple handlers if setup_logging is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '{"time": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
