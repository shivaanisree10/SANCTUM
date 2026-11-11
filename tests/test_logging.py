import logging
from sanctum.logging import setup_logging

def test_setup_logging() -> None:
    # Reset handlers if any
    logger = logging.getLogger("sanctum")
    logger.handlers.clear()
    
    setup_logging("DEBUG")
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) == 1
    
    # Second call should not add another handler
    setup_logging("INFO")
    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
