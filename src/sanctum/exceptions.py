import sys
import logging

logger = logging.getLogger("sanctum")

class SanctumError(Exception):
    """Base exception for all SANCTUM errors."""
    pass

class ConfigurationError(SanctumError):
    """Raised when configuration is invalid or cannot be loaded."""
    pass

def global_exception_handler(exc_type, exc_value, exc_traceback): # type: ignore
    """Global exception handler that logs the error and exits safely (fails closed)."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.critical("Unhandled exception: fails closed.", exc_info=(exc_type, exc_value, exc_traceback))
    sys.exit(1)

# Set the global exception handler
sys.excepthook = global_exception_handler
