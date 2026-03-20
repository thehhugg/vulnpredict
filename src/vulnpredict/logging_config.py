"""Structured logging configuration for VulnPredict.

Provides a centralized logging setup with configurable verbosity levels.
All modules should use ``get_logger(__name__)`` to obtain their logger.
"""

import logging
import sys
from typing import Optional

# Custom log format
_LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
_LOG_FORMAT_DEBUG = (
    "%(asctime)s [%(levelname)-8s] %(name)s (%(filename)s:%(lineno)d): %(message)s"
)
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Package-level logger
_ROOT_LOGGER_NAME = "vulnpredict"

_configured = False


def configure_logging(
    verbosity: int = 0,
    log_file: Optional[str] = None,
) -> None:
    """Configure the VulnPredict logging subsystem.

    Parameters
    ----------
    verbosity:
        0 = WARNING (default), 1 = INFO (--verbose), 2+ = DEBUG (--debug)
    log_file:
        Optional path to a log file. If provided, logs are written to both
        stderr and the file.
    """
    global _configured

    if verbosity >= 2:
        level = logging.DEBUG
        fmt = _LOG_FORMAT_DEBUG
    elif verbosity == 1:
        level = logging.INFO
        fmt = _LOG_FORMAT
    else:
        level = logging.WARNING
        fmt = _LOG_FORMAT

    root_logger = logging.getLogger(_ROOT_LOGGER_NAME)
    root_logger.setLevel(level)

    # Clear existing handlers to avoid duplicates on reconfiguration
    root_logger.handlers.clear()

    # Console handler (stderr)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(fmt, datefmt=_DATE_FORMAT))
    root_logger.addHandler(console)

    # Optional file handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(level)
            file_handler.setFormatter(logging.Formatter(fmt, datefmt=_DATE_FORMAT))
            root_logger.addHandler(file_handler)
        except OSError as exc:
            root_logger.warning("Could not open log file %s: %s", log_file, exc)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the ``vulnpredict`` namespace.

    If ``configure_logging`` has not been called yet, a default WARNING-level
    configuration is applied automatically so that log messages are never lost.
    """
    global _configured
    if not _configured:
        configure_logging(verbosity=0)

    # Ensure the logger is under the vulnpredict namespace
    if not name.startswith(_ROOT_LOGGER_NAME):
        name = f"{_ROOT_LOGGER_NAME}.{name}"
    return logging.getLogger(name)
