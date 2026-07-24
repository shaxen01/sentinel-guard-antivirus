"""
Sentinel Guard — Colored Logger
"""
import logging
import sys
from pathlib import Path

# ANSI color codes
COLORS = {
    'DEBUG': '\033[36m',     # Cyan
    'INFO': '\033[32m',      # Green
    'WARNING': '\033[33m',   # Yellow
    'ERROR': '\033[31m',     # Red
    'CRITICAL': '\033[35m',  # Magenta
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
}

_loggers = {}
_log_level = logging.INFO


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output."""

    def format(self, record):
        color = COLORS.get(record.levelname, '')
        reset = COLORS['RESET']
        bold = COLORS['BOLD']

        # Add color to level name
        record.levelname = f"{color}{bold}{record.levelname:<8}{reset}"
        record.name = f"{color}{record.name}{reset}"

        return super().format(record)


def get_logger(name: str = "sentinel") -> logging.Logger:
    """Get or create a colored logger."""
    global _loggers

    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(_log_level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = ColoredFormatter(
            '%(levelname)s │ %(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.propagate = False
    _loggers[name] = logger
    return logger


def set_log_level(level: str):
    """Set the global log level."""
    global _log_level
    levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL,
    }
    _log_level = levels.get(level.upper(), logging.INFO)
    for logger in _loggers.values():
        logger.setLevel(_log_level)
