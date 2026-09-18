"""Logging utilities for the migration tool.

Provides consistent CLI output formatting.
IMPORTANT: Never log secrets, tokens, API keys, or passwords.
"""

import logging
import sys
from typing import TextIO


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


# Check if output supports colors
def _supports_color(stream: TextIO) -> bool:
    """Check if stream supports ANSI colors."""
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    return True


_use_color = _supports_color(sys.stdout)


def set_color_output(enabled: bool) -> None:
    """Enable or disable color output."""
    global _use_color
    _use_color = enabled


def _colorize(text: str, color: str) -> str:
    """Apply color to text if supported."""
    if _use_color:
        return f"{color}{text}{Colors.RESET}"
    return text


def log_ok(message: str, detail: str | None = None) -> None:
    """Log success message."""
    prefix = _colorize("[OK]", Colors.GREEN)
    print(f"{prefix} {message}")
    if detail:
        print(f"     {_colorize(detail, Colors.GRAY)}")


def log_warn(message: str, detail: str | None = None) -> None:
    """Log warning message."""
    prefix = _colorize("[WARN]", Colors.YELLOW)
    print(f"{prefix} {message}")
    if detail:
        print(f"      {_colorize(detail, Colors.GRAY)}")


def log_error(message: str, detail: str | None = None) -> None:
    """Log error message."""
    prefix = _colorize("[ERROR]", Colors.RED)
    print(f"{prefix} {message}", file=sys.stderr)
    if detail:
        print(f"       {_colorize(detail, Colors.GRAY)}", file=sys.stderr)


def log_skip(message: str, reason: str | None = None) -> None:
    """Log skipped item."""
    prefix = _colorize("[SKIP]", Colors.GRAY)
    print(f"{prefix} {message}")
    if reason:
        print(f"      {_colorize(reason, Colors.GRAY)}")


def log_info(message: str) -> None:
    """Log informational message."""
    prefix = _colorize("[INFO]", Colors.BLUE)
    print(f"{prefix} {message}")


def log_step(message: str) -> None:
    """Log a step in a process."""
    arrow = _colorize("→", Colors.CYAN)
    print(f"{arrow} {message}")


def log_header(message: str) -> None:
    """Log a section header."""
    print()
    print(_colorize(f"=== {message} ===", Colors.BOLD))
    print()


def log_subheader(message: str) -> None:
    """Log a subsection header."""
    print()
    print(_colorize(f"--- {message} ---", Colors.CYAN))


def log_detail(key: str, value: str) -> None:
    """Log a key-value detail."""
    key_str = _colorize(f"  {key}:", Colors.GRAY)
    print(f"{key_str} {value}")


def log_list_item(item: str, indent: int = 2) -> None:
    """Log a list item."""
    prefix = " " * indent + _colorize("•", Colors.GRAY)
    print(f"{prefix} {item}")


def log_table_row(columns: list[str], widths: list[int] | None = None) -> None:
    """Log a table row."""
    if widths:
        formatted = []
        for col, width in zip(columns, widths):
            formatted.append(col.ljust(width))
        print("  " + "  ".join(formatted))
    else:
        print("  " + "  ".join(columns))


class MigrationLogger(logging.Handler):
    """Custom logging handler for migration tool."""

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record."""
        msg = self.format(record)

        if record.levelno >= logging.ERROR:
            log_error(msg)
        elif record.levelno >= logging.WARNING:
            log_warn(msg)
        elif record.levelno >= logging.INFO:
            log_info(msg)
        else:
            print(f"      {_colorize(msg, Colors.GRAY)}")


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging for the migration tool.

    Args:
        verbose: Enable verbose/debug output

    Returns:
        Configured logger
    """
    logger = logging.getLogger("docker_migration_tool")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Remove existing handlers
    logger.handlers = []

    # Add our custom handler
    handler = MigrationLogger()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    return logger


# Redaction patterns for secrets
SECRET_PATTERNS = [
    "KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL",
    "AUTH", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE",
]

SECRET_PREFIXES = [
    "AWS_", "OPENAI_", "ANTHROPIC_", "GITHUB_", "AZURE_",
    "DOCKER_", "NPM_", "PYPI_",
]


def redact_value(key: str, value: str) -> str:
    """Redact a value if the key looks like a secret.

    Args:
        key: Environment variable or config key
        value: The value

    Returns:
        Redacted value if key matches secret patterns, original otherwise
    """
    key_upper = key.upper()

    # Check prefixes
    for prefix in SECRET_PREFIXES:
        if key_upper.startswith(prefix):
            return "[REDACTED]"

    # Check patterns
    for pattern in SECRET_PATTERNS:
        if pattern in key_upper:
            return "[REDACTED]"

    return value


def safe_env_dict(env_vars: dict[str, str]) -> dict[str, str]:
    """Create a safe copy of environment variables with secrets redacted.

    Args:
        env_vars: Original environment variables

    Returns:
        Copy with secret values redacted
    """
    return {k: redact_value(k, v) for k, v in env_vars.items()}
