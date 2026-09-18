"""Security module for secret detection and protection.

CRITICAL: This module detects secrets but NEVER reads or logs their contents.
Only existence, path, size, and kind are recorded.

`scanner.py` owns the secret path patterns (single source of truth);
`layers.py` reuses them to scan every layer of a `docker save` archive;
`image_config.py` scans the image *config metadata* and build history, where a
credential can travel without any file existing in any layer.
"""

from docker_migration_tool.security.scanner import (
    SCANNER_VERSION,
    SECRET_PATHS,
    SecretScanner,
    scan_image_for_secrets,
    scan_container_for_secrets,
    scan_path_for_secrets,
    is_secret_path,
    is_layer_secret_path,
    matches_secret_path_pattern,
    is_generated_config,
    is_nvidia_runtime_file,
)
from docker_migration_tool.security.image_config import (
    CONFIG_SCANNER_VERSION,
    ENV_KEY_ALLOWLIST,
    SECRET_ENV_KEY_PREFIXES,
    SECRET_ENV_KEY_WORDS,
    is_allowlisted_secret_like_key,
    key_name_pattern,
    matched_secret_env_key,
    scan_image_config,
    scan_image_config_data,
    value_looks_like_credential,
)
from docker_migration_tool.security.layers import (
    SUPPORTED_ARCHIVE_FORMATS,
    ImageArchiveError,
    UnsupportedImageArchiveError,
    detect_archive_format,
    normalize_layer_member_path,
    scan_image_archive,
)

__all__ = [
    "SCANNER_VERSION",
    "CONFIG_SCANNER_VERSION",
    "ENV_KEY_ALLOWLIST",
    "SECRET_ENV_KEY_PREFIXES",
    "SECRET_ENV_KEY_WORDS",
    "is_allowlisted_secret_like_key",
    "key_name_pattern",
    "matched_secret_env_key",
    "scan_image_config",
    "scan_image_config_data",
    "value_looks_like_credential",
    "SECRET_PATHS",
    "SecretScanner",
    "scan_image_for_secrets",
    "scan_container_for_secrets",
    "scan_path_for_secrets",
    "is_secret_path",
    "is_layer_secret_path",
    "matches_secret_path_pattern",
    "is_generated_config",
    "is_nvidia_runtime_file",
    "SUPPORTED_ARCHIVE_FORMATS",
    "ImageArchiveError",
    "UnsupportedImageArchiveError",
    "detect_archive_format",
    "normalize_layer_member_path",
    "scan_image_archive",
]
