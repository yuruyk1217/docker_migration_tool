"""Credential scanner for Docker image config metadata and build history.

Why this exists
---------------
A credential does not have to be a *file* to travel with an image. `docker save`
ships the image config and the build history alongside the layer blobs, so a
token baked in by

    ENV OPENAI_API_KEY=sk-...
    ARG GITHUB_TOKEN=ghp_...
    RUN curl -H "Authorization: Bearer <token>" ...

is handed to the other person even when no credential *file* exists in any
layer. The final-filesystem scan and the all-layer scan both match on *paths*,
so neither of them can see this. This module closes that gap.

Scope
-----
* ``Config.Env``                       (primary target)
* ``ContainerConfig.Env``              (older daemons only; absent on docker 29)
* ``Config.Cmd`` / ``Config.Entrypoint``
* ``Config.Labels``
* ``docker image history --no-trunc`` -> ``CreatedBy``

Safety properties
-----------------
* An environment variable VALUE is never returned, logged, written to the bundle
  or stored in a finding. A value-side detection records only ``matched=True``
  and the kind ``possible_credential_value``.
* Key names ARE recorded: the operator needs them to fix the image, and a key
  name is not the secret. Values are always dropped on the floor.
* Value detection uses format-limited regexes (``sk-`` + >=20 chars, ``AKIA`` +
  16 uppercase, ``ghp_`` + >=36, ...). A bare substring test such as "sk" is
  deliberately NOT used: it would match half of every image.
* Nothing runs inside the image: `docker image inspect` and `docker history`
  are read-only metadata calls. No `docker run`, no shell, no `shell=True`.
* An unreadable config or history is reported as ``error`` - never as a pass.
  An unscanned image config is never treated as safe.

Key-name matching
-----------------
The key vocabulary is shared with value redaction (`utils.logging`) so the two
cannot drift. The *matching* differs on purpose:

* redaction (`redact_value`) uses a greedy substring test - over-redacting a
  report is harmless;
* this scanner requires the secret word to be a NAME COMPONENT of the key
  (``OPENAI_API_KEY`` -> ``[OPENAI, API, KEY]``), because a greedy substring
  test also matches ``--keyring=``, ``KEYSTORE`` and ``XAUTHORITY`` and would
  block exports of perfectly clean images.

This is the same component-scoped idea the workspace exclusion policy uses, so
that ``**/build`` drops ``build/`` without dropping ``rebuild_tool.py``.
"""

import json
import re
from typing import Any

from docker_migration_tool.model import (
    Classification,
    ImageConfigScanResult,
    ImageConfigSecretFinding,
)
from docker_migration_tool.utils.docker import (
    DockerError,
    get_image_history,
    inspect_image_json,
)
from docker_migration_tool.utils.logging import SECRET_PATTERNS, SECRET_PREFIXES


# Ruleset version for the config/history scan. Kept separate from
# SCANNER_VERSION (the secret *path* ruleset) so each can move on its own.
CONFIG_SCANNER_VERSION = "1.0.0"

# Finding sources (the metadata surface a finding was seen on)
SOURCE_CONFIG_ENV = "image_config_env"
SOURCE_CONTAINER_CONFIG_ENV = "image_container_config_env"
SOURCE_CONFIG_CMD = "image_config_cmd"
SOURCE_CONFIG_ENTRYPOINT = "image_config_entrypoint"
SOURCE_CONFIG_LABELS = "image_config_labels"
SOURCE_HISTORY_CREATED_BY = "image_history_created_by"

# Finding kinds
KIND_CREDENTIAL_ENVIRONMENT = "credential_environment"
KIND_CREDENTIAL_LABEL = "credential_label"
KIND_POSSIBLE_CREDENTIAL_VALUE = "possible_credential_value"

# Secret key vocabulary. SINGLE SOURCE OF TRUTH: utils.logging owns the words
# used for value redaction and this scanner reuses them, so a key that is
# redacted in a report is also a key this scanner knows about.
#
# Required by spec: *KEY*, *TOKEN*, *SECRET*, *PASSWORD*, *CREDENTIAL* and the
# AWS_ / OPENAI_ / ANTHROPIC_ / GITHUB_ / AZURE_ / DOCKER_ prefixes.
SECRET_ENV_KEY_WORDS: tuple[str, ...] = tuple(SECRET_PATTERNS)
SECRET_ENV_KEY_PREFIXES: tuple[str, ...] = tuple(SECRET_PREFIXES)

# Keys whose NAME matches the vocabulary but which are structurally not
# credentials (a path, a socket, a flag, a public fingerprint).
#
# An allowlisted key only escapes the NAME check - its value is still run
# through the credential-format detectors below, so allowlisting can never hide
# real credential material.
ENV_KEY_ALLOWLIST: frozenset[str] = frozenset({
    "GPG_KEY",                 # public signing key fingerprint (python images)
    "XAUTHORITY",              # path to the X11 cookie file (never migrated)
    "SSH_AUTH_SOCK",           # agent socket path
    "DOCKER_HOST",             # daemon socket / URL
    "DOCKER_CONFIG",           # config directory path
    "DOCKER_CONTEXT",          # context name
    "DOCKER_BUILDKIT",         # build flag
    "DOCKER_CERT_PATH",        # TLS material *directory* (never migrated)
    "DOCKER_TLS_VERIFY",       # flag
    "DOCKER_DEFAULT_PLATFORM",  # platform string
})

# Credential material detectors. Each is format-limited on purpose: a generic
# "long random string" rule would flag CUDA package versions, git hashes and
# base64 licence blobs in every robotics image.
_CREDENTIAL_VALUE_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # OpenAI / Codex
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    # Anthropic / Claude
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    # GitHub
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}")),
    # AWS access key id (AKIA/ASIA/ABIA/ACCA + 16 uppercase/digits)
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    # Google
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    # Slack
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    # PyPI upload token
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{32,}")),
    # JSON Web Token (header.payload.signature)
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )),
    # Authorization: Bearer <token>
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}")),
    # PEM private key block
    ("private_key_block", re.compile(
        r"-----BEGIN (?:[A-Z][A-Z ]*)?PRIVATE KEY-----"
    )),
    # scheme://user:password@host
    ("url_embedded_credentials", re.compile(
        r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/:@]+@"
    )),
    # A credential assignment nested inside another value or a build command,
    # e.g. MY_APP_CONFIG=OPENAI_API_KEY=... or --build-arg TOKEN=<something>
    # The lookbehind (rather than \b) is what lets OPENAI_API_KEY= match: an
    # underscore is a word character, so \bAPI_KEY would never fire there.
    ("nested_credential_assignment", re.compile(
        r"(?<![A-Za-z0-9])(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN|"
        r"REFRESH[_-]?TOKEN|AUTH[_-]?TOKEN|BEARER[_-]?TOKEN|CLIENT[_-]?SECRET|"
        r"PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|SECRET|TOKEN)"
        r"\s*=\s*[^\s\"'&]{8,}",
        re.IGNORECASE,
    )),
)

# Shell/Dockerfile style assignments inside a build command or a value:
#   ENV FOO=..., ARG FOO=..., export FOO=..., --build-arg FOO=...
_ASSIGNMENT_KEY_RE = re.compile(r"(?:^|[\s\"'=])([A-Za-z_][A-Za-z0-9_]{1,64})=")

# Placeholder-only values (nothing was actually baked in)
_PLACEHOLDER_VALUE_RE = re.compile(r"^\$[A-Za-z_{(][^\s]*$")

_KEY_COMPONENT_SPLIT_RE = re.compile(r"[^A-Z0-9]+")


def _key_components(key: str) -> list[str]:
    """Split an env/label key into upper-case name components."""
    return [part for part in _KEY_COMPONENT_SPLIT_RE.split(key.upper()) if part]


def _word_matches_component(word: str, component: str) -> bool:
    """Match a vocabulary word against one key name component.

    Exact match, or the simple plural (``TOKENS``, ``CREDENTIALS``). Substring
    matching is deliberately not used here - see the module docstring.
    """
    return component == word or component == word + "S"


def key_name_pattern(key: str) -> str | None:
    """Return the vocabulary pattern a key name matches, ignoring the allowlist.

    Args:
        key: Environment variable or label key

    Returns:
        A pattern label such as ``"*KEY*"`` / ``"AWS_*"``, or None
    """
    if not key:
        return None

    key_upper = key.upper()

    for prefix in SECRET_ENV_KEY_PREFIXES:
        if key_upper.startswith(prefix):
            return f"{prefix}*"

    components = _key_components(key)
    for word in SECRET_ENV_KEY_WORDS:
        word_upper = word.upper()
        # Multi-word vocabulary entries ("API_KEY", "ACCESS_KEY") are specific
        # enough to test against the whole normalised name.
        if "_" in word_upper:
            if word_upper in key_upper.replace("-", "_"):
                return f"*{word_upper}*"
            continue
        if any(_word_matches_component(word_upper, c) for c in components):
            return f"*{word_upper}*"

    return None


def matched_secret_env_key(key: str) -> tuple[bool, str | None]:
    """Decide whether an env/label key name is credential-like.

    Args:
        key: Environment variable or label key

    Returns:
        (is_secret_like, matched_pattern). Allowlisted keys return (False, None);
        their values are still scanned by the caller.
    """
    pattern = key_name_pattern(key)
    if pattern is None:
        return False, None
    if key.upper() in ENV_KEY_ALLOWLIST:
        return False, None
    return True, pattern


def is_allowlisted_secret_like_key(key: str) -> bool:
    """True when a key matches the vocabulary but is allowlisted as non-secret."""
    return key.upper() in ENV_KEY_ALLOWLIST and key_name_pattern(key) is not None


def value_looks_like_credential(value: str) -> bool:
    """Check a value for credential material without keeping any of it.

    Args:
        value: The value to inspect (never stored, returned or logged)

    Returns:
        True if the value matches one of the credential format detectors
    """
    if not value:
        return False
    candidate = value.strip()
    if not candidate or _PLACEHOLDER_VALUE_RE.match(candidate):
        # "$TOKEN" / "${TOKEN}" is a reference, not baked-in material.
        return False
    return any(pattern.search(candidate)
               for _name, pattern in _CREDENTIAL_VALUE_DETECTORS)


def _finding(source: str, kind: str, key: str | None = None,
             matched_pattern: str | None = None,
             location: str | None = None) -> ImageConfigSecretFinding:
    return ImageConfigSecretFinding(
        source=source,
        kind=kind,
        key=key,
        matched=True,
        matched_pattern=matched_pattern,
        location=location,
        classification=Classification.D,
    )


def _scan_assignment_keys(text: str, source: str, location: str,
                          findings: list[ImageConfigSecretFinding]) -> None:
    """Record credential-like KEY= assignment names found in free text.

    Only the key name is recorded; the assigned value is never examined for
    content beyond the format detectors applied separately by the caller.
    """
    seen: set[str] = set()
    for match in _ASSIGNMENT_KEY_RE.finditer(text):
        key = match.group(1)
        if key in seen:
            continue
        seen.add(key)
        is_secret, pattern = matched_secret_env_key(key)
        if is_secret:
            findings.append(_finding(
                source, KIND_CREDENTIAL_ENVIRONMENT, key=key,
                matched_pattern=pattern, location=location,
            ))


def _scan_env_entries(entries: Any, source: str, location: str,
                      findings: list[ImageConfigSecretFinding],
                      allowlisted: list[str]) -> int:
    """Scan a Config.Env style list of "KEY=value" strings.

    Returns:
        Number of entries scanned
    """
    if not isinstance(entries, list):
        return 0

    scanned = 0
    for entry in entries:
        if not isinstance(entry, str) or not entry:
            continue
        scanned += 1

        key, sep, value = entry.partition("=")
        key = key.strip()
        if not sep:
            value = ""

        is_secret, pattern = matched_secret_env_key(key)
        if is_secret:
            findings.append(_finding(
                source, KIND_CREDENTIAL_ENVIRONMENT, key=key or None,
                matched_pattern=pattern, location=location,
            ))
            # Already blocking on the name; scanning the value adds nothing.
            continue

        if is_allowlisted_secret_like_key(key) and key not in allowlisted:
            allowlisted.append(key)

        if value_looks_like_credential(value):
            # Value side: matched + kind only. Never the value, never which
            # detector matched.
            findings.append(_finding(
                source, KIND_POSSIBLE_CREDENTIAL_VALUE, key=key or None,
                location=location,
            ))

    return scanned


def _scan_text_list(values: Any, source: str, location: str,
                    findings: list[ImageConfigSecretFinding]) -> None:
    """Scan Config.Cmd / Config.Entrypoint token lists."""
    if not isinstance(values, list):
        return
    text = " ".join(v for v in values if isinstance(v, str))
    if not text:
        return
    _scan_assignment_keys(text, source, location, findings)
    if value_looks_like_credential(text):
        findings.append(_finding(
            source, KIND_POSSIBLE_CREDENTIAL_VALUE, location=location,
        ))


def _scan_labels(labels: Any, findings: list[ImageConfigSecretFinding],
                 allowlisted: list[str]) -> int:
    """Scan Config.Labels keys and values.

    Returns:
        Number of labels scanned
    """
    if not isinstance(labels, dict):
        return 0

    scanned = 0
    for key, value in labels.items():
        if not isinstance(key, str):
            continue
        scanned += 1

        is_secret, pattern = matched_secret_env_key(key)
        if is_secret:
            findings.append(_finding(
                SOURCE_CONFIG_LABELS, KIND_CREDENTIAL_LABEL, key=key,
                matched_pattern=pattern, location="Config.Labels",
            ))
            continue

        if is_allowlisted_secret_like_key(key) and key not in allowlisted:
            allowlisted.append(key)

        if isinstance(value, str) and value_looks_like_credential(value):
            findings.append(_finding(
                SOURCE_CONFIG_LABELS, KIND_POSSIBLE_CREDENTIAL_VALUE, key=key,
                location="Config.Labels",
            ))

    return scanned


def _scan_history(history: Any,
                  findings: list[ImageConfigSecretFinding]) -> int:
    """Scan `docker history --no-trunc` CreatedBy build commands.

    Returns:
        Number of history entries scanned
    """
    if not isinstance(history, list):
        return 0

    scanned = 0
    for index, entry in enumerate(history):
        if not isinstance(entry, dict):
            continue
        created_by = entry.get("CreatedBy")
        if not isinstance(created_by, str) or not created_by:
            scanned += 1
            continue

        scanned += 1
        location = f"history[{index}]"

        before = len(findings)
        _scan_assignment_keys(created_by, SOURCE_HISTORY_CREATED_BY,
                              location, findings)
        name_matched = len(findings) > before

        # The build command text itself is never logged or recorded.
        if not name_matched and value_looks_like_credential(created_by):
            findings.append(_finding(
                SOURCE_HISTORY_CREATED_BY, KIND_POSSIBLE_CREDENTIAL_VALUE,
                location=location,
            ))

    return scanned


def scan_image_config_data(inspect_data: dict[str, Any],
                           history: list[dict[str, Any]] | None = None
                           ) -> ImageConfigScanResult:
    """Scan already-fetched image metadata for credential material.

    Pure function: no Docker calls, no filesystem access. `scan_image_config()`
    is the thin wrapper that fetches the data.

    Args:
        inspect_data: One entry of `docker image inspect` JSON
        history: `docker history --no-trunc --format json` entries

    Returns:
        ImageConfigScanResult. `result` is "passed" only when no surface
        produced a finding.
    """
    findings: list[ImageConfigSecretFinding] = []
    allowlisted: list[str] = []

    config = inspect_data.get("Config")
    config = config if isinstance(config, dict) else {}

    env_scanned = _scan_env_entries(
        config.get("Env"), SOURCE_CONFIG_ENV, "Config.Env",
        findings, allowlisted,
    )

    # ContainerConfig is absent on docker 29 (containerd image store); scan it
    # when the daemon still reports it rather than assuming it cannot exist.
    container_config = inspect_data.get("ContainerConfig")
    container_config_present = isinstance(container_config, dict) and bool(
        container_config
    )
    if container_config_present:
        env_scanned += _scan_env_entries(
            container_config.get("Env"), SOURCE_CONTAINER_CONFIG_ENV,
            "ContainerConfig.Env", findings, allowlisted,
        )

    _scan_text_list(config.get("Cmd"), SOURCE_CONFIG_CMD,
                    "Config.Cmd", findings)
    _scan_text_list(config.get("Entrypoint"), SOURCE_CONFIG_ENTRYPOINT,
                    "Config.Entrypoint", findings)
    labels_scanned = _scan_labels(config.get("Labels"), findings, allowlisted)
    history_scanned = _scan_history(history, findings)

    return ImageConfigScanResult(
        performed=True,
        result="failed" if findings else "passed",
        scanner_version=CONFIG_SCANNER_VERSION,
        env_vars_scanned=env_scanned,
        labels_scanned=labels_scanned,
        history_entries_scanned=history_scanned,
        container_config_present=container_config_present,
        findings=findings,
        allowlisted_keys=allowlisted,
        message=(
            f"{len(findings)} credential-like item(s) in image config metadata"
            if findings else
            f"no credential-like items in {env_scanned} env var(s), "
            f"{labels_scanned} label(s), {history_scanned} history entry(ies)"
        ),
    )


def scan_image_config(image: str) -> ImageConfigScanResult:
    """Scan an image's config metadata and build history for credentials.

    Read-only: `docker image inspect` and `docker image history --no-trunc`.
    Nothing is executed inside the image.

    Args:
        image: Image reference or ID

    Returns:
        ImageConfigScanResult. A config or history that cannot be read yields
        result="error" - never a pass, because an unscanned image config must
        not be treated as safe.
    """
    try:
        inspect_data = inspect_image_json(image)
    except (DockerError, json.JSONDecodeError, ValueError) as exc:
        return ImageConfigScanResult(
            performed=True,
            result="error",
            scanner_version=CONFIG_SCANNER_VERSION,
            message=f"image config could not be read: {exc}",
        )

    try:
        history = get_image_history(image)
    except (DockerError, json.JSONDecodeError, ValueError) as exc:
        return ImageConfigScanResult(
            performed=True,
            result="error",
            scanner_version=CONFIG_SCANNER_VERSION,
            message=f"image history could not be read: {exc}",
        )

    return scan_image_config_data(inspect_data, history)
