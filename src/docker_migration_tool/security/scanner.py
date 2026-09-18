"""Secret scanner for detecting credentials.

CRITICAL: This scanner detects secrets but NEVER reads or logs their contents.
Only existence, path, size, and kind are recorded.

Detection covers:
- Known credential paths (.codex, .claude, .ssh, etc.)
- Credential-like filenames (auth.json, secrets.yaml, etc.)
- Environment files that may contain secrets
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from docker_migration_tool.model import SecretFinding, Classification
from docker_migration_tool.utils.docker import docker_exec, DockerError


# Scanner ruleset version. Bump whenever SECRET_PATHS / kind classification
# changes so that bundle metadata records which ruleset produced the verdict.
SCANNER_VERSION = "1.1.0"

# Known secret paths (glob patterns).
#
# SINGLE SOURCE OF TRUTH: container scans, host scans and the image-layer scan
# (security/layers.py) all match against this list. Do not duplicate these
# patterns in other modules.
#
# NOTE: fnmatch's "*" also matches "/", so "/home/*/.claude/*" matches nested
# paths such as "/home/u/.claude/sessions/x.json".
SECRET_PATHS = [
    # AI/ML service credentials
    "/home/*/.codex/auth.json",
    "/home/*/.codex/*",
    "/home/*/.claude.json",
    "/home/*/.claude/*",
    "/home/*/.claude/sessions/*",
    "/home/*/.config/claude-bedrock/*",
    "/home/*/.config/claude-bedrock/env",
    # Root equivalents
    "/root/.codex/*",
    "/root/.claude*",
    "/root/.config/claude-bedrock/*",
    # SSH
    "/home/*/.ssh/*",
    "/home/*/.ssh/id_*",
    "/home/*/.ssh/*_rsa",
    "/home/*/.ssh/*_ed25519",
    "/home/*/.ssh/*_ecdsa",
    "/home/*/.ssh/*_dsa",
    "/home/*/.ssh/config",
    "/root/.ssh/*",
    # Docker credentials
    "/home/*/.docker/config.json",
    "/root/.docker/config.json",
    # AWS
    "/home/*/.aws/*",
    "/home/*/.aws/credentials",
    "/home/*/.aws/config",
    "/root/.aws/*",
    # GCP
    "/home/*/.config/gcloud/*",
    # Azure
    "/home/*/.azure/*",
    # Shell history (may contain secrets)
    "/home/*/.bash_history",
    "/home/*/.zsh_history",
    "/root/.bash_history",
    # NPM
    "/home/*/.npmrc",
    "/root/.npmrc",
    # Python/PyPI
    "/home/*/.pypirc",
    "/root/.pypirc",
    # Git credentials
    "/home/*/.git-credentials",
    "/root/.git-credentials",
    # Netrc
    "/home/*/.netrc",
    "/root/.netrc",
    # Keyring
    "/home/*/.local/share/keyrings/*",
    "/home/*/keyring-backup/*",
    # X11 auth
    "/home/*/.Xauthority",
    "/home/*/.docker/robotics-xauthority",
    "/tmp/.docker.xauth",
]

# Credential-like filename patterns
CREDENTIAL_FILENAMES = [
    r"auth\.json$",
    r"secrets?\.ya?ml$",
    r"secrets?\.json$",
    r"credentials?$",
    r"credentials?\.json$",
    r"\.env$",
    r"\.env\.local$",
    r"\.env\.production$",
    r"api[_-]?key",
    r"private[_-]?key",
    r"token\.json$",
    r"oauth.*\.json$",
]

# Generated config files (host-specific, never copy)
GENERATED_CONFIG_FILES = [
    ".env",
    "docker-compose.override.yml",
    "compose.generated.yml",
    ".docker.xauth",
    "robotics-xauthority",
]

# NVIDIA runtime files (host-specific, exclude from migration)
NVIDIA_RUNTIME_PATTERNS = [
    r"/usr/lib/.*nvidia.*",
    r"/usr/lib/x86_64-linux-gnu/.*nvidia.*",
    r"/usr/lib/x86_64-linux-gnu/libcuda.*",
    r"/usr/lib/x86_64-linux-gnu/libnvidia.*",
    r"/usr/bin/nvidia-.*",
    r"/usr/lib/firmware/nvidia/.*",
    r"/etc/nvidia/.*",
    r"/etc/OpenCL/.*",
    r"/etc/vulkan/.*nvidia.*",
    r"/etc/ld\.so\.conf\.d/.*nvidia.*",
    r"/run/nvidia-.*",
]


def _classify_secret_kind(path: str) -> str:
    """Classify the kind of secret a path represents.

    Shared by every scan surface (container, host, image layers) so the kind
    vocabulary is defined exactly once.

    Args:
        path: Absolute path (contents are never inspected)

    Returns:
        Secret kind label
    """
    if ".codex" in path:
        return "codex_credential"
    elif ".claude" in path or "claude-bedrock" in path:
        return "claude_credential"
    elif ".ssh" in path:
        return "ssh_key"
    elif ".docker/config" in path:
        return "docker_credential"
    elif ".aws" in path:
        return "aws_credential"
    elif "history" in path:
        return "shell_history"
    elif "keyring" in path:
        return "keyring"
    elif "xauth" in path.lower() or "Xauthority" in path:
        return "x11_cookie"
    elif ".npmrc" in path or ".pypirc" in path:
        return "package_registry_credential"
    elif "git-credentials" in path:
        return "git_credential"
    elif ".netrc" in path:
        return "netrc"
    elif "gcloud" in path or ".azure" in path:
        return "cloud_credential"
    return "credential"


def matches_secret_path_pattern(path: str) -> bool:
    """Check whether a path matches one of the known secret path globs.

    Args:
        path: Absolute path

    Returns:
        True if the path matches SECRET_PATHS
    """
    import fnmatch

    path = path.rstrip("/")
    return any(fnmatch.fnmatch(path, pattern) for pattern in SECRET_PATHS)


def is_secret_path(path: str) -> tuple[bool, str]:
    """Check if a path is a known secret location.

    Args:
        path: Path to check

    Returns:
        (is_secret, kind) tuple
    """
    # Normalize path
    path = path.rstrip("/")

    # Check against known paths
    if matches_secret_path_pattern(path):
        return True, _classify_secret_kind(path)

    # Check filename patterns
    filename = os.path.basename(path)
    for pattern in CREDENTIAL_FILENAMES:
        if re.search(pattern, filename, re.IGNORECASE):
            return True, "credential_file"

    return False, ""


def is_layer_secret_path(path: str) -> tuple[bool, str]:
    """Check whether an image-layer member path is a credential location.

    Uses the same SECRET_PATHS globs and the same kind vocabulary as
    `is_secret_path()`. It deliberately does NOT apply the
    `CREDENTIAL_FILENAMES` heuristics: an image layer legitimately contains
    thousands of library/test files whose names look credential-like
    (`.env`, `credentials.json`, `api_key.py`, ...), and treating those as
    credentials would block every export for no security benefit.

    Args:
        path: Absolute path reconstructed from a layer tar member name

    Returns:
        (is_secret, kind) tuple
    """
    path = path.rstrip("/")
    if matches_secret_path_pattern(path):
        return True, _classify_secret_kind(path)
    return False, ""


def is_generated_config(path: str) -> bool:
    """Check if a path is a generated config file that should not be copied.

    Args:
        path: Path to check

    Returns:
        True if path is a generated config
    """
    filename = os.path.basename(path)
    return filename in GENERATED_CONFIG_FILES


def is_nvidia_runtime_file(path: str) -> bool:
    """Check if a path is an NVIDIA runtime file injected by the toolkit.

    Args:
        path: Path to check

    Returns:
        True if path is an NVIDIA runtime file
    """
    for pattern in NVIDIA_RUNTIME_PATTERNS:
        if re.match(pattern, path):
            return True
    return False


@dataclass
class SecretScanner:
    """Scanner for detecting secrets in containers and images.

    IMPORTANT: Never reads or logs secret contents.
    """

    def scan_container(self, container: str, username: str | None = None) -> list[SecretFinding]:
        """Scan a running container for secrets.

        Args:
            container: Container name or ID
            username: Expected username in container

        Returns:
            List of secret findings (existence only, no contents)
        """
        findings = []

        # Paths to check
        check_paths = [
            # AI credentials
            f"/home/{username or '*'}/.codex",
            f"/home/{username or '*'}/.claude.json",
            f"/home/{username or '*'}/.claude",
            f"/home/{username or '*'}/.config/claude-bedrock",
            # Root
            "/root/.codex",
            "/root/.claude.json",
            "/root/.claude",
            # SSH
            f"/home/{username or '*'}/.ssh",
            "/root/.ssh",
            # Docker
            f"/home/{username or '*'}/.docker/config.json",
            # History
            f"/home/{username or '*'}/.bash_history",
        ]

        for path_pattern in check_paths:
            # For patterns with *, we need to resolve username
            if "*" in path_pattern and username:
                path = path_pattern.replace("*", username)
            else:
                path = path_pattern.strip("*")

            finding = self._check_path_in_container(container, path)
            if finding:
                findings.append(finding)

        return findings

    def _check_path_in_container(self, container: str, path: str) -> SecretFinding | None:
        """Check if a path exists in container (without reading content).

        Args:
            container: Container name
            path: Path to check

        Returns:
            SecretFinding if path exists, None otherwise
        """
        try:
            # Check existence and get size without reading content
            result = docker_exec(
                container,
                ["sh", "-c", f'[ -e "{path}" ] && stat -c "%s" "{path}" 2>/dev/null || echo "NOTFOUND"'],
                timeout=10,
            )
            output = result.stdout.strip()

            if output == "NOTFOUND" or not output:
                return None

            # Parse size
            try:
                size = int(output)
            except ValueError:
                size = None

            is_secret, kind = is_secret_path(path)
            if not kind:
                # Directories such as /home/<user>/.codex do not match the
                # file globs; classify them with the shared kind vocabulary
                # instead of reporting them as "unknown".
                kind = _classify_secret_kind(path)

            return SecretFinding(
                path=path,
                kind=kind,
                exists=True,
                size_bytes=size,
                location="container",
                classification=Classification.D,
            )

        except DockerError:
            return None

    def scan_image_paths(self, image: str) -> list[SecretFinding]:
        """Scan an image for known secret paths.

        This creates a temporary container to check paths.

        Args:
            image: Image name or ID

        Returns:
            List of secret findings
        """
        from docker_migration_tool.utils.docker import run_docker

        findings = []

        # Check paths by running a temporary container
        # We list known secret directories without reading content
        check_commands = [
            # Check .codex
            'find /home -maxdepth 3 -name ".codex" -type d 2>/dev/null',
            # Check .claude*
            'find /home -maxdepth 2 -name ".claude*" 2>/dev/null',
            # Check claude-bedrock
            'find /home -path "*/.config/claude-bedrock" -type d 2>/dev/null',
            # Check root
            'ls -la /root/.codex /root/.claude* 2>/dev/null || true',
            # Check .ssh private keys
            'find /home -path "*/.ssh/id_*" -o -path "*/.ssh/*_rsa" 2>/dev/null || true',
        ]

        for cmd in check_commands:
            try:
                result = run_docker([
                    "run", "--rm", "--entrypoint", "sh",
                    image, "-c", cmd
                ], timeout=30)

                for line in result.stdout.strip().split("\n"):
                    if line and not line.startswith("ls:"):
                        path = line.strip()
                        is_secret, kind = is_secret_path(path)
                        if is_secret:
                            findings.append(SecretFinding(
                                path=path,
                                kind=kind,
                                exists=True,
                                size_bytes=None,
                                location="image",
                                classification=Classification.D,
                            ))
            except DockerError:
                pass

        return findings


def scan_image_for_secrets(image: str) -> list[SecretFinding]:
    """Scan a Docker image for secrets.

    Args:
        image: Image name or ID

    Returns:
        List of secret findings
    """
    scanner = SecretScanner()
    return scanner.scan_image_paths(image)


def scan_container_for_secrets(container: str, username: str | None = None) -> list[SecretFinding]:
    """Scan a running container for secrets.

    Args:
        container: Container name or ID
        username: Expected username in container

    Returns:
        List of secret findings
    """
    scanner = SecretScanner()
    return scanner.scan_container(container, username)


def scan_path_for_secrets(path: Path) -> Iterator[SecretFinding]:
    """Scan a local path for secrets.

    Args:
        path: Path to scan

    Yields:
        Secret findings
    """
    if not path.exists():
        return

    if path.is_file():
        is_secret, kind = is_secret_path(str(path))
        if is_secret:
            yield SecretFinding(
                path=str(path),
                kind=kind,
                exists=True,
                size_bytes=path.stat().st_size,
                location="host",
                classification=Classification.D,
            )
        return

    # Walk directory
    for root, dirs, files in os.walk(path):
        # Skip .git internals
        if ".git" in root.split(os.sep):
            continue

        root_path = Path(root)

        for file in files:
            file_path = root_path / file
            is_secret, kind = is_secret_path(str(file_path))
            if is_secret:
                try:
                    size = file_path.stat().st_size
                except OSError:
                    size = None

                yield SecretFinding(
                    path=str(file_path),
                    kind=kind,
                    exists=True,
                    size_bytes=size,
                    location="host",
                    classification=Classification.D,
                )
