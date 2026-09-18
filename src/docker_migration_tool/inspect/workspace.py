"""Workspace inspection module.

Inspects ROS workspaces, git repositories, and Docker configuration.
"""

import os
import re
import subprocess
from pathlib import Path

from dataclasses import dataclass

from docker_migration_tool.model import (
    ExcludedLargeFile,
    GitRepoInfo,
    LargeFile,
    PortableDockerConfig,
    Classification,
)
from docker_migration_tool.utils.filesystem import (
    compute_sha256_file,
    matched_exclude_pattern,
    matched_exclude_pattern_for_relative,
)


# Large file threshold: 10 MB
LARGE_FILE_THRESHOLD = 10 * 1024 * 1024

# SINGLE SOURCE OF TRUTH for the workspace `src` archive exclusion policy.
#
# Every consumer must go through get_workspace_excludes():
#   - the real archive (create_archive in export/bundle.py)
#   - large-file discovery and checksums (discover_large_files below)
#   - the dry-run report
#
# Duplicating this list is what previously let the dry run claim "core.* is
# excluded" while simultaneously listing core.12345 as a large file to include.
DEFAULT_WORKSPACE_EXCLUDES = [
    "**/__pycache__",
    "**/build",
    "**/install",
    "**/log",
    "core.*",
    "*.jsonl",
]

# Host-specific generated files. These never live in `src`, but they must never
# reach the bundle from any path, so the policy names them explicitly.
# Portable Docker config is copied by the config collector, not by this archive;
# see security/scanner.py::GENERATED_CONFIG_FILES for the copy-side list.
GENERATED_FILE_EXCLUDES = [
    ".env",
    "docker-compose.override.yml",
    "compose.generated.yml",
    ".docker.xauth",
    "robotics-xauthority",
]


def inspect_workspace(workspace_path: Path) -> dict:
    """Inspect a workspace directory.

    Args:
        workspace_path: Path to workspace

    Returns:
        Dict with workspace info
    """
    result = {
        "path": str(workspace_path),
        "exists": workspace_path.exists(),
        "is_ros_workspace": False,
        "ros_distro": None,
        "has_src": False,
        "has_docker": False,
        "has_container_setup": False,
        "install_script_path": None,
        "size_bytes": 0,
    }

    if not workspace_path.exists():
        return result

    # Check for src directory
    src_path = workspace_path / "src"
    if src_path.exists():
        result["has_src"] = True
        result["is_ros_workspace"] = True

        # Check for _container_setup
        setup_path = src_path / "_container_setup"
        if setup_path.exists():
            result["has_container_setup"] = True

            # Check for install script
            install_script = setup_path / "install_workspace_dependencies.sh"
            if install_script.exists():
                result["install_script_path"] = str(install_script)

    # Check for docker directory
    docker_path = workspace_path / "docker"
    if docker_path.exists():
        result["has_docker"] = True

    # Calculate size
    result["size_bytes"] = _get_directory_size(workspace_path)

    return result


def inspect_git_repos(src_path: Path) -> list[GitRepoInfo]:
    """Inspect git repositories in a src directory.

    Args:
        src_path: Path to src directory

    Returns:
        List of GitRepoInfo
    """
    repos = []

    if not src_path.exists():
        return repos

    # Find .git directories
    git_dirs = []
    for root, dirs, files in os.walk(src_path):
        if ".git" in dirs:
            git_dirs.append(Path(root))
            # Don't recurse into .git or submodule dirs
            dirs[:] = [d for d in dirs if d != ".git"]

    for repo_path in git_dirs:
        repo_info = _inspect_git_repo(repo_path)
        if repo_info:
            repos.append(repo_info)

    return repos


def _inspect_git_repo(repo_path: Path) -> GitRepoInfo | None:
    """Inspect a single git repository.

    Args:
        repo_path: Path to repository

    Returns:
        GitRepoInfo or None on error
    """
    def run_git(args: list[str]) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path)] + args,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    # Get remote URL (preserve exactly, don't re-encode)
    remote_url = run_git(["config", "--get", "remote.origin.url"])

    # Get branch
    branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"])

    # Get HEAD commit
    head_commit = run_git(["rev-parse", "--short=12", "HEAD"])

    # Get upstream
    upstream = run_git(["rev-parse", "--abbrev-ref", "@{upstream}"])

    # Get ahead/behind
    ahead, behind = 0, 0
    if upstream:
        counts = run_git(["rev-list", "--left-right", "--count", f"HEAD...{upstream}"])
        if counts:
            parts = counts.split()
            if len(parts) == 2:
                ahead, behind = int(parts[0]), int(parts[1])

    # Check dirty state
    status = run_git(["status", "--porcelain"])
    is_dirty = bool(status)

    # Get modified files (tracked)
    modified = []
    if status:
        for line in status.split("\n"):
            if line and not line.startswith("??"):
                modified.append(line[3:])

    # Get untracked files
    untracked = []
    if status:
        for line in status.split("\n"):
            if line.startswith("??"):
                untracked.append(line[3:])

    # Get submodules
    submodules = []
    submodule_status = run_git(["submodule", "status"])
    if submodule_status:
        for line in submodule_status.split("\n"):
            if line:
                # Parse: +SHA path (branch) or -SHA path or SHA path
                parts = line.split()
                if len(parts) >= 2:
                    sub_sha = parts[0].lstrip("+-")
                    sub_path = parts[1]
                    sub_full_path = repo_path / sub_path

                    # Check if submodule is dirty (indicated by +)
                    sub_dirty = line.startswith("+")

                    # Get submodule remote
                    sub_remote = None
                    try:
                        result = subprocess.run(
                            ["git", "-C", str(sub_full_path), "config", "--get", "remote.origin.url"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        if result.returncode == 0:
                            sub_remote = result.stdout.strip()
                    except:
                        pass

                    submodules.append(GitRepoInfo(
                        path=sub_path,
                        remote_url=sub_remote,
                        head_commit=sub_sha[:12] if sub_sha else None,
                        is_dirty=sub_dirty,
                        classification=Classification.B,
                    ))

    return GitRepoInfo(
        path=str(repo_path),
        remote_url=remote_url,
        branch=branch,
        head_commit=head_commit,
        upstream=upstream,
        ahead=ahead,
        behind=behind,
        is_dirty=is_dirty,
        modified_files=modified,
        untracked_files=untracked,
        submodules=submodules,
        classification=Classification.B,
    )


@dataclass
class LargeFileDiscovery:
    """Result of large-file discovery under the workspace exclusion policy."""
    included: list[LargeFile]
    excluded: list[ExcludedLargeFile]


def discover_large_files(src_path: Path, threshold: int = LARGE_FILE_THRESHOLD,
                         compute_checksums: bool = True,
                         excludes: list[str] | None = None) -> LargeFileDiscovery:
    """Discover large files, applying the exclusion policy first.

    Order of operations (this order is the fix - large-file discovery must not
    run ahead of the exclusion policy):

        file discovery -> exclusion policy -> included set -> large-file test
        -> checksum

    An excluded file is never checksummed and never reported as included; it is
    only recorded as audit information with the pattern that dropped it.

    Args:
        src_path: Path to search (the authoritative workspace `src`)
        threshold: Size threshold in bytes
        compute_checksums: Whether to compute SHA-256 checksums
        excludes: Exclusion policy (defaults to the workspace policy)

    Returns:
        LargeFileDiscovery with included and excluded large files
    """
    excludes = get_workspace_excludes() if excludes is None else list(excludes)
    included: list[LargeFile] = []
    excluded: list[ExcludedLargeFile] = []

    if not src_path.exists():
        return LargeFileDiscovery(included=included, excluded=excluded)

    for root, dirs, files in os.walk(src_path):
        # Skip .git internals but not .git itself (we need to preserve it)
        root_path = Path(root)
        if ".git" in root_path.parts[:-1]:  # Skip contents of .git, not .git itself
            continue

        # Step 1: exclusion policy prunes directories before anything is sized
        dirs[:] = [
            d for d in dirs
            if matched_exclude_pattern(root_path / d, src_path, excludes) is None
        ]

        for file in files:
            file_path = root_path / file
            try:
                size = file_path.stat().st_size
            except OSError:
                continue

            rel_path = str(file_path.relative_to(src_path))

            # Step 2: exclusion policy decides membership of the include set
            pattern = matched_exclude_pattern(file_path, src_path, excludes)
            if pattern is not None:
                # Step 3: excluded files are audit-only - no checksum
                if size >= threshold:
                    excluded.append(ExcludedLargeFile(
                        path=rel_path,
                        size_bytes=size,
                        excluded_by=pattern,
                        classification=Classification.B,
                    ))
                continue

            # Step 4: large-file test on the include set only
            if size < threshold:
                continue

            is_gitignored = _is_gitignored(file_path, src_path)

            # Step 5: checksum
            sha256 = None
            if compute_checksums:
                try:
                    sha256 = compute_sha256_file(file_path)
                except OSError:
                    pass

            included.append(LargeFile(
                path=rel_path,
                size_bytes=size,
                sha256=sha256,
                is_gitignored=is_gitignored,
                classification=Classification.B,
            ))

    # Sort by size descending
    included.sort(key=lambda f: f.size_bytes, reverse=True)
    excluded.sort(key=lambda f: f.size_bytes, reverse=True)

    return LargeFileDiscovery(included=included, excluded=excluded)


def find_large_files(src_path: Path, threshold: int = LARGE_FILE_THRESHOLD,
                     compute_checksums: bool = True,
                     excludes: list[str] | None = None) -> list[LargeFile]:
    """Find large files that the workspace archive will actually include.

    Thin wrapper over discover_large_files() for callers that do not need the
    audit list of excluded large files.

    Args:
        src_path: Path to search
        threshold: Size threshold in bytes
        compute_checksums: Whether to compute SHA-256 checksums
        excludes: Exclusion policy (defaults to the workspace policy)

    Returns:
        List of LargeFile that pass the exclusion policy
    """
    return discover_large_files(
        src_path,
        threshold=threshold,
        compute_checksums=compute_checksums,
        excludes=excludes,
    ).included


def partition_large_files(
    large_files: list[LargeFile], excludes: list[str] | None = None,
) -> tuple[list[LargeFile], list[ExcludedLargeFile]]:
    """Re-apply the exclusion policy to an existing large-file list.

    Defensive re-check for consumers (LARGE_FILES.json, the dry-run report) so
    that a list built elsewhere can never report a file the archive drops.
    Operates on relative paths only; no filesystem access.

    Args:
        large_files: Large files with paths relative to the src root
        excludes: Exclusion policy (defaults to the workspace policy)

    Returns:
        (included, excluded) tuple
    """
    excludes = get_workspace_excludes() if excludes is None else list(excludes)
    included: list[LargeFile] = []
    excluded: list[ExcludedLargeFile] = []

    for large_file in large_files:
        pattern = matched_exclude_pattern_for_relative(large_file.path, excludes)
        if pattern is None:
            included.append(large_file)
        else:
            excluded.append(ExcludedLargeFile(
                path=large_file.path,
                size_bytes=large_file.size_bytes,
                excluded_by=pattern,
                classification=Classification.B,
            ))

    return included, excluded


def _is_gitignored(file_path: Path, repo_root: Path) -> bool:
    """Check if a file is gitignored.

    Args:
        file_path: File to check
        repo_root: Repository root

    Returns:
        True if gitignored
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", "-q", str(file_path)],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def inspect_docker_config(docker_dir: Path) -> PortableDockerConfig:
    """Inspect Docker configuration files.

    Identifies portable files vs generated files.

    Args:
        docker_dir: Path to docker directory

    Returns:
        PortableDockerConfig
    """
    config = PortableDockerConfig()

    if not docker_dir.exists():
        return config

    # Portable files (should be copied)
    portable_files = {
        "Dockerfile": "dockerfile_path",
        "docker-compose.yml": "compose_yml_path",
        "env.sh": "env_sh_path",
        "common.sh": "common_sh_path",
        "config.sh": "config_sh_path",
        ".dockerignore": "dockerignore_path",
    }

    for filename, attr in portable_files.items():
        file_path = docker_dir / filename
        if file_path.exists():
            setattr(config, attr, str(file_path))

    # Read Dockerfile content for analysis
    if config.dockerfile_path:
        try:
            with open(config.dockerfile_path, "r") as f:
                config.dockerfile_content = f.read()
        except OSError:
            pass

    # Look for udev rules
    workspace_dir = docker_dir.parent
    udev_locations = [
        workspace_dir / "udev" / "99-robotics-docker.rules",
        docker_dir / "udev" / "99-robotics-docker.rules",
    ]
    for udev_path in udev_locations:
        if udev_path.exists():
            config.udev_rules_path = str(udev_path)
            break

    # Look for install scripts
    script_locations = [
        (workspace_dir / "install_host_udev_rules.sh", "udev_install_script"),
        (workspace_dir / "install_user_xauthority_sync.sh", "xauthority_install_script"),
        (docker_dir / "install_host_udev_rules.sh", "udev_install_script"),
        (docker_dir / "install_user_xauthority_sync.sh", "xauthority_install_script"),
    ]
    for script_path, attr in script_locations:
        if script_path.exists() and getattr(config, attr) is None:
            setattr(config, attr, str(script_path))

    # Look for xauthority sync script
    xauth_locations = [
        workspace_dir / "xauthority" / "sync-robotics-xauthority.sh",
        docker_dir / "xauthority" / "sync-robotics-xauthority.sh",
    ]
    for xauth_path in xauth_locations:
        if xauth_path.exists():
            config.xauthority_sync_script = str(xauth_path)
            break

    # Look for desktop template
    desktop_locations = [
        workspace_dir / "xauthority" / "robotics-docker-xauthority.desktop.in",
        docker_dir / "xauthority" / "robotics-docker-xauthority.desktop.in",
    ]
    for desktop_path in desktop_locations:
        if desktop_path.exists():
            config.xauthority_desktop_template = str(desktop_path)
            break

    return config


def _get_directory_size(path: Path) -> int:
    """Get total size of a directory."""
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            for file in files:
                try:
                    total += (Path(root) / file).stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def get_workspace_excludes(include_generated: bool = True) -> list[str]:
    """Get the workspace `src` archive exclusion policy.

    This is the accessor every consumer must use: the real archive, large-file
    discovery, checksums and the dry-run report all read the policy from here so
    they cannot disagree.

    Args:
        include_generated: Also exclude host-specific generated files

    Returns:
        List of exclude patterns
    """
    excludes = DEFAULT_WORKSPACE_EXCLUDES.copy()
    if include_generated:
        excludes += GENERATED_FILE_EXCLUDES
    return excludes


def resolve_src_archive_root(workspace_path: Path,
                             src_bind_mount: Path | None = None) -> Path | None:
    """Resolve the authoritative source directory for workspace/src.tar.zst.

    The authoritative ROS workspace data is the host bind mount that the
    container sees as its colcon `src`. The workspace root is NOT archived:
    Dockerfile/env.sh/common.sh/config.sh/docker-compose.yml, udev rules and
    xauthority scripts are collected separately into docker/config/ by the
    portable config collector, so archiving the root would duplicate them and
    would risk pulling in host-specific generated files.

    Args:
        workspace_path: Workspace root (e.g. ~/my_workspace)
        src_bind_mount: Host source of the detected workspace bind mount

    Returns:
        The directory to archive, or None if no src directory can be found
    """
    if src_bind_mount is not None and src_bind_mount.exists():
        return src_bind_mount

    if workspace_path is None:
        return None

    candidate = workspace_path / "src"
    if candidate.exists():
        return candidate

    if workspace_path.name == "src" and workspace_path.exists():
        return workspace_path

    return None
