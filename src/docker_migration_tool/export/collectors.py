"""Collector classes for export operations.

These collectors gather specific types of data for the migration bundle.
The main orchestration is in bundle.py; these provide modular collection logic.
"""

from pathlib import Path
from typing import Protocol

from docker_migration_tool.model import (
    InspectionResult,
    ImageInfo,
    GitRepoInfo,
    PackageManifest,
    PortableDockerConfig,
    HostInfo,
    HardwareInventory,
)


class Collector(Protocol):
    """Protocol for collectors."""

    def collect(self) -> dict:
        """Collect data."""
        ...


class ImageCollector:
    """Collects image information."""

    def __init__(self, container_name: str):
        self.container_name = container_name

    def collect(self) -> tuple[ImageInfo | None, ImageInfo | None]:
        """Collect runtime and clean parent images.

        Returns:
            (runtime_image, clean_parent_image) tuple
        """
        from docker_migration_tool.inspect import (
            inspect_container,
            inspect_image,
            find_clean_parent_image,
        )

        container = inspect_container(self.container_name)
        runtime_image = inspect_image(container.image)

        # Find clean parent
        clean_parent = None
        workspace = discover_workspace_from_container(container)
        env_sh = workspace.get("docker_dir")
        if env_sh:
            env_sh_path = Path(env_sh) / "env.sh"
            if env_sh_path.exists():
                clean_parent = find_clean_parent_image(
                    container.image,
                    str(env_sh_path)
                )

        return runtime_image, clean_parent


class WorkspaceCollector:
    """Collects workspace data."""

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path

    def collect(self) -> dict:
        """Collect workspace information."""
        from docker_migration_tool.inspect import (
            inspect_workspace,
            find_large_files,
        )

        info = inspect_workspace(self.workspace_path)
        large_files = find_large_files(self.workspace_path / "src")

        return {
            "info": info,
            "large_files": large_files,
        }


class GitCollector:
    """Collects git repository state."""

    def __init__(self, src_path: Path):
        self.src_path = src_path

    def collect(self) -> list[GitRepoInfo]:
        """Collect git repository information."""
        from docker_migration_tool.inspect import inspect_git_repos
        return inspect_git_repos(self.src_path)


class PackageCollector:
    """Collects package manifests."""

    def __init__(self, container_name: str, username: str | None = None):
        self.container_name = container_name
        self.username = username

    def collect(self) -> PackageManifest:
        """Collect package information."""
        from docker_migration_tool.inspect import inspect_packages
        return inspect_packages(self.container_name, self.username)


class ConfigCollector:
    """Collects Docker configuration."""

    def __init__(self, docker_dir: Path):
        self.docker_dir = docker_dir

    def collect(self) -> PortableDockerConfig:
        """Collect Docker configuration."""
        from docker_migration_tool.inspect import inspect_docker_config
        return inspect_docker_config(self.docker_dir)


class HostCollector:
    """Collects host information."""

    def collect(self) -> HostInfo:
        """Collect host information."""
        from docker_migration_tool.inspect import inspect_host
        return inspect_host()


class HardwareCollector:
    """Collects hardware inventory."""

    def collect(self) -> HardwareInventory:
        """Collect hardware information."""
        from docker_migration_tool.inspect import inspect_hardware
        return inspect_hardware()


# Helper function from container inspection
def discover_workspace_from_container(container):
    """Helper to discover workspace from container."""
    from docker_migration_tool.inspect import discover_workspace_from_container as _discover
    return _discover(container)
