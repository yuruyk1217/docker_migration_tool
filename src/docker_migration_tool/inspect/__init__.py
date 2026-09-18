"""Inspection module for analyzing Docker environments.

Performs read-only inspection of containers, images, hosts, and workspaces.
"""

from docker_migration_tool.inspect.container import (
    inspect_container,
    discover_workspace_from_container,
    get_container_mounts,
)
from docker_migration_tool.inspect.image import (
    inspect_image,
    discover_clean_parent_candidates,
    find_clean_parent_image,
    resolve_clean_parent_image,
    verify_layer_relationship,
    get_image_history,
)
from docker_migration_tool.inspect.host import (
    inspect_host,
    inspect_hardware,
    inspect_network,
)
from docker_migration_tool.inspect.workspace import (
    inspect_workspace,
    inspect_git_repos,
    discover_large_files,
    find_large_files,
    partition_large_files,
    get_workspace_excludes,
    resolve_src_archive_root,
    inspect_docker_config,
)
from docker_migration_tool.inspect.packages import (
    inspect_packages,
)

__all__ = [
    "inspect_container",
    "discover_workspace_from_container",
    "get_container_mounts",
    "inspect_image",
    "discover_clean_parent_candidates",
    "find_clean_parent_image",
    "resolve_clean_parent_image",
    "verify_layer_relationship",
    "get_image_history",
    "inspect_host",
    "inspect_hardware",
    "inspect_network",
    "inspect_workspace",
    "inspect_git_repos",
    "discover_large_files",
    "find_large_files",
    "partition_large_files",
    "get_workspace_excludes",
    "resolve_src_archive_root",
    "inspect_docker_config",
    "inspect_packages",
]
