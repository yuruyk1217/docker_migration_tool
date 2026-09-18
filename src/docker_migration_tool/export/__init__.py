"""Export module for creating migration bundles.

Creates migration bundles with:
- Clean parent image (NOT snapshot with credentials)
- Workspace archive with git state
- Package manifests
- Portable Docker configuration
- Host/hardware information for comparison
"""

from docker_migration_tool.export.bundle import (
    create_bundle,
    BundleCreator,
)
from docker_migration_tool.export.collectors import (
    ImageCollector,
    WorkspaceCollector,
    GitCollector,
    PackageCollector,
    ConfigCollector,
    HostCollector,
    HardwareCollector,
)

__all__ = [
    "create_bundle",
    "BundleCreator",
    "ImageCollector",
    "WorkspaceCollector",
    "GitCollector",
    "PackageCollector",
    "ConfigCollector",
    "HostCollector",
    "HardwareCollector",
]
