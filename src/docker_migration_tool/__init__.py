"""Docker Migration Tool for robotics development environments.

This tool migrates Docker-based robotics development environments from
User A's machine to User B's machine, preserving workspace state, git
repositories, and configuration while properly handling secrets and
host-dependent state.

v1 Strategy:
- Export clean parent image (NOT the snapshot with credentials)
- Archive workspace src with git state preserved
- Collect package manifests for restoration via existing scripts
- Never copy host-specific generated files (.env, override)
- Regenerate host-dependent configuration on User B's machine
"""

__version__ = "1.0.0"
__author__ = "Robotics Team"

from docker_migration_tool.model import (
    Classification,
    MountInfo,
    ContainerInfo,
    ImageInfo,
    GitRepoInfo,
    BundleManifest,
)

__all__ = [
    "__version__",
    "Classification",
    "MountInfo",
    "ContainerInfo",
    "ImageInfo",
    "GitRepoInfo",
    "BundleManifest",
]
