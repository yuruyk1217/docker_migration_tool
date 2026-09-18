"""Container inspection module."""

from pathlib import Path

from docker_migration_tool.model import (
    ContainerInfo,
    MountInfo,
    Classification,
)
from docker_migration_tool.utils.docker import (
    get_container_info,
    inspect_container_json,
    DockerError,
)
from docker_migration_tool.utils.logging import redact_value


def inspect_container(container_name: str) -> ContainerInfo:
    """Inspect a Docker container.

    Args:
        container_name: Container name or ID

    Returns:
        ContainerInfo with container details
    """
    data = get_container_info(container_name)
    full_data = inspect_container_json(container_name)

    # Parse environment variables with redaction
    env_vars = {}
    for env in data.get("env", []):
        if "=" in env:
            key, value = env.split("=", 1)
            env_vars[key] = redact_value(key, value)

    # Parse mounts
    mounts = []
    for m in data.get("mounts", []):
        mount = MountInfo(
            host_source=m.get("source", ""),
            container_target=m.get("destination", ""),
            mode=m.get("mode", "rw"),
            mount_type=m.get("type", "bind"),
            propagation=m.get("propagation"),
        )
        # Classify mount
        mount.classification, mount.migration_action = _classify_mount(mount)
        mounts.append(mount)

    # Extract workspace info from env or labels
    workspace_name = env_vars.get("WORKSPACE_NAME")
    ros_workspace = env_vars.get("ROS_WORKSPACE")
    container_username = env_vars.get("CONTAINER_USERNAME")

    # Find workspace mount
    workspace_path = None
    for m in mounts:
        if m.is_workspace:
            workspace_path = m.host_source
            break

    return ContainerInfo(
        name=data.get("name", ""),
        container_id=data.get("id", ""),
        image=data.get("image", ""),
        image_id=data.get("image_id", ""),
        state=data.get("state", "unknown"),
        created=data.get("created", ""),
        user=data.get("user", ""),
        privileged=data.get("privileged", False),
        network_mode=data.get("network_mode", "bridge"),
        ipc=data.get("ipc", "private"),
        shm_size=str(data.get("shm_size")) if data.get("shm_size") else None,
        mounts=mounts,
        env_vars=env_vars,
        labels=data.get("labels", {}),
        compose_project=data.get("compose_project"),
        compose_working_dir=data.get("compose_working_dir"),
        compose_config_files=data.get("compose_config_files", []),
        workspace_name=workspace_name,
        workspace_path=workspace_path,
        ros_workspace=ros_workspace,
        container_username=container_username,
    )


def _classify_mount(mount: MountInfo) -> tuple[Classification, str]:
    """Classify a mount for migration.

    Args:
        mount: Mount info

    Returns:
        (Classification, migration_action) tuple
    """
    target = mount.container_target
    source = mount.host_source

    # /dev mount - host device tree
    if target == "/dev" or source == "/dev":
        return Classification.C, "regenerate"

    # X11 socket
    if "/tmp/.X11-unix" in target or "/tmp/.X11-unix" in source:
        return Classification.C, "regenerate"

    # Xauthority - credential
    if "xauth" in target.lower() or "xauth" in source.lower():
        return Classification.D, "regenerate"

    # PulseAudio
    if "/pulse" in target or "/pulse" in source:
        return Classification.C, "regenerate"

    # Run directory (uid-specific)
    if "/run/user/" in source:
        return Classification.C, "regenerate"

    # Workspace src mount - THE critical one.
    #
    # The signal is the *shape* of the mount, not any particular workspace
    # directory name: a read-write bind mount whose container-side (or
    # host-side) path is a directory literally named ``src`` is the ROS
    # workspace source tree. Matching on names such as ``colcon_ws`` would
    # silently miss workspaces that happen to be called something else.
    if mount.mount_type == "bind":
        system_prefixes = ("/usr/", "/opt/ros/", "/var/", "/etc/")
        for candidate in (target, source):
            if not candidate or Path(candidate).name != "src":
                continue
            if candidate.startswith(system_prefixes):
                continue
            mount.is_workspace = True
            return Classification.B, "copy"

    # Volume
    if mount.mount_type == "volume":
        return Classification.B, "copy"

    # Default for bind mounts
    return Classification.C, "regenerate"


def discover_workspace_from_container(container: ContainerInfo) -> dict[str, str | None]:
    """Discover workspace paths from container info.

    Args:
        container: Container info

    Returns:
        Dict with workspace discovery results
    """
    result = {
        "workspace_name": container.workspace_name,
        "workspace_path": None,
        "compose_dir": None,
        "docker_dir": None,
        "src_mount_host": None,
        "src_mount_container": None,
    }

    # From compose labels
    if container.compose_working_dir:
        result["compose_dir"] = container.compose_working_dir
        # Docker dir is typically compose_dir itself or compose_dir/docker
        docker_dir = Path(container.compose_working_dir)
        if docker_dir.name == "docker":
            result["docker_dir"] = str(docker_dir)
            result["workspace_path"] = str(docker_dir.parent)
        else:
            # Check if docker subdir exists
            if (docker_dir / "docker").exists():
                result["docker_dir"] = str(docker_dir / "docker")
                result["workspace_path"] = str(docker_dir)
            else:
                result["docker_dir"] = str(docker_dir)
                result["workspace_path"] = str(docker_dir.parent)

    # From mounts
    for mount in container.mounts:
        if mount.is_workspace:
            result["src_mount_host"] = mount.host_source
            result["src_mount_container"] = mount.container_target

            # Derive workspace path from src mount
            src_path = Path(mount.host_source)
            if src_path.name == "src":
                result["workspace_path"] = str(src_path.parent)

    return result


def get_container_mounts(container_name: str) -> list[MountInfo]:
    """Get mounts for a container.

    Args:
        container_name: Container name or ID

    Returns:
        List of MountInfo
    """
    container = inspect_container(container_name)
    return container.mounts
