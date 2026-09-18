"""Docker CLI utilities.

Uses subprocess to call Docker commands. Never uses shell=True.
"""

import json
import subprocess
from pathlib import Path
from typing import Any


class DockerError(Exception):
    """Error from Docker command."""
    pass


def run_docker(args: list[str], capture_output: bool = True,
               check: bool = True, timeout: int | None = 300) -> subprocess.CompletedProcess:
    """Run a docker command safely (no shell=True).

    Args:
        args: Command arguments (without 'docker' prefix)
        capture_output: Capture stdout/stderr
        check: Raise on non-zero exit
        timeout: Command timeout in seconds

    Returns:
        CompletedProcess result

    Raises:
        DockerError: On command failure
    """
    cmd = ["docker"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=check,
            timeout=timeout,
        )
        return result
    except subprocess.CalledProcessError as e:
        raise DockerError(f"Docker command failed: {' '.join(cmd)}\n{e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"Docker command timed out: {' '.join(cmd)}") from e
    except FileNotFoundError:
        raise DockerError("Docker CLI not found. Is Docker installed?")


def run_docker_compose(args: list[str], cwd: str | Path | None = None,
                       capture_output: bool = True, check: bool = True,
                       timeout: int | None = 300) -> subprocess.CompletedProcess:
    """Run a docker compose command safely.

    Args:
        args: Command arguments (without 'docker compose' prefix)
        cwd: Working directory
        capture_output: Capture stdout/stderr
        check: Raise on non-zero exit
        timeout: Command timeout in seconds

    Returns:
        CompletedProcess result
    """
    cmd = ["docker", "compose"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=check,
            timeout=timeout,
            cwd=cwd,
        )
        return result
    except subprocess.CalledProcessError as e:
        raise DockerError(f"Docker compose failed: {' '.join(cmd)}\n{e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"Docker compose timed out: {' '.join(cmd)}") from e


def inspect_container_json(container: str) -> dict[str, Any]:
    """Get container inspect JSON.

    Args:
        container: Container name or ID

    Returns:
        Container inspect data
    """
    result = run_docker(["inspect", "--type=container", container])
    data = json.loads(result.stdout)
    if not data:
        raise DockerError(f"Container not found: {container}")
    return data[0]


def inspect_image_json(image: str) -> dict[str, Any]:
    """Get image inspect JSON.

    Args:
        image: Image name or ID

    Returns:
        Image inspect data
    """
    result = run_docker(["image", "inspect", image])
    data = json.loads(result.stdout)
    if not data:
        raise DockerError(f"Image not found: {image}")
    return data[0]


def get_container_info(container: str) -> dict[str, Any]:
    """Get comprehensive container information.

    Args:
        container: Container name or ID

    Returns:
        Dict with container details
    """
    data = inspect_container_json(container)

    # Parse user uid:gid
    user = data.get("Config", {}).get("User", "")

    # Extract compose labels
    labels = data.get("Config", {}).get("Labels", {})
    compose_project = labels.get("com.docker.compose.project")
    compose_working_dir = labels.get("com.docker.compose.project.working_dir")
    compose_config = labels.get("com.docker.compose.project.config_files", "")

    # Parse mounts
    mounts = []
    for m in data.get("Mounts", []):
        mounts.append({
            "source": m.get("Source", ""),
            "destination": m.get("Destination", ""),
            "mode": "ro" if m.get("RW") is False else "rw",
            "type": m.get("Type", "bind"),
            "propagation": m.get("Propagation"),
        })

    # Host config
    host_config = data.get("HostConfig", {})

    return {
        "name": data.get("Name", "").lstrip("/"),
        "id": data.get("Id", "")[:12],
        "image": data.get("Config", {}).get("Image", ""),
        "image_id": data.get("Image", "")[:12],
        "state": data.get("State", {}).get("Status", "unknown"),
        "created": data.get("Created", ""),
        "user": user,
        "privileged": host_config.get("Privileged", False),
        "network_mode": host_config.get("NetworkMode", "bridge"),
        "ipc": host_config.get("IpcMode", "private"),
        "shm_size": host_config.get("ShmSize"),
        "mounts": mounts,
        "env": data.get("Config", {}).get("Env", []),
        "labels": labels,
        "compose_project": compose_project,
        "compose_working_dir": compose_working_dir,
        "compose_config_files": compose_config.split(",") if compose_config else [],
    }


def get_image_info(image: str) -> dict[str, Any]:
    """Get comprehensive image information.

    Args:
        image: Image name or ID

    Returns:
        Dict with image details
    """
    data = inspect_image_json(image)

    # Parse repository:tag from RepoTags
    repo_tags = data.get("RepoTags", [])
    repository = ""
    tag = ""
    if repo_tags:
        if ":" in repo_tags[0]:
            repository, tag = repo_tags[0].rsplit(":", 1)
        else:
            repository = repo_tags[0]
            tag = "latest"

    # Get digest
    repo_digests = data.get("RepoDigests", [])
    digest = repo_digests[0] if repo_digests else None

    # Size
    size = data.get("Size", 0)

    # Ordered RootFS layer diff IDs. The ORDER is significant: parent images
    # are proven by their chain being a prefix of the child's chain.
    layers = list(data.get("RootFS", {}).get("Layers", []))

    return {
        "repository": repository,
        "tag": tag,
        "id": data.get("Id", "")[:12],
        "digest": digest,
        "size": size,
        "layers": len(layers),
        "rootfs_layers": layers,
        "created": data.get("Created", ""),
    }


def get_image_rootfs_layers(image: str) -> list[str]:
    """Get the ordered RootFS layer diff IDs of an image.

    Uses `docker image inspect` JSON (never string/table parsing).

    Args:
        image: Image name or ID

    Returns:
        Ordered list of layer diff IDs (empty if unavailable)
    """
    data = inspect_image_json(image)
    return list(data.get("RootFS", {}).get("Layers", []))


def list_image_references() -> list[str]:
    """List local image references (repository:tag), skipping untagged images.

    Returns:
        List of image references
    """
    try:
        result = run_docker(["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
    except DockerError:
        return []

    refs = []
    for line in result.stdout.strip().split("\n"):
        ref = line.strip()
        if not ref or "<none>" in ref:
            continue
        if ref not in refs:
            refs.append(ref)
    return refs


def get_images_rootfs_layers(references: list[str]) -> dict[str, list[str]]:
    """Get ordered RootFS layer chains for several images in one inspect call.

    Args:
        references: Image references

    Returns:
        Mapping of reference -> ordered layer diff IDs
    """
    if not references:
        return {}

    try:
        # check=False: a stale reference must not discard the other results
        result = run_docker(["image", "inspect", *references], check=False)
    except DockerError:
        return {}

    try:
        entries = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    by_repo_tag: dict[str, list[str]] = {}
    for entry in entries:
        layers = list(entry.get("RootFS", {}).get("Layers", []))
        for repo_tag in entry.get("RepoTags", []) or []:
            by_repo_tag[repo_tag] = layers

    # Preserve requested references (inspect output order may differ)
    return {ref: by_repo_tag[ref] for ref in references if ref in by_repo_tag}


def docker_exec(container: str, command: list[str], user: str | None = None,
                workdir: str | None = None, timeout: int | None = 300) -> subprocess.CompletedProcess:
    """Execute command in container.

    Args:
        container: Container name or ID
        command: Command to execute
        user: User to run as
        workdir: Working directory
        timeout: Command timeout

    Returns:
        CompletedProcess result
    """
    args = ["exec"]
    if user:
        args.extend(["-u", user])
    if workdir:
        args.extend(["-w", workdir])
    args.append(container)
    args.extend(command)

    return run_docker(args, timeout=timeout)


def docker_save(image: str, output_path: Path, progress: bool = False) -> None:
    """Save Docker image to tar file.

    Args:
        image: Image name or ID
        output_path: Output tar file path
        progress: Show progress (not implemented for subprocess)
    """
    args = ["save", "-o", str(output_path), image]
    # Use longer timeout for large images
    run_docker(args, timeout=3600, capture_output=not progress)


def docker_load(input_path: Path) -> str:
    """Load Docker image from tar file.

    Args:
        input_path: Input tar file path

    Returns:
        Loaded image reference
    """
    args = ["load", "-i", str(input_path)]
    result = run_docker(args, timeout=3600)
    # Parse loaded image from output
    for line in result.stdout.split("\n"):
        if "Loaded image:" in line:
            return line.split("Loaded image:")[-1].strip()
    return ""


def get_docker_version() -> str | None:
    """Get Docker version."""
    try:
        result = run_docker(["version", "--format", "{{.Server.Version}}"])
        return result.stdout.strip()
    except DockerError:
        return None


def get_compose_version() -> str | None:
    """Get Docker Compose version."""
    try:
        result = run_docker_compose(["version", "--short"])
        return result.stdout.strip()
    except DockerError:
        return None


def check_docker_access() -> bool:
    """Check if Docker daemon is accessible."""
    try:
        run_docker(["info"], timeout=10)
        return True
    except DockerError:
        return False


def list_volumes() -> list[dict[str, Any]]:
    """List Docker volumes."""
    try:
        result = run_docker(["volume", "ls", "--format", "json"])
        volumes = []
        for line in result.stdout.strip().split("\n"):
            if line:
                volumes.append(json.loads(line))
        return volumes
    except DockerError:
        return []


def get_image_history(image: str) -> list[dict[str, Any]]:
    """Get image history (layers).

    Args:
        image: Image name or ID

    Returns:
        List of layer info dicts
    """
    result = run_docker(["history", "--no-trunc", "--format", "json", image])
    history = []
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                history.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return history
