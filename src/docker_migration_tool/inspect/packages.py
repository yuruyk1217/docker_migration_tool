"""Package inspection module.

Collects package manifests from containers for restoration.
"""

from docker_migration_tool.model import PackageManifest
from docker_migration_tool.utils.docker import docker_exec, DockerError


def inspect_packages(container: str, username: str | None = None) -> PackageManifest:
    """Inspect packages installed in a container.

    Args:
        container: Container name or ID
        username: Container username

    Returns:
        PackageManifest with package information
    """
    manifest = PackageManifest()

    # Get apt manually installed packages
    manifest.apt_manual = _get_apt_manual(container)

    # Get apt package versions
    manifest.apt_versions = _get_apt_versions(container, manifest.apt_manual)

    # Get pip freeze
    manifest.pip_freeze = _get_pip_freeze(container, username)

    # Get Python version
    manifest.python_version = _get_python_version(container)

    # Get ROS distro
    manifest.ros_distro = _get_ros_distro(container)

    return manifest


def _get_apt_manual(container: str) -> list[str]:
    """Get manually installed apt packages.

    Args:
        container: Container name

    Returns:
        List of package names
    """
    try:
        result = docker_exec(
            container,
            ["apt-mark", "showmanual"],
            timeout=30,
        )
        packages = [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]
        return packages
    except DockerError:
        return []


def _get_apt_versions(container: str, packages: list[str]) -> dict[str, str]:
    """Get versions of specific apt packages.

    Args:
        container: Container name
        packages: Packages to query

    Returns:
        Dict of package -> version
    """
    versions = {}

    if not packages:
        return versions

    # Query in batches to avoid command line length limits
    batch_size = 50
    for i in range(0, len(packages), batch_size):
        batch = packages[i:i + batch_size]
        try:
            result = docker_exec(
                container,
                ["dpkg-query", "-W", "-f=${Package}=${Version}\n"] + batch,
                timeout=30,
            )
            for line in result.stdout.strip().split("\n"):
                if "=" in line:
                    pkg, ver = line.split("=", 1)
                    versions[pkg.strip()] = ver.strip()
        except DockerError:
            pass

    return versions


def _get_pip_freeze(container: str, username: str | None = None) -> list[str]:
    """Get pip freeze output (user packages).

    Args:
        container: Container name
        username: Username for --user packages

    Returns:
        List of package==version strings
    """
    try:
        # Get user site packages
        result = docker_exec(
            container,
            ["pip3", "freeze", "--user"],
            user=username,
            timeout=60,
        )
        packages = [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]
        return packages
    except DockerError:
        # Try without --user
        try:
            result = docker_exec(
                container,
                ["pip3", "freeze"],
                user=username,
                timeout=60,
            )
            return [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]
        except DockerError:
            return []


def _get_python_version(container: str) -> str | None:
    """Get Python version.

    Args:
        container: Container name

    Returns:
        Version string or None
    """
    try:
        result = docker_exec(
            container,
            ["python3", "--version"],
            timeout=10,
        )
        # Output: "Python 3.10.12"
        output = result.stdout.strip()
        if output.startswith("Python "):
            return output.split()[1]
        return output
    except DockerError:
        return None


def _get_ros_distro(container: str) -> str | None:
    """Get ROS distribution.

    Args:
        container: Container name

    Returns:
        ROS distro name or None
    """
    try:
        result = docker_exec(
            container,
            ["sh", "-c", "echo $ROS_DISTRO"],
            timeout=10,
        )
        distro = result.stdout.strip()
        return distro if distro else None
    except DockerError:
        pass

    # Try sourcing ROS setup first
    try:
        result = docker_exec(
            container,
            ["sh", "-c", "source /opt/ros/*/setup.sh 2>/dev/null && echo $ROS_DISTRO"],
            timeout=10,
        )
        distro = result.stdout.strip()
        return distro if distro else None
    except DockerError:
        pass

    # Check for ROS installation
    try:
        result = docker_exec(
            container,
            ["ls", "/opt/ros/"],
            timeout=10,
        )
        distros = result.stdout.strip().split()
        if distros:
            return distros[0]  # Return first found
    except DockerError:
        pass

    return None


def collect_constraint_files(container: str, src_path: str, username: str | None = None) -> list[dict]:
    """Collect constraint files from workspace.

    Args:
        container: Container name
        src_path: Container path to src
        username: Container username

    Returns:
        List of {path, content} dicts
    """
    constraints = []

    # Known constraint file patterns
    patterns = [
        f"{src_path}/**/dependencies/python-constraints.txt",
        f"{src_path}/**/dependencies/constraints.txt",
        f"{src_path}/**/requirements.txt",
    ]

    for pattern in patterns:
        try:
            # Find files matching pattern
            result = docker_exec(
                container,
                ["sh", "-c", f"find {src_path} -name 'python-constraints.txt' -o -name 'constraints.txt' 2>/dev/null"],
                user=username,
                timeout=30,
            )
            for file_path in result.stdout.strip().split("\n"):
                if file_path:
                    try:
                        content_result = docker_exec(
                            container,
                            ["cat", file_path],
                            user=username,
                            timeout=10,
                        )
                        constraints.append({
                            "path": file_path,
                            "content": content_result.stdout,
                        })
                    except DockerError:
                        pass
        except DockerError:
            pass

    return constraints
