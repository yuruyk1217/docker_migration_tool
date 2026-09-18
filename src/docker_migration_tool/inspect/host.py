"""Host system inspection module.

Collects host information for compatibility comparison.
Never copies host-specific state directly.
"""

import os
import subprocess
from pathlib import Path

from docker_migration_tool.model import (
    HostInfo,
    HardwareInventory,
    NetworkIntent,
    Classification,
)
from docker_migration_tool.utils.docker import get_docker_version, get_compose_version
from docker_migration_tool.utils.filesystem import get_disk_free


def inspect_host() -> HostInfo:
    """Inspect host system information.

    Returns:
        HostInfo with system details
    """
    # OS info
    os_name, os_version = _get_os_info()
    kernel = _get_kernel_version()
    arch = _get_architecture()

    # CPU
    cpu = _get_cpu_info()

    # RAM
    ram_gb = _get_ram_gb()

    # Docker/Compose
    docker_version = get_docker_version()
    compose_version = get_compose_version()

    # GPU
    gpu_model, nvidia_driver = _get_nvidia_info()
    nvidia_toolkit = _get_nvidia_toolkit_version()

    # User
    uid = os.getuid()
    gid = os.getgid()
    groups = _get_user_groups()

    # Disk
    disk_free_gb = get_disk_free(Path.home()) // (1024 ** 3)

    # Display
    display = os.environ.get("DISPLAY")

    return HostInfo(
        os_name=os_name,
        os_version=os_version,
        kernel=kernel,
        architecture=arch,
        cpu=cpu,
        ram_gb=ram_gb,
        docker_version=docker_version,
        compose_version=compose_version,
        gpu_model=gpu_model,
        nvidia_driver=nvidia_driver,
        nvidia_toolkit=nvidia_toolkit,
        uid=uid,
        gid=gid,
        groups=groups,
        disk_free_gb=disk_free_gb,
        display=display,
        classification=Classification.C,
    )


def _get_os_info() -> tuple[str, str]:
    """Get OS name and version."""
    try:
        # Try lsb_release first
        result = subprocess.run(
            ["lsb_release", "-si"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        name = result.stdout.strip() if result.returncode == 0 else "Linux"

        result = subprocess.run(
            ["lsb_release", "-sr"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = result.stdout.strip() if result.returncode == 0 else "unknown"

        return name, version
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback to /etc/os-release
        try:
            with open("/etc/os-release") as f:
                info = {}
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        info[key] = value.strip('"')
                return info.get("NAME", "Linux"), info.get("VERSION_ID", "unknown")
        except OSError:
            return "Linux", "unknown"


def _get_kernel_version() -> str:
    """Get kernel version."""
    try:
        result = subprocess.run(
            ["uname", "-r"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "unknown"


def _get_architecture() -> str:
    """Get system architecture."""
    try:
        result = subprocess.run(
            ["uname", "-m"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "unknown"


def _get_cpu_info() -> str | None:
    """Get CPU model name."""
    try:
        result = subprocess.run(
            ["lscpu"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "Model name:" in line:
                    return line.split(":", 1)[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback to /proc/cpuinfo
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass

    return None


def _get_ram_gb() -> int:
    """Get total RAM in GB."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    # Value is in kB
                    kb = int(line.split()[1])
                    return kb // (1024 * 1024)
    except (OSError, ValueError):
        pass
    return 0


def _get_nvidia_info() -> tuple[str | None, str | None]:
    """Get NVIDIA GPU model and driver version."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            line = result.stdout.strip().split("\n")[0]
            parts = line.split(",")
            if len(parts) >= 2:
                return parts[0].strip(), parts[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None, None


def _get_nvidia_toolkit_version() -> str | None:
    """Get NVIDIA Container Toolkit version."""
    try:
        result = subprocess.run(
            ["nvidia-container-cli", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # Parse version from output
            for line in result.stdout.split("\n"):
                if "version" in line.lower():
                    parts = line.split()
                    for part in parts:
                        if part[0].isdigit():
                            return part
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def _get_user_groups() -> list[str]:
    """Get current user's groups."""
    try:
        result = subprocess.run(
            ["groups"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip().split()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return []


def inspect_hardware() -> HardwareInventory:
    """Inspect hardware devices.

    Returns:
        HardwareInventory with device information
    """
    # Cameras by ID
    cameras = _list_devices_by_id("/dev/v4l/by-id")

    # Serial by ID and path
    serial_by_id = _list_devices_by_id("/dev/serial/by-id")
    serial_by_path = _list_devices_by_id("/dev/serial/by-path")

    # USB devices
    usb_devices = _get_usb_devices()

    # DRI devices
    dri_devices = _list_devices("/dev/dri")

    # Sound devices
    sound_devices = _list_devices("/dev/snd")

    # Device GIDs
    dri_gid = _get_device_gid("/dev/dri/card0") or _get_device_gid("/dev/dri/renderD128")
    audio_gid = _get_device_gid("/dev/snd/controlC0")
    render_gid = _get_device_gid("/dev/dri/renderD128")

    return HardwareInventory(
        cameras_by_id=cameras,
        serial_by_id=serial_by_id,
        serial_by_path=serial_by_path,
        usb_devices=usb_devices,
        dri_devices=dri_devices,
        sound_devices=sound_devices,
        dri_gid=dri_gid,
        audio_gid=audio_gid,
        render_gid=render_gid,
        classification=Classification.C,
    )


def _list_devices_by_id(path: str) -> list[str]:
    """List device symlinks in a by-id directory."""
    devices = []
    try:
        dir_path = Path(path)
        if dir_path.exists():
            for entry in dir_path.iterdir():
                devices.append(entry.name)
    except OSError:
        pass
    return devices


def _list_devices(path: str) -> list[str]:
    """List devices in a directory."""
    devices = []
    try:
        dir_path = Path(path)
        if dir_path.exists():
            for entry in dir_path.iterdir():
                devices.append(entry.name)
    except OSError:
        pass
    return devices


def _get_usb_devices() -> list[dict[str, str]]:
    """Get USB devices from lsusb."""
    devices = []
    try:
        result = subprocess.run(
            ["lsusb"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line:
                    # Parse: Bus 001 Device 002: ID 1234:5678 Description
                    parts = line.split()
                    if len(parts) >= 6:
                        devices.append({
                            "bus": parts[1],
                            "device": parts[3].rstrip(":"),
                            "id": parts[5],
                            "description": " ".join(parts[6:]) if len(parts) > 6 else "",
                        })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return devices


def _get_device_gid(path: str) -> int | None:
    """Get GID of a device file."""
    try:
        stat = os.stat(path)
        return stat.st_gid
    except OSError:
        return None


def inspect_network() -> list[NetworkIntent]:
    """Inspect network configuration (intents only, no credentials).

    IMPORTANT: Never reads Wi-Fi passwords or other credentials.

    Returns:
        List of NetworkIntent
    """
    intents = []

    # Get interfaces
    interfaces = _get_network_interfaces()

    for iface in interfaces:
        intent = NetworkIntent(
            interface_name=iface.get("name", ""),
            interface_type=iface.get("type", "unknown"),
            address=iface.get("address"),
            subnet=iface.get("subnet"),
            gateway=iface.get("gateway"),
            connection_name=iface.get("connection_name"),
            classification=Classification.C,
        )
        intents.append(intent)

    return intents


def _get_network_interfaces() -> list[dict[str, str]]:
    """Get network interface information."""
    interfaces = []

    try:
        # Use ip command to get interfaces
        result = subprocess.run(
            ["ip", "-j", "addr"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)

            for iface in data:
                name = iface.get("ifname", "")
                if name == "lo":
                    continue

                # Determine type from name
                iface_type = "unknown"
                if name.startswith("en"):
                    iface_type = "ethernet"
                elif name.startswith("wl"):
                    iface_type = "wifi"
                elif name.startswith("enx"):
                    iface_type = "usb-ethernet"

                # Get addresses
                address = None
                subnet = None
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        address = addr_info.get("local")
                        prefix = addr_info.get("prefixlen")
                        if address and prefix:
                            subnet = f"{address}/{prefix}"
                        break

                interfaces.append({
                    "name": name,
                    "type": iface_type,
                    "address": address,
                    "subnet": subnet,
                    "state": iface.get("operstate", "unknown"),
                })

    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    # Try to get connection names from nmcli (no credentials)
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,DEVICE,TYPE", "connection", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 3:
                    conn_name, device, conn_type = parts[0], parts[1], parts[2]
                    # Find matching interface
                    for iface in interfaces:
                        if iface["name"] == device:
                            iface["connection_name"] = conn_name
                            break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return interfaces


def check_docker_group() -> bool:
    """Check if current user is in docker group."""
    groups = _get_user_groups()
    return "docker" in groups
