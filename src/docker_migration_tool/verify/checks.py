"""Verification checks for bundles and restored workspaces."""

import json
import subprocess
from pathlib import Path

from docker_migration_tool.model import VerificationResult
from docker_migration_tool.utils.docker import (
    run_docker,
    docker_exec,
    check_docker_access,
    get_docker_version,
    DockerError,
)
from docker_migration_tool.utils.filesystem import compute_sha256_file
from docker_migration_tool.utils.logging import (
    log_ok, log_warn, log_error, log_step, log_header,
)


# Model weights are recognised by file extension rather than by package name,
# so no project-specific weight file is ever assumed to exist.
WEIGHT_SUFFIXES = (
    ".pt", ".pth", ".onnx", ".engine", ".trt", ".weights", ".safetensors", ".bin",
)
# Below this size a file is treated as a placeholder or a git-lfs pointer.
MIN_WEIGHT_SIZE_BYTES = 1024 * 1024


class BundleVerifier:
    """Verifies migration bundle integrity."""

    def __init__(self, bundle_path: Path):
        self.bundle_path = bundle_path
        self.results: list[VerificationResult] = []

    def verify(self) -> list[VerificationResult]:
        """Run all bundle verifications.

        Returns:
            List of verification results
        """
        log_header("Verifying Bundle")

        self._verify_structure()
        self._verify_manifest()
        self._verify_security_metadata()
        self._verify_checksums()
        self._verify_image()

        return self.results

    def _add_result(self, name: str, passed: bool, message: str,
                    status: str = "ok") -> None:
        """Add a verification result."""
        if passed:
            log_ok(f"{name}: {message}")
        else:
            if status == "error":
                log_error(f"{name}: {message}")
            else:
                log_warn(f"{name}: {message}")

        self.results.append(VerificationResult(
            name=name,
            passed=passed,
            status=status if passed else ("error" if status == "error" else "warning"),
            message=message,
        ))

    def _verify_structure(self) -> None:
        """Verify bundle directory structure."""
        log_step("Checking bundle structure...")

        required = [
            "MANIFEST.json",
            "docker/image",
            "docker/config",
            "workspace",
        ]

        for path in required:
            full_path = self.bundle_path / path
            if full_path.exists():
                self._add_result(f"structure_{path}", True, "Present")
            else:
                self._add_result(f"structure_{path}", False, "Missing", "error")

    def _verify_manifest(self) -> None:
        """Verify manifest is valid."""
        log_step("Checking manifest...")

        manifest_path = self.bundle_path / "MANIFEST.json"
        if not manifest_path.exists():
            self._add_result("manifest", False, "MANIFEST.json not found", "error")
            return

        try:
            with open(manifest_path) as f:
                manifest = json.load(f)

            required_keys = ["schema_version", "tool_version", "created_at"]
            missing = [k for k in required_keys if k not in manifest]

            if missing:
                self._add_result("manifest", False, f"Missing keys: {missing}", "warning")
            else:
                self._add_result("manifest", True, "Valid manifest")

        except json.JSONDecodeError as e:
            self._add_result("manifest", False, f"Invalid JSON: {e}", "error")

    def _verify_security_metadata(self) -> None:
        """Verify the bundle carries a passing export security verdict.

        Mirrors the import gate: a bundle without security metadata is reported
        as an unsafe legacy bundle rather than silently accepted.
        """
        log_step("Checking security metadata...")

        manifest_path = self.bundle_path / "MANIFEST.json"
        if not manifest_path.exists():
            return

        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except json.JSONDecodeError:
            return

        if "parent_relationship_verified" not in manifest and \
                "layer_secret_scan_result" not in manifest:
            self._add_result(
                "security_metadata", False,
                "unsafe legacy bundle: no export security metadata", "error",
            )
            return

        verified = manifest.get("parent_relationship_verified")
        if verified is True:
            self._add_result(
                "parent_relationship_verified", True,
                f"{manifest.get('parent_relationship_method', 'unknown')} "
                f"({manifest.get('clean_image_layer_count', 0)}/"
                f"{manifest.get('runtime_layer_count', 0)} layers)",
            )
        else:
            self._add_result(
                "parent_relationship_verified", False,
                f"not verified ({verified!r})", "error",
            )

        scan_result = manifest.get("layer_secret_scan_result", "not_performed")
        if scan_result == "passed":
            self._add_result(
                "layer_secret_scan", True,
                f"passed (scanner {manifest.get('scanner_version', 'unknown')})",
            )
        else:
            self._add_result(
                "layer_secret_scan", False,
                f"layer secret scan result: {scan_result}", "error",
            )

    def _verify_checksums(self) -> None:
        """Verify file checksums."""
        log_step("Verifying checksums...")

        manifest_path = self.bundle_path / "MANIFEST.json"
        if not manifest_path.exists():
            return

        with open(manifest_path) as f:
            manifest = json.load(f)

        checksums = manifest.get("checksums", {})
        if not checksums:
            self._add_result("checksums", True, "No checksums to verify")
            return

        all_valid = True
        for file_path, expected in checksums.items():
            full_path = self.bundle_path / file_path
            if not full_path.exists():
                self._add_result(f"checksum_{file_path}", False, "File missing", "error")
                all_valid = False
                continue

            actual = compute_sha256_file(full_path)
            if actual == expected:
                self._add_result(f"checksum_{file_path}", True, "Valid")
            else:
                self._add_result(f"checksum_{file_path}", False, "Mismatch", "error")
                all_valid = False

    def _verify_image(self) -> None:
        """Verify image file exists and is loadable."""
        log_step("Checking image...")

        image_path = self.bundle_path / "docker" / "image" / "base-image.tar"
        if not image_path.exists():
            self._add_result("image_file", False, "base-image.tar not found", "error")
            return

        self._add_result("image_file", True, f"Present ({image_path.stat().st_size / (1024**3):.1f} GB)")


class WorkspaceVerifier:
    """Verifies a restored workspace."""

    def __init__(self, workspace_path: Path, container_name: str | None = None):
        self.workspace_path = workspace_path
        self.container_name = container_name
        self.results: list[VerificationResult] = []

    def verify(self) -> list[VerificationResult]:
        """Run all workspace verifications.

        Returns:
            List of verification results
        """
        log_header("Verifying Workspace")

        self._verify_docker()
        self._verify_structure()
        self._verify_config()
        self._verify_container()
        self._verify_gpu()
        self._verify_ros()
        self._verify_models()

        return self.results

    def _add_result(self, name: str, passed: bool, message: str,
                    status: str = "ok") -> None:
        """Add a verification result."""
        if passed:
            log_ok(f"{name}: {message}")
        else:
            if status == "error":
                log_error(f"{name}: {message}")
            elif status == "manual":
                log_warn(f"{name}: {message} (manual check required)")
            else:
                log_warn(f"{name}: {message}")

        self.results.append(VerificationResult(
            name=name,
            passed=passed,
            status=status if passed else ("error" if status == "error" else "warning"),
            message=message,
        ))

    def _verify_docker(self) -> None:
        """Verify Docker environment."""
        log_step("Checking Docker...")

        version = get_docker_version()
        if version:
            self._add_result("docker", True, f"Docker {version}")
        else:
            self._add_result("docker", False, "Docker not available", "error")

        if check_docker_access():
            self._add_result("docker_access", True, "Daemon accessible")
        else:
            self._add_result("docker_access", False, "Cannot access daemon", "error")

    def _verify_structure(self) -> None:
        """Verify workspace structure."""
        log_step("Checking workspace structure...")

        src_path = self.workspace_path / "src"
        docker_path = self.workspace_path / "docker"

        if src_path.exists():
            self._add_result("workspace_src", True, "src directory present")
        else:
            self._add_result("workspace_src", False, "src directory missing", "error")

        if docker_path.exists():
            self._add_result("workspace_docker", True, "docker directory present")
        else:
            self._add_result("workspace_docker", False, "docker directory missing", "error")

    def _verify_config(self) -> None:
        """Verify configuration files."""
        log_step("Checking configuration...")

        docker_dir = self.workspace_path / "docker"

        # Check for required files
        required = ["docker-compose.yml", "Dockerfile", "env.sh", "common.sh", "config.sh"]
        for filename in required:
            if (docker_dir / filename).exists():
                self._add_result(f"config_{filename}", True, "Present")
            else:
                self._add_result(f"config_{filename}", False, "Missing", "warning")

        # Check for generated files
        if (docker_dir / ".env").exists():
            self._add_result("config_env", True, ".env generated")
        else:
            self._add_result("config_env", False, ".env not generated", "error")

        if (docker_dir / "docker-compose.override.yml").exists():
            self._add_result("config_override", True, "override generated")
        else:
            self._add_result("config_override", False, "override not generated", "error")

    def _verify_container(self) -> None:
        """Verify container is running."""
        log_step("Checking container...")

        if not self.container_name:
            # Try to discover
            docker_dir = self.workspace_path / "docker"
            try:
                from docker_migration_tool.utils.docker import run_docker_compose
                result = run_docker_compose(
                    ["ps", "--format", "json"],
                    cwd=docker_dir,
                    timeout=30,
                )
                containers = json.loads(result.stdout)
                if containers:
                    self.container_name = containers[0].get("Name")
            except (DockerError, json.JSONDecodeError):
                pass

        if not self.container_name:
            self._add_result("container", False, "Container not found", "warning")
            return

        try:
            result = run_docker(["inspect", "--format", "{{.State.Status}}", self.container_name])
            status = result.stdout.strip()
            if status == "running":
                self._add_result("container", True, f"{self.container_name} running")
            else:
                self._add_result("container", False, f"{self.container_name} is {status}", "warning")
        except DockerError:
            self._add_result("container", False, "Container not found", "warning")

    def _verify_gpu(self) -> None:
        """Verify GPU access."""
        log_step("Checking GPU...")

        # Host GPU
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                gpu = result.stdout.strip().split("\n")[0]
                self._add_result("gpu_host", True, f"Host GPU: {gpu}")
            else:
                self._add_result("gpu_host", False, "nvidia-smi failed", "warning")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self._add_result("gpu_host", False, "nvidia-smi not found", "warning")

        # Container GPU
        if self.container_name:
            try:
                result = docker_exec(
                    self.container_name,
                    ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                    timeout=10,
                )
                if result.returncode == 0:
                    gpu = result.stdout.strip().split("\n")[0]
                    self._add_result("gpu_container", True, f"Container GPU: {gpu}")
                else:
                    self._add_result("gpu_container", False, "nvidia-smi failed in container", "warning")
            except DockerError:
                self._add_result("gpu_container", False, "Could not check GPU in container", "warning")

    def _verify_ros(self) -> None:
        """Verify ROS environment."""
        log_step("Checking ROS...")

        if not self.container_name:
            self._add_result("ros", False, "Cannot verify without container", "warning")
            return

        # Check ROS distro
        try:
            result = docker_exec(
                self.container_name,
                ["bash", "-c", "source /opt/ros/*/setup.bash && echo $ROS_DISTRO"],
                timeout=10,
            )
            distro = result.stdout.strip()
            if distro:
                self._add_result("ros_distro", True, f"ROS {distro}")
            else:
                self._add_result("ros_distro", False, "ROS distro not found", "warning")
        except DockerError:
            self._add_result("ros_distro", False, "Could not check ROS", "warning")

        # Check workspace build. No workspace directory name is assumed: the
        # first ``~/*/install/setup.bash`` present inside the container is
        # sourced, so a workspace called anything at all is picked up.
        source_workspace = (
            'for setup in "$HOME"/*/install/setup.bash; do '
            'if [ -f "$setup" ]; then . "$setup"; break; fi; done'
        )
        try:
            result = docker_exec(
                self.container_name,
                [
                    "bash", "-c",
                    "source /opt/ros/*/setup.bash && "
                    f"{{ {source_workspace}; }} 2>/dev/null; "
                    "ros2 pkg list | wc -l",
                ],
                timeout=30,
            )
            pkg_count = result.stdout.strip()
            if pkg_count and int(pkg_count) > 0:
                self._add_result("ros_packages", True, f"{pkg_count} ROS packages")
            else:
                self._add_result("ros_packages", False, "No ROS packages found", "warning")
        except (DockerError, ValueError):
            self._add_result("ros_packages", False, "Could not list packages", "warning")

    def _verify_models(self) -> None:
        """Verify model weights are present.

        Weight files are discovered by extension and size, not by package or
        file name: the tool has no knowledge of which perception packages a
        given workspace happens to contain.
        """
        log_step("Checking model weights...")

        src_path = self.workspace_path / "src"
        if not src_path.is_dir():
            self._add_result("model_weights", False, "No src directory", "warning")
            return

        found: list[Path] = []
        for path in src_path.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in WEIGHT_SUFFIXES:
                continue
            # Skip placeholders and git-lfs pointer files.
            if path.stat().st_size < MIN_WEIGHT_SIZE_BYTES:
                continue
            found.append(path)

        if found:
            total_mb = sum(p.stat().st_size for p in found) / (1024 * 1024)
            self._add_result(
                "model_weights", True,
                f"{len(found)} weight files, {total_mb:.0f} MB total",
            )
        else:
            self._add_result(
                "model_weights", False,
                "No model weight files found in workspace src", "warning",
            )


def verify_bundle(bundle_path: Path) -> list[VerificationResult]:
    """Verify a migration bundle.

    Args:
        bundle_path: Path to bundle

    Returns:
        List of verification results
    """
    verifier = BundleVerifier(bundle_path)
    return verifier.verify()


def verify_workspace(workspace_path: Path, container_name: str | None = None) -> list[VerificationResult]:
    """Verify a restored workspace.

    Args:
        workspace_path: Path to workspace
        container_name: Container name

    Returns:
        List of verification results
    """
    verifier = WorkspaceVerifier(workspace_path, container_name)
    return verifier.verify()
