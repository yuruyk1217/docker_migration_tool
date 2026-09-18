"""Preflight checks for import operation.

Validates that User B's host is ready for import.
"""

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from docker_migration_tool.model import VerificationResult
from docker_migration_tool.utils.docker import (
    check_docker_access,
    get_docker_version,
    get_compose_version,
    run_docker,
    DockerError,
)
from docker_migration_tool.utils.filesystem import get_disk_free
from docker_migration_tool.utils.logging import log_ok, log_warn, log_error, log_step


@dataclass
class PreflightResult:
    """Result of preflight checks."""
    passed: bool
    checks: list[VerificationResult]
    errors: list[str]
    warnings: list[str]


class PreflightChecker:
    """Runs preflight checks before import."""

    def __init__(self, bundle_path: Path):
        """Initialize preflight checker.

        Args:
            bundle_path: Path to migration bundle
        """
        self.bundle_path = bundle_path
        self.manifest = self._load_manifest()
        self.checks: list[VerificationResult] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def _load_manifest(self) -> dict:
        """Load bundle manifest."""
        manifest_path = self.bundle_path / "MANIFEST.json"
        if not manifest_path.exists():
            raise ValueError(f"Bundle manifest not found: {manifest_path}")
        with open(manifest_path) as f:
            return json.load(f)

    def run(self) -> PreflightResult:
        """Run all preflight checks.

        Returns:
            PreflightResult with check results
        """
        log_step("Running preflight checks...")

        self._check_docker()
        self._check_compose()
        self._check_docker_group()
        self._check_disk_space()
        self._check_gpu()
        self._check_nvidia_toolkit()
        self._check_bundle_security_metadata()
        self._check_runtime_image_consistency()  # P0 FIX
        self._validate_bundle()

        passed = len(self.errors) == 0
        return PreflightResult(
            passed=passed,
            checks=self.checks,
            errors=self.errors,
            warnings=self.warnings,
        )

    def _add_check(self, name: str, passed: bool, message: str,
                   status: str = "ok") -> None:
        """Add a check result."""
        if passed:
            log_ok(f"{name}: {message}")
        else:
            if status == "error":
                log_error(f"{name}: {message}")
            else:
                log_warn(f"{name}: {message}")

        self.checks.append(VerificationResult(
            name=name,
            passed=passed,
            status=status if passed else ("error" if status == "error" else "warning"),
            message=message,
        ))

    def _check_docker(self) -> None:
        """Check Docker is installed and accessible."""
        # Check installation
        version = get_docker_version()
        if not version:
            self.errors.append("Docker is not installed or not accessible")
            self._add_check("docker_installed", False, "Docker not found", "error")
            return

        self._add_check("docker_installed", True, f"Docker {version}")

        # Check daemon access
        if not check_docker_access():
            self.errors.append("Cannot connect to Docker daemon")
            self._add_check("docker_accessible", False, "Cannot connect to daemon", "error")
            return

        self._add_check("docker_accessible", True, "Daemon accessible")

    def _check_compose(self) -> None:
        """Check Docker Compose is available."""
        version = get_compose_version()
        if not version:
            self.errors.append("Docker Compose is not installed")
            self._add_check("compose_installed", False, "Compose not found", "error")
            return

        self._add_check("compose_installed", True, f"Compose {version}")

    def _check_docker_group(self) -> None:
        """Check user is in docker group."""
        try:
            result = subprocess.run(
                ["groups"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            groups = result.stdout.strip().split()
            if "docker" in groups:
                self._add_check("docker_group", True, "User in docker group")
            else:
                self.warnings.append("User not in docker group - may need sudo for Docker commands")
                self._add_check("docker_group", False, "User not in docker group", "warning")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.warnings.append("Could not check docker group membership")
            self._add_check("docker_group", False, "Could not verify", "warning")

    def _check_disk_space(self) -> None:
        """Check sufficient disk space."""
        # Need ~60GB: bundle + uncompressed image
        required_gb = 60
        home = Path.home()
        free_bytes = get_disk_free(home)
        free_gb = free_bytes // (1024 ** 3)

        if free_gb >= required_gb:
            self._add_check("disk_space", True, f"{free_gb} GB free (need {required_gb} GB)")
        else:
            self.errors.append(f"Insufficient disk space: {free_gb} GB free, need {required_gb} GB")
            self._add_check("disk_space", False, f"{free_gb} GB free, need {required_gb} GB", "error")

    def _check_gpu(self) -> None:
        """Check GPU availability if needed."""
        # Check if bundle requires GPU
        host_info_path = self.bundle_path / "host" / "host_info.json"
        requires_gpu = False
        if host_info_path.exists():
            with open(host_info_path) as f:
                host_info = json.load(f)
                requires_gpu = host_info.get("gpu_model") is not None

        if not requires_gpu:
            self._add_check("gpu", True, "GPU not required by bundle")
            return

        # Check nvidia-smi
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                gpu_name = result.stdout.strip().split("\n")[0]
                self._add_check("gpu", True, f"GPU: {gpu_name}")
            else:
                self.errors.append("nvidia-smi failed - GPU not accessible")
                self._add_check("gpu", False, "nvidia-smi failed", "error")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.errors.append("nvidia-smi not found - NVIDIA driver not installed")
            self._add_check("gpu", False, "nvidia-smi not found", "error")

    def _check_nvidia_toolkit(self) -> None:
        """Check NVIDIA Container Toolkit."""
        # Check if bundle requires GPU
        host_info_path = self.bundle_path / "host" / "host_info.json"
        requires_gpu = False
        if host_info_path.exists():
            with open(host_info_path) as f:
                host_info = json.load(f)
                requires_gpu = host_info.get("gpu_model") is not None

        if not requires_gpu:
            return

        try:
            result = subprocess.run(
                ["nvidia-container-cli", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._add_check("nvidia_toolkit", True, "NVIDIA Container Toolkit installed")
            else:
                self.errors.append("NVIDIA Container Toolkit not working")
                self._add_check("nvidia_toolkit", False, "Toolkit check failed", "error")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.errors.append("NVIDIA Container Toolkit not installed")
            self._add_check("nvidia_toolkit", False, "Toolkit not found", "error")

    def _security_metadata(self) -> dict:
        """Collect the bundle's export security metadata.

        MANIFEST.json is authoritative; docker/image/IMAGE_INFO.json is used as
        a fallback for the individual fields it also records.

        Returns:
            Merged metadata dict (empty when the bundle records nothing)
        """
        keys = (
            "parent_relationship_verified",
            "parent_relationship_method",
            "runtime_layer_count",
            "clean_image_layer_count",
            "layer_secret_scan",
            "layer_secret_scan_result",
            "scanner_version",
            "image_config_scan",
            "image_config_scan_result",
            "config_scanner_version",
        )

        metadata: dict = {}

        image_info_path = self.bundle_path / "docker" / "image" / "IMAGE_INFO.json"
        if image_info_path.exists():
            try:
                with open(image_info_path) as f:
                    image_info = json.load(f)
            except (json.JSONDecodeError, OSError):
                image_info = {}
            if isinstance(image_info, dict):
                metadata.update({k: image_info[k] for k in keys if k in image_info})

        metadata.update({k: self.manifest[k] for k in keys if k in self.manifest})
        return metadata

    def _check_bundle_security_metadata(self) -> None:
        """Reject bundles that do not carry a passing export security verdict.

        A bundle is refused when:
          * it records no security metadata at all (unsafe legacy bundle - it
            was produced before the layer gates existed, so nothing proves the
            exported image is credential-free),
          * parent_relationship_verified is not true,
          * layer_secret_scan_result is not "passed", or
          * image_config_scan_result is not "passed" (a credential baked into
            the image config or build history travels with `docker save` even
            when every layer path is clean).

        Missing metadata is never treated as implicitly safe.
        """
        log_step("Checking bundle security metadata...")

        metadata = self._security_metadata()

        if not metadata:
            self.errors.append(
                "unsafe legacy bundle: no export security metadata "
                "(parent_relationship_verified / layer_secret_scan_result). "
                "Re-export the bundle with a tool version that verifies the "
                "clean parent layer chain and scans all image layers."
            )
            self._add_check(
                "bundle_security_metadata", False,
                "unsafe legacy bundle: security metadata missing", "error",
            )
            return

        verified = metadata.get("parent_relationship_verified")
        scan_result = metadata.get("layer_secret_scan_result", "not_performed")
        scan_performed = metadata.get("layer_secret_scan", False)

        if verified is not True:
            self.errors.append(
                "Bundle refused: parent_relationship_verified is not true "
                f"(got {verified!r}). The exported image is not proven to be "
                "the credential-free parent of the source runtime image."
            )
            self._add_check(
                "parent_relationship_verified", False,
                f"not verified (parent_relationship_verified={verified!r})", "error",
            )
        else:
            self._add_check(
                "parent_relationship_verified", True,
                f"verified via {metadata.get('parent_relationship_method', 'unknown')} "
                f"({metadata.get('clean_image_layer_count', 0)}/"
                f"{metadata.get('runtime_layer_count', 0)} layers)",
            )

        if scan_result != "passed":
            self.errors.append(
                "Bundle refused: layer_secret_scan_result is not 'passed' "
                f"(got {scan_result!r}, layer_secret_scan={scan_performed!r}). "
                "The bundle image was not proven free of credential paths in "
                "every layer."
            )
            self._add_check(
                "layer_secret_scan", False,
                f"layer secret scan result: {scan_result}", "error",
            )
        else:
            self._add_check(
                "layer_secret_scan", True,
                f"passed (scanner {metadata.get('scanner_version', 'unknown')})",
            )

        config_result = metadata.get("image_config_scan_result", "not_performed")
        config_performed = metadata.get("image_config_scan", False)

        if config_result != "passed":
            self.errors.append(
                "Bundle refused: image_config_scan_result is not 'passed' "
                f"(got {config_result!r}, image_config_scan={config_performed!r}). "
                "The bundle image was not proven free of credentials in its "
                "config metadata (Config.Env / ContainerConfig.Env / Cmd / "
                "Entrypoint / Labels) or its build history."
            )
            self._add_check(
                "image_config_scan", False,
                f"image config/history scan result: {config_result}", "error",
            )
        else:
            self._add_check(
                "image_config_scan", True,
                "passed (config scanner "
                f"{metadata.get('config_scanner_version', 'unknown')})",
            )

    def _check_runtime_image_consistency(self) -> None:
        """P0 FIX: Verify the bundle's config uses the image the bundle provides.

        The clean image recorded in MANIFEST.json / IMAGE_INFO.json must match
        what the portable Docker config (env.sh) will actually use at runtime.
        If env.sh has a RUNTIME_IMAGE_TAG_OVERRIDE pointing to a source snapshot
        that the bundle doesn't contain, import would fail or use the wrong image.

        Since export now normalizes RUNTIME_IMAGE_TAG_OVERRIDE, this should pass.
        If it fails, the bundle was created by an older tool version or tampered.
        """
        log_step("Checking runtime image consistency...")

        # Get the clean image from manifest
        clean_image = self.manifest.get("clean_base_image")
        if not clean_image:
            self.warnings.append(
                "No clean_base_image in manifest - cannot verify runtime consistency"
            )
            self._add_check(
                "runtime_image_consistency", False,
                "No clean_base_image in manifest", "warning",
            )
            return

        # Parse env.sh to find what runtime image would actually be used
        env_sh_path = self.bundle_path / "docker" / "config" / "env.sh"
        if not env_sh_path.exists():
            # No env.sh - rely on defaults in common.sh/config.sh
            self._add_check(
                "runtime_image_consistency", True,
                f"No env.sh override - bundle uses {clean_image}",
            )
            return

        resolved_runtime = self._resolve_runtime_image_from_config(env_sh_path)

        if resolved_runtime is None:
            # Could not determine - not a hard error, just a warning
            self._add_check(
                "runtime_image_consistency", True,
                "Could not determine runtime image from config; assuming clean parent",
            )
            return

        if resolved_runtime == clean_image:
            self._add_check(
                "runtime_image_consistency", True,
                f"Config runtime image matches bundle: {clean_image}",
            )
        else:
            self.errors.append(
                f"Runtime image configuration references an image that is not "
                f"supplied by this bundle. Bundle provides: {clean_image}, "
                f"but config specifies: {resolved_runtime}. This bundle may have "
                f"been created by an older tool version or tampered with."
            )
            self._add_check(
                "runtime_image_consistency", False,
                f"Mismatch: bundle={clean_image}, config={resolved_runtime}", "error",
            )

    def _resolve_runtime_image_from_config(self, env_sh_path: Path) -> str | None:
        """Parse env.sh to find the effective runtime image.

        Looks for RUNTIME_IMAGE_TAG_OVERRIDE first (the override), then falls
        back to IMAGE_TAG or LOCAL_BASE_TAG constructions.

        Returns:
            The resolved image tag, or None if undeterminable
        """
        import re

        try:
            content = env_sh_path.read_text(encoding="utf-8")
        except OSError:
            return None

        # Look for RUNTIME_IMAGE_TAG_OVERRIDE first (takes precedence)
        patterns = [
            r'RUNTIME_IMAGE_TAG_OVERRIDE\s*=\s*"([^"]+)"',
            r"RUNTIME_IMAGE_TAG_OVERRIDE\s*=\s*'([^']+)'",
            r'RUNTIME_IMAGE_TAG_OVERRIDE\s*=\s*(\S+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                value = match.group(1)
                # Skip if it's a variable reference like ${VAR}
                if not value.startswith("$"):
                    return value

        # Fall back to IMAGE_TAG or LOCAL_BASE_TAG
        for var in ["IMAGE_TAG", "LOCAL_BASE_TAG"]:
            for pattern in [
                rf'{var}\s*=\s*"([^"]+)"',
                rf"{var}\s*=\s*'([^']+)'",
                rf'{var}\s*=\s*(\S+)',
            ]:
                match = re.search(pattern, content)
                if match:
                    value = match.group(1)
                    if not value.startswith("$"):
                        return value

        return None

    def _validate_bundle(self) -> None:
        """Validate bundle structure and checksums."""
        log_step("Validating bundle integrity...")

        # Check required directories
        required_dirs = ["docker/image", "docker/config", "workspace"]
        for dir_name in required_dirs:
            dir_path = self.bundle_path / dir_name
            if not dir_path.exists():
                self.errors.append(f"Missing bundle directory: {dir_name}")
                self._add_check("bundle_structure", False, f"Missing {dir_name}", "error")
                return

        self._add_check("bundle_structure", True, "Bundle structure valid")

        # Validate checksums
        checksums = self.manifest.get("checksums", {})
        for file_path, expected_hash in checksums.items():
            full_path = self.bundle_path / file_path
            if not full_path.exists():
                self.errors.append(f"Missing file: {file_path}")
                self._add_check("checksum_" + file_path, False, "File missing", "error")
                continue

            from docker_migration_tool.utils.filesystem import compute_sha256_file
            actual_hash = compute_sha256_file(full_path)
            if actual_hash == expected_hash:
                self._add_check("checksum_" + file_path, True, "Checksum valid")
            else:
                self.errors.append(f"Checksum mismatch: {file_path}")
                self._add_check("checksum_" + file_path, False, "Checksum mismatch", "error")


def run_preflight(bundle_path: Path) -> PreflightResult:
    """Run preflight checks.

    Args:
        bundle_path: Path to migration bundle

    Returns:
        PreflightResult
    """
    checker = PreflightChecker(bundle_path)
    return checker.run()
