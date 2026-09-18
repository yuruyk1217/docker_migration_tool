"""Bundle restoration module.

Restores migration bundles on User B's machine.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

from docker_migration_tool.model import ImportResult, VerificationResult
from docker_migration_tool.importers.preflight import run_preflight
from docker_migration_tool.utils.docker import docker_load, run_docker, run_docker_compose, DockerError
from docker_migration_tool.utils.filesystem import safe_extract_archive, ensure_directory
from docker_migration_tool.utils.logging import (
    log_ok, log_warn, log_error, log_info, log_step, log_header,
)


# Where a restored workspace is placed when neither --workspace nor the
# environment variable below is given. Deliberately a generic directory under
# the *importing* user's own home: nothing about the source host is reused.
DEFAULT_WORKSPACE_ROOT_ENV = "DOCKER_MIGRATION_WORKSPACE_ROOT"
DEFAULT_WORKSPACE_ROOT_NAME = "docker_workspaces"

# Path of the optional dependency installer *inside* the workspace, relative to
# the workspace src directory. The absolute in-container path is never
# hardcoded: it is derived from the bundle manifest and, failing that, searched
# for below the container user's own home directory.
DEPENDENCY_SCRIPT_RELATIVE = "_container_setup/install_workspace_dependencies.sh"


class BundleRestorer:
    """Restores migration bundles."""

    def __init__(self, bundle_path: Path, target_workspace: Path | None = None,
                 ros_domain_id: int | None = None, dry_run: bool = False,
                 interactive: bool = True):
        """Initialize restorer.

        Args:
            bundle_path: Path to migration bundle
            target_workspace: Target workspace path
                (default: ~/docker_workspaces/<workspace name>)
            ros_domain_id: ROS domain ID to use (None = prompt or keep original)
            dry_run: If True, don't make changes
            interactive: If True, prompt for decisions
        """
        self.bundle_path = bundle_path
        self.target_workspace = target_workspace
        self.ros_domain_id = ros_domain_id
        self.dry_run = dry_run
        self.interactive = interactive
        self.manifest = self._load_manifest()
        self.verifications: list[VerificationResult] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.manual_actions: list[str] = []

    def _load_manifest(self) -> dict:
        """Load bundle manifest."""
        manifest_path = self.bundle_path / "MANIFEST.json"
        if not manifest_path.exists():
            raise ValueError(f"Bundle manifest not found: {manifest_path}")
        with open(manifest_path) as f:
            return json.load(f)

    def restore(self) -> ImportResult:
        """Restore the bundle.

        Returns:
            ImportResult with restoration status
        """
        log_header("Restoring Migration Bundle")

        # Run preflight
        log_step("Running preflight checks...")
        preflight = run_preflight(self.bundle_path)
        self.verifications.extend(preflight.checks)

        if not preflight.passed:
            log_error("Preflight checks failed")
            for error in preflight.errors:
                log_error(f"  {error}")
            return ImportResult(
                success=False,
                verifications=self.verifications,
                errors=preflight.errors,
            )

        log_ok("Preflight checks passed")

        if self.dry_run:
            # P1 FIX: Determine workspace path BEFORE dry-run report so we can
            # show the planned target rather than "None"
            self._determine_workspace_path()
            self._dry_run_report()
            return ImportResult(
                success=True,
                workspace_path=str(self.target_workspace) if self.target_workspace else None,
                verifications=self.verifications,
                warnings=["Dry run - no changes made"],
            )

        try:
            # Determine workspace path
            self._determine_workspace_path()

            # Load image
            self._load_image()

            # Restore workspace
            self._restore_workspace()

            # Restore Docker config
            self._restore_docker_config()

            # Setup udev (requires sudo)
            self._setup_udev()

            # Setup Xauthority
            self._setup_xauthority()

            # Regenerate host-specific config
            self._regenerate_config()

            # Handle ROS domain ID
            self._handle_ros_domain_id()

            # Start container and restore dependencies
            self._restore_dependencies()

            # Add manual actions
            self._collect_manual_actions()

            return ImportResult(
                success=True,
                workspace_path=str(self.target_workspace),
                container_name=self.manifest.get("container_name"),
                verifications=self.verifications,
                warnings=self.warnings,
                manual_actions_required=self.manual_actions,
            )

        except Exception as e:
            log_error(f"Restoration failed: {e}")
            self.errors.append(str(e))
            return ImportResult(
                success=False,
                workspace_path=str(self.target_workspace) if self.target_workspace else None,
                verifications=self.verifications,
                errors=self.errors,
                warnings=self.warnings,
            )

    def _determine_workspace_path(self) -> None:
        """Determine target workspace path.

        Resolution order (no source-host path is ever reused):

            1. the explicit ``--workspace`` argument
            2. ``$DOCKER_MIGRATION_WORKSPACE_ROOT/<workspace name>``
            3. ``~/docker_workspaces/<workspace name>``
        """
        if self.target_workspace:
            return

        workspace_name = self.manifest.get("workspace_name") or "restored_workspace"

        root_override = os.environ.get(DEFAULT_WORKSPACE_ROOT_ENV)
        root = (Path(root_override).expanduser() if root_override
                else Path.home() / DEFAULT_WORKSPACE_ROOT_NAME)
        self.target_workspace = root / workspace_name

        log_info(f"Target workspace: {self.target_workspace}")
        if not root_override:
            log_info(
                "  (override with --workspace or "
                f"${DEFAULT_WORKSPACE_ROOT_ENV})"
            )

    def _dry_run_report(self) -> None:
        """Report what would be done in dry run."""
        log_header("Dry Run Report")

        # P1 FIX: Show the planned workspace path clearly
        log_info(f"Planned workspace: {self.target_workspace}")

        # Image
        image = self.manifest.get("clean_base_image")
        if image:
            log_info(f"Would load image: {image}")

        # Workspace
        log_info("Would extract workspace archive")

        # Config
        log_info("Would restore Docker configuration")

        # Sudo actions
        log_info("\nSudo will be required for:")
        log_info("  - udev rule installation")

        # Regeneration
        log_info("\nWill regenerate on this host:")
        log_info("  - .env (via config.sh)")
        log_info("  - docker-compose.override.yml (via config.sh)")
        log_info("  - X11 cookie (via xauthority sync)")

        # Manual actions
        log_info("\nManual actions will be required:")
        log_info("  - Supply credentials (see SECRETS_REQUIRED.md)")
        log_info("  - Configure network interfaces")
        log_info("  - Verify device paths")

    def _load_image(self) -> None:
        """Load the base image."""
        log_step("Loading base image...")

        image_path = self.bundle_path / "docker" / "image" / "base-image.tar"
        if not image_path.exists():
            raise ValueError(f"Image file not found: {image_path}")

        try:
            loaded = docker_load(image_path)
            log_ok(f"Image loaded: {loaded or self.manifest.get('clean_base_image')}")

            self.verifications.append(VerificationResult(
                name="image_loaded",
                passed=True,
                status="ok",
                message="Base image loaded successfully",
            ))
        except DockerError as e:
            log_error(f"Failed to load image: {e}")
            raise

    def _restore_workspace(self) -> None:
        """Restore workspace from archive."""
        log_step("Restoring workspace...")

        archive_path = self.bundle_path / "workspace" / "src.tar.zst"
        if not archive_path.exists():
            # Try .tar.gz
            archive_path = self.bundle_path / "workspace" / "src.tar.gz"
        if not archive_path.exists():
            raise ValueError("Workspace archive not found")

        # Create target directory
        src_path = self.target_workspace / "src"
        ensure_directory(self.target_workspace)

        # Extract archive
        safe_extract_archive(archive_path, src_path)

        log_ok(f"Workspace restored to: {src_path}")

        self.verifications.append(VerificationResult(
            name="workspace_restored",
            passed=True,
            status="ok",
            message=f"Workspace restored to {src_path}",
        ))

    def _restore_docker_config(self) -> None:
        """Restore Docker configuration files."""
        log_step("Restoring Docker configuration...")

        config_src = self.bundle_path / "docker" / "config"
        docker_dir = self.target_workspace / "docker"
        ensure_directory(docker_dir)

        # Copy portable files
        portable_files = [
            "Dockerfile",
            "docker-compose.yml",
            "env.sh",
            "common.sh",
            "config.sh",
            ".dockerignore",
        ]

        for filename in portable_files:
            src = config_src / filename
            if src.exists():
                shutil.copy(src, docker_dir / filename)
                # Make scripts executable
                if filename.endswith(".sh"):
                    os.chmod(docker_dir / filename, 0o755)

        # Copy udev directory
        udev_src = config_src / "udev"
        if udev_src.exists():
            udev_dst = self.target_workspace / "udev"
            if udev_dst.exists():
                shutil.rmtree(udev_dst)
            shutil.copytree(udev_src, udev_dst)

        # Copy install scripts
        for script in ["install_host_udev_rules.sh", "install_user_xauthority_sync.sh"]:
            src = config_src / script
            if src.exists():
                dst = self.target_workspace / script
                shutil.copy(src, dst)
                os.chmod(dst, 0o755)

        # Copy xauthority directory
        xauth_src = config_src / "xauthority"
        if xauth_src.exists():
            xauth_dst = self.target_workspace / "xauthority"
            if xauth_dst.exists():
                shutil.rmtree(xauth_dst)
            shutil.copytree(xauth_src, xauth_dst)
            # Make scripts executable
            for script in xauth_dst.glob("*.sh"):
                os.chmod(script, 0o755)

        log_ok("Docker configuration restored")

    def _setup_udev(self) -> None:
        """Setup udev rules (requires sudo)."""
        log_step("Setting up udev rules...")

        install_script = self.target_workspace / "install_host_udev_rules.sh"
        if not install_script.exists():
            self.warnings.append("udev install script not found - skipping")
            log_warn("udev install script not found")
            return

        log_info("udev rule installation requires sudo")
        log_info("The rule sets MODE:=\"0666\" for USB/serial/video devices")
        log_info("This makes these devices world-readable/writable on the host")

        if self.interactive:
            response = input("Run sudo to install udev rules? [y/N] ")
            if response.lower() != "y":
                self.manual_actions.append(
                    f"Install udev rules: sudo {install_script}"
                )
                log_warn("Skipping udev setup - add to manual actions")
                return

        try:
            result = subprocess.run(
                ["sudo", str(install_script)],
                cwd=self.target_workspace,
                timeout=60,
            )
            if result.returncode == 0:
                log_ok("udev rules installed")
                self.verifications.append(VerificationResult(
                    name="udev_installed",
                    passed=True,
                    status="ok",
                    message="udev rules installed",
                ))
            else:
                self.warnings.append("udev installation returned non-zero")
                log_warn("udev installation may have failed")
        except subprocess.TimeoutExpired:
            self.warnings.append("udev installation timed out")
            log_warn("udev installation timed out")

    def _setup_xauthority(self) -> None:
        """Setup Xauthority sync."""
        log_step("Setting up Xauthority sync...")

        install_script = self.target_workspace / "install_user_xauthority_sync.sh"
        if not install_script.exists():
            self.warnings.append("Xauthority install script not found")
            log_warn("Xauthority install script not found")
            return

        try:
            result = subprocess.run(
                [str(install_script)],
                cwd=self.target_workspace,
                timeout=30,
            )
            if result.returncode == 0:
                log_ok("Xauthority sync configured")
            else:
                self.warnings.append("Xauthority setup may have failed")
                log_warn("Xauthority setup returned non-zero")
        except subprocess.TimeoutExpired:
            self.warnings.append("Xauthority setup timed out")
            log_warn("Xauthority setup timed out")

    def _regenerate_config(self) -> None:
        """Regenerate host-specific configuration."""
        log_step("Regenerating host-specific configuration...")

        docker_dir = self.target_workspace / "docker"
        config_script = docker_dir / "config.sh"

        if not config_script.exists():
            self.warnings.append("config.sh not found - cannot regenerate .env")
            log_warn("config.sh not found")
            return

        log_info("Running config.sh to regenerate .env and docker-compose.override.yml")
        log_info(f"This will detect: UID={os.getuid()}, GID={os.getgid()}, DISPLAY={os.environ.get('DISPLAY', 'not set')}")

        try:
            result = subprocess.run(
                ["bash", str(config_script)],
                cwd=docker_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                log_ok("Configuration regenerated")

                # Verify files were created
                env_file = docker_dir / ".env"
                override_file = docker_dir / "docker-compose.override.yml"

                if env_file.exists() and override_file.exists():
                    self.verifications.append(VerificationResult(
                        name="config_regenerated",
                        passed=True,
                        status="ok",
                        message=".env and override regenerated",
                    ))
                else:
                    self.warnings.append("config.sh ran but files not created")
                    log_warn("Generated config files not found")
            else:
                self.warnings.append(f"config.sh failed: {result.stderr}")
                log_warn(f"config.sh failed: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            self.warnings.append("config.sh timed out")
            log_warn("config.sh timed out")

    def _handle_ros_domain_id(self) -> None:
        """Handle ROS domain ID configuration."""
        original_id = self.manifest.get("ros_domain_id")

        if original_id is None:
            return

        log_info(f"Original ROS_DOMAIN_ID: {original_id}")

        if self.ros_domain_id is not None:
            # Use specified ID
            new_id = self.ros_domain_id
        elif self.interactive:
            log_info("On the same LAN, using the same domain ID as User A")
            log_info("could cause ROS graph cross-talk")
            response = input(f"Keep ROS_DOMAIN_ID={original_id}? [Y/n/number] ")

            if response.lower() == "n":
                new_id = (original_id + 1) % 233  # Use next ID
                log_info(f"Changed to ROS_DOMAIN_ID={new_id}")
            elif response.isdigit():
                new_id = int(response)
            else:
                new_id = original_id
        else:
            new_id = original_id

        # Update env.sh if needed
        if new_id != original_id:
            env_sh = self.target_workspace / "docker" / "env.sh"
            if env_sh.exists():
                content = env_sh.read_text()
                content = content.replace(
                    f'ROS_DOMAIN_ID="{original_id}"',
                    f'ROS_DOMAIN_ID="{new_id}"'
                )
                content = content.replace(
                    f'ROS_DOMAIN_ID={original_id}',
                    f'ROS_DOMAIN_ID={new_id}'
                )
                env_sh.write_text(content)
                log_ok(f"ROS_DOMAIN_ID updated to {new_id}")

    def _restore_dependencies(self) -> None:
        """Start container and restore dependencies."""
        log_step("Starting container and restoring dependencies...")

        docker_dir = self.target_workspace / "docker"

        # Check for install script
        install_script = self.target_workspace / "src" / "_container_setup" / "install_workspace_dependencies.sh"
        if not install_script.exists():
            self.errors.append(
                "Dependency restore strategy unavailable: "
                "install_workspace_dependencies.sh not found"
            )
            log_error("install_workspace_dependencies.sh not found")
            log_error("Cannot automatically restore dependencies")
            self.manual_actions.append(
                "Manually install apt packages and pip packages in the container"
            )
            return

        # Start container
        log_info("Starting container with docker compose...")
        try:
            run_docker_compose(["up", "-d"], cwd=docker_dir, timeout=120)
            log_ok("Container started")
        except DockerError as e:
            self.errors.append(f"Failed to start container: {e}")
            log_error(f"Failed to start container: {e}")
            return

        # Get container name from compose
        container_name = self.manifest.get("container_name")
        if not container_name:
            # Try to discover from compose
            try:
                result = run_docker_compose(
                    ["ps", "--format", "json"],
                    cwd=docker_dir,
                    timeout=30,
                )
                import json
                containers = json.loads(result.stdout)
                if containers:
                    container_name = containers[0].get("Name")
            except (DockerError, json.JSONDecodeError):
                pass

        if not container_name:
            self.warnings.append("Could not determine container name")
            log_warn("Could not determine container name for dependency restore")
            return

        # Run install script in container
        log_info("Running dependency installation script...")
        log_info("This may take several minutes...")

        try:
            from docker_migration_tool.utils.docker import docker_exec
            result = docker_exec(
                container_name,
                self._dependency_script_command(),
                timeout=1800,  # 30 minutes
            )
            log_ok("Dependencies restored")
            self.verifications.append(VerificationResult(
                name="dependencies_restored",
                passed=True,
                status="ok",
                message="Dependencies installed via install_workspace_dependencies.sh",
            ))
        except DockerError as e:
            self.warnings.append(f"Dependency installation had issues: {e}")
            log_warn(f"Dependency installation may have failed: {e}")

    def _dependency_script_candidates(self) -> list[str]:
        """In-container candidate paths for the dependency install script.

        The absolute path depends on the *container's* user and workspace
        layout, which differ per image, so nothing is hardcoded:

            1. the workspace src directory recorded in the bundle manifest
               (``workspace_container_target``, written at export time),
            2. ``$HOME/<workspace name>/src`` and ``$HOME/colcon_ws/src``,
            3. finally a glob over ``$HOME/*_ws/src`` inside the container.

        Returns:
            Candidate paths, most specific first (may contain shell globs,
            which are expanded by the container's shell, not by this process)
        """
        candidates: list[str] = []

        container_src = self.manifest.get("workspace_container_target")
        if container_src:
            candidates.append(f"{container_src.rstrip('/')}/{DEPENDENCY_SCRIPT_RELATIVE}")

        workspace_name = self.manifest.get("workspace_name")
        if workspace_name:
            candidates.append(
                f'"$HOME"/{workspace_name}/src/{DEPENDENCY_SCRIPT_RELATIVE}'
            )

        candidates.append(f'"$HOME"/colcon_ws/src/{DEPENDENCY_SCRIPT_RELATIVE}')
        candidates.append(f'"$HOME"/*_ws/src/{DEPENDENCY_SCRIPT_RELATIVE}')

        return candidates

    def _dependency_script_command(self) -> list[str]:
        """Build the container command that runs the dependency install script.

        Returns:
            Argument list for `docker exec` (the container's own shell resolves
            the candidates; no host shell is involved and shell=True is unused)
        """
        candidates = " ".join(self._dependency_script_candidates())
        script = (
            f"for candidate in {candidates}; do\n"
            '  if [ -f "$candidate" ]; then\n'
            '    echo "Running $candidate"\n'
            '    exec bash "$candidate"\n'
            "  fi\n"
            "done\n"
            'echo "install_workspace_dependencies.sh not found in this '
            'container" >&2\n'
            "exit 127\n"
        )
        return ["bash", "-c", script]

    def _collect_manual_actions(self) -> None:
        """Collect required manual actions."""
        # Secrets
        self.manual_actions.append(
            "Supply your own credentials - see configuration/SECRETS_REQUIRED.md"
        )

        # Network
        self.manual_actions.append(
            "Configure network interfaces for robot communication"
        )

        # Devices
        self.manual_actions.append(
            "Verify camera and serial device paths match your hardware"
        )

        # Calibration
        self.manual_actions.append(
            "Camera extrinsic calibration must be re-done for your robot cell"
        )


def restore_bundle(bundle_path: Path, target_workspace: Path | None = None,
                   ros_domain_id: int | None = None, dry_run: bool = False,
                   interactive: bool = True) -> ImportResult:
    """Restore a migration bundle.

    Args:
        bundle_path: Path to bundle
        target_workspace: Target workspace path
        ros_domain_id: ROS domain ID to use
        dry_run: If True, don't make changes
        interactive: If True, prompt for decisions

    Returns:
        ImportResult
    """
    restorer = BundleRestorer(
        bundle_path,
        target_workspace,
        ros_domain_id,
        dry_run,
        interactive,
    )
    return restorer.restore()
