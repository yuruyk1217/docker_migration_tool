"""Bundle creation module.

Creates migration bundles from inspection results.

CRITICAL DESIGN DECISION:
v1 does NOT export the snapshot image. The snapshot contains credentials
that cannot be safely removed without a rebuild. Instead, v1 exports:
- The clean parent image (Dockerfile-derived, no credentials)
- Package manifests for restoration via install_workspace_dependencies.sh
"""

import json
import os
import shutil
import tarfile
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from docker_migration_tool import __version__
from docker_migration_tool.model import (
    BundleManifest,
    ImageConfigScanResult,
    InspectionResult,
    Classification,
    LayerScanResult,
    SecurityCheckState,
    SecurityStatus,
)
from docker_migration_tool.inspect.workspace import (
    get_workspace_excludes,
    partition_large_files,
    resolve_src_archive_root,
)
from docker_migration_tool.security import (
    CONFIG_SCANNER_VERSION,
    SCANNER_VERSION,
    ImageArchiveError,
    UnsupportedImageArchiveError,
    scan_image_archive,
    scan_image_config,
    scan_image_for_secrets,
)
from docker_migration_tool.utils.docker import docker_save, DockerError
from docker_migration_tool.utils.filesystem import (
    create_archive,
    compute_sha256_file,
    ensure_directory,
)
from docker_migration_tool.utils.logging import (
    log_ok,
    log_warn,
    log_error,
    log_info,
    log_step,
    log_header,
)


class ExportBlockedError(Exception):
    """Export blocked due to security issue."""
    pass


class BundleCreator:
    """Creates migration bundles from inspection results."""

    def __init__(self, inspection: InspectionResult, output_dir: Path,
                 dry_run: bool = False):
        """Initialize bundle creator.

        Args:
            inspection: Inspection results
            output_dir: Output directory for bundle
            dry_run: If True, don't create anything
        """
        self.inspection = inspection
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.manifest = BundleManifest()
        self.checksums: dict[str, str] = {}
        self.layer_scan = LayerScanResult()
        self.config_scan = ImageConfigScanResult()
        # Per-check security state. Kept separate so that a log line can never
        # claim more than the check that actually ran (a dry run performs the
        # final-filesystem scan only).
        self.security_status = SecurityStatus()
        self.excludes = get_workspace_excludes()

    def create(self) -> Path:
        """Create the migration bundle.

        Gate order (every gate must pass or nothing is exported):

            1. inspect runtime image
            2. discover clean parent candidate
            3. verify the RootFS layer relationship        <- gate 1
            4. scan image config metadata + build history  <- gate 2
            5. scan the merged final filesystem            <- gate 3
            6. create the clean image archive (one docker save)
            7. scan ALL image layers for secret paths      <- gate 4
            8. continue the bundle export

        Gates 1-3 need no `docker save`, so a dry run performs them in full and
        a dry run is blocked by them exactly like a real export.

        Returns:
            Path to created bundle directory

        Raises:
            ExportBlockedError: If the parent relationship cannot be proven,
                credential material is found in the image config metadata or
                build history, or a credential-like path is found in the final
                filesystem or in any image layer
        """
        log_header("Creating Migration Bundle")

        # Validate inspection
        self._validate_inspection()

        # Set up manifest
        self._initialize_manifest()

        # Gate 1: prove the clean parent relationship (naming/env.sh is not proof)
        self._verify_parent_relationship()

        # Gate 2: image config metadata + build history (no files involved)
        self._scan_image_config_metadata()

        # Gate 3: security scan the clean image (final filesystem view)
        self._security_scan_image()

        if self.dry_run:
            self._dry_run_report()
            return self.output_dir

        # Create bundle directory structure
        self._create_bundle_structure()

        # Export components
        self._export_image()
        self._export_workspace()
        self._export_git_state()
        self._export_packages()
        self._export_docker_config()
        self._export_host_info()
        self._export_hardware_info()
        self._export_secrets_required()
        self._export_verification()

        # Write manifest
        self._write_manifest()

        # Write README
        self._write_readme()

        log_ok(f"Bundle created at: {self.output_dir}")

        return self.output_dir

    def _validate_inspection(self) -> None:
        """Validate inspection results."""
        if not self.inspection.container:
            raise ValueError("No container in inspection results")

        if not self.inspection.workspace_path:
            log_warn("Workspace path not found in inspection")

    def _initialize_manifest(self) -> None:
        """Initialize bundle manifest."""
        self.manifest.schema_version = "1.0.0"
        self.manifest.tool_version = __version__
        self.manifest.created_at = datetime.now().isoformat()

        if self.inspection.host:
            self.manifest.source_host = f"{self.inspection.host.os_name} {self.inspection.host.os_version}"

        if self.inspection.container:
            self.manifest.workspace_name = self.inspection.container.workspace_name
            self.manifest.container_name = self.inspection.container.name
            self.manifest.container_username = self.inspection.container.container_username
            for mount in self.inspection.container.mounts:
                if mount.is_workspace and mount.mount_type == "bind":
                    self.manifest.workspace_container_target = mount.container_target
                    break

        if self.inspection.runtime_image:
            self.manifest.source_runtime_image = (
                f"{self.inspection.runtime_image.repository}:{self.inspection.runtime_image.tag}"
            )

        if self.inspection.clean_base_image:
            self.manifest.clean_base_image = (
                f"{self.inspection.clean_base_image.repository}:{self.inspection.clean_base_image.tag}"
            )
            self.manifest.clean_base_image_id = self.inspection.clean_base_image.image_id
            self.manifest.clean_base_image_digest = self.inspection.clean_base_image.digest
            self.manifest.clean_base_image_size = self.inspection.clean_base_image.size_bytes

        # Security metadata. The defaults in BundleManifest are deliberately
        # "unverified"/"not_performed": a bundle that skipped a gate must be
        # refused on import rather than implicitly trusted.
        self.manifest.scanner_version = SCANNER_VERSION

        relationship = self.inspection.parent_relationship
        if relationship:
            self.manifest.parent_relationship_verified = relationship.verified
            self.manifest.parent_relationship_method = relationship.method
            self.manifest.runtime_layer_count = relationship.runtime_layer_count
            self.manifest.clean_image_layer_count = relationship.candidate_layer_count
        else:
            if self.inspection.runtime_image:
                self.manifest.runtime_layer_count = len(
                    self.inspection.runtime_image.rootfs_layers
                )
            if self.inspection.clean_base_image:
                self.manifest.clean_image_layer_count = len(
                    self.inspection.clean_base_image.rootfs_layers
                )

        if self.inspection.packages:
            self.manifest.ros_distro = self.inspection.packages.ros_distro

        # ROS domain ID from env
        if self.inspection.container and self.inspection.container.env_vars:
            domain_id = self.inspection.container.env_vars.get("ROS_DOMAIN_ID")
            if domain_id and domain_id != "[REDACTED]":
                try:
                    self.manifest.ros_domain_id = int(domain_id)
                except ValueError:
                    pass

    def _verify_parent_relationship(self) -> None:
        """Gate 1: require a proven RootFS layer relationship.

        Candidate discovery (env.sh, tag naming, docker history) is never
        accepted on its own. Only an exact RootFS layer chain prefix - or an
        identical chain when the runtime image is already clean - allows the
        export to continue.

        Raises:
            ExportBlockedError: If the relationship is unproven
        """
        log_step("Verifying clean parent image layer relationship...")

        relationship = self.inspection.parent_relationship

        if self.inspection.clean_base_image and relationship and relationship.verified:
            log_ok(
                f"Layer relationship proven ({relationship.relationship}): "
                f"{relationship.candidate_layer_count}/"
                f"{relationship.runtime_layer_count} layers"
            )
            log_info(f"  Runtime image:   {relationship.runtime_image}")
            log_info(f"  Clean candidate: {relationship.candidate_image}")
            log_info(f"  Discovered via:  {relationship.candidate_source}")
            return

        # Blocked. Report identities and layer counts only - never secrets.
        log_error("EXPORT BLOCKED: Unable to prove clean parent image relationship")
        if relationship:
            log_error(f"  Runtime image:        {relationship.runtime_image}")
            log_error(f"  Candidate image:      {relationship.candidate_image}")
            log_error(f"  Runtime layer count:  {relationship.runtime_layer_count}")
            log_error(f"  Candidate layer count: {relationship.candidate_layer_count}")
            log_error(f"  Relationship:         {relationship.relationship}")
            if relationship.reason:
                log_error(f"  Reason:               {relationship.reason}")

        raise ExportBlockedError(
            "Unable to prove clean parent image relationship. The candidate "
            "image's RootFS layer chain is not a prefix of the runtime image's "
            "chain, so it cannot be shown to be the credential-free parent. "
            "The snapshot image is never exported. Either:\n"
            "  1. Identify the clean Dockerfile-built parent image\n"
            "  2. Rebuild the image from Dockerfile without credentials"
        )

    def _scan_image_config_metadata(self) -> None:
        """Gate 2: refuse images whose config metadata carries credentials.

        `docker save` ships the image config and the build history, so a token
        baked in with `ENV OPENAI_API_KEY=...` or an `ARG GITHUB_TOKEN=...`
        travels with the image even when every layer path is clean. The path
        scans (gates 3 and 4) cannot see that, so this is a separate check.

        Scanned: Config.Env, ContainerConfig.Env (when the daemon reports it),
        Config.Cmd, Config.Entrypoint, Config.Labels and every
        `docker image history --no-trunc` CreatedBy command.

        Environment variable VALUES are never logged, recorded in the bundle or
        included in the error message: a value-side detection is reported as
        `matched: true` with kind `possible_credential_value` only.

        Raises:
            ExportBlockedError: On any finding, or when the config/history
                cannot be read (an unscanned config is never treated as safe)
        """
        log_step("Scanning clean image config metadata and build history...")

        clean_image = (
            f"{self.inspection.clean_base_image.repository}:"
            f"{self.inspection.clean_base_image.tag}"
        )
        self.config_scan = scan_image_config(clean_image)
        self._record_config_scan()

        if self.config_scan.result == "error":
            log_error(
                "EXPORT BLOCKED: image config metadata could not be scanned"
            )
            log_error(f"  {self.config_scan.message}")
            raise ExportBlockedError(
                "EXPORT BLOCKED: the clean image's config metadata / build "
                f"history could not be read ({self.config_scan.message}). "
                "An unscanned image config is never treated as safe."
            )

        if not self.config_scan.passed:
            log_error(
                "EXPORT BLOCKED: credential-like material in image config "
                "metadata"
            )
            for finding in self.config_scan.findings:
                self._log_config_finding(finding)
            log_error("  (values are never displayed, logged or recorded)")
            raise ExportBlockedError(
                f"EXPORT BLOCKED: {len(self.config_scan.findings)} "
                "credential-like item(s) in the config metadata / build history "
                f"of {clean_image}. `docker save` ships the image config, so "
                "this material would be handed to the other person even though "
                "no credential file exists in any layer. The image must be "
                "rebuilt without baking credentials into ENV/ARG/RUN."
            )

        log_ok("Image config/history credential scan passed")
        log_info(
            "  Scope: Config.Env"
            + (", ContainerConfig.Env" if self.config_scan.container_config_present
               else "")
            + ", Cmd, Entrypoint, Labels, history CreatedBy"
        )
        log_info(
            f"  Env vars scanned: {self.config_scan.env_vars_scanned}, "
            f"labels: {self.config_scan.labels_scanned}, "
            f"history entries: {self.config_scan.history_entries_scanned}"
        )
        log_info("  Values are never read into the report (key names only)")
        if self.config_scan.allowlisted_keys:
            log_info(
                "  Name matched the secret vocabulary but allowlisted as "
                "non-credential (values checked, no match): "
                + ", ".join(self.config_scan.allowlisted_keys)
            )

    @staticmethod
    def _log_config_finding(finding) -> None:
        """Log one config finding: identity only, never a value."""
        log_error(f"  source: {finding.source}")
        if finding.key:
            log_error(f"    key:  {finding.key}")
        log_error(f"    kind: {finding.kind}")
        if finding.matched_pattern:
            log_error(f"    matched_pattern: {finding.matched_pattern}")
        if finding.location:
            log_error(f"    location: {finding.location}")
        if finding.kind == "possible_credential_value":
            log_error("    matched: true (value not shown)")

    def _record_config_scan(self) -> None:
        """Copy the config scan verdict into the manifest and internal status."""
        self.manifest.image_config_scan = self.config_scan.performed
        self.manifest.image_config_scan_result = self.config_scan.result
        self.manifest.config_scanner_version = (
            self.config_scan.scanner_version or CONFIG_SCANNER_VERSION
        )
        self.security_status.config_metadata_scan = self.config_scan.result

    def _security_scan_image(self) -> None:
        """Gate 3: scan the clean image's final filesystem for credential paths.

        This is one of three image security checks. It observes the merged
        final filesystem, which is exactly the view a whiteout hides, so its
        success is reported with that scope named explicitly - never as a
        blanket "clean image passed security scan". The full image-layer scan
        (gate 4) runs later, in _export_image(), and only on a real export.

        Raises:
            ExportBlockedError: If secrets found
        """
        log_step("Security scanning clean parent image...")

        clean_image = f"{self.inspection.clean_base_image.repository}:{self.inspection.clean_base_image.tag}"
        secrets = scan_image_for_secrets(clean_image)

        if secrets:
            self.security_status.final_filesystem_scan = (
                SecurityCheckState.FAILED.value
            )
            self._record_final_filesystem_scan()
            log_error("EXPORT BLOCKED: Secrets detected in clean image")
            for secret in secrets:
                log_error(f"  {secret.kind}: {secret.path}")

            raise ExportBlockedError(
                f"Secrets detected in clean image ({len(secrets)} found). "
                "Cannot export image with credentials. "
                "The image must be rebuilt from Dockerfile without credentials."
            )

        self.security_status.final_filesystem_scan = SecurityCheckState.PASSED.value
        self._record_final_filesystem_scan()
        log_ok("Final-filesystem secret path scan passed")
        log_info("  Scope: merged final filesystem of the clean image only")
        log_info("  Full image-layer secret scan is a separate check")

    def _record_final_filesystem_scan(self) -> None:
        """Copy the final-filesystem verdict into the manifest.

        Recorded for transparency only. The import gate deliberately keys off
        layer_secret_scan_result: a passing final-filesystem scan is not
        evidence that the layers are clean.
        """
        self.manifest.final_filesystem_scan_result = (
            self.security_status.final_filesystem_scan
        )

    def _dry_run_report(self) -> None:
        """Report what would be done in dry run.

        A dry run never runs `docker save`: multi-GB archives are not written
        and therefore the full layer secret scan cannot run either. This is
        stated explicitly so that a successful dry run is not mistaken for
        proof that the export is safe.
        """
        log_header("Dry Run Report")

        log_info("Would create bundle at: " + str(self.output_dir))

        # Image
        if self.inspection.clean_base_image:
            log_info(f"Would export clean image: {self.inspection.clean_base_image.repository}:{self.inspection.clean_base_image.tag}")
            log_info(f"  Estimated size: {self.inspection.clean_base_image.size_bytes / (1024**3):.1f} GB")

        if self.inspection.runtime_image:
            log_warn(f"Would NOT export snapshot: {self.inspection.runtime_image.repository}:{self.inspection.runtime_image.tag}")
            log_info("  Reason: Contains credentials that cannot be safely removed")

        # Layer relationship (already verified above - dry run reaches this
        # point only when the relationship is proven)
        relationship = self.inspection.parent_relationship
        if relationship:
            log_info("Clean parent layer relationship:")
            log_info(f"  Runtime image:            {relationship.runtime_image}")
            log_info(f"  Candidate clean image:    {relationship.candidate_image}")
            log_info(f"  Discovered via:           {relationship.candidate_source}")
            log_info(f"  Verification method:      {relationship.method}")
            log_info(f"  Relationship:             {relationship.relationship}")
            log_info(f"  Verified:                 {relationship.verified}")
            log_info(f"  Runtime layer count:      {relationship.runtime_layer_count}")
            log_info(f"  Clean image layer count:  {relationship.candidate_layer_count}")
            log_info(
                f"  Expected exported layers: {relationship.candidate_layer_count} "
                f"(of {relationship.runtime_layer_count} runtime layers)"
            )
            if relationship.rejected_candidates:
                log_info(
                    f"  Rejected candidates:      {len(relationship.rejected_candidates)}"
                )
                for rejected in relationship.rejected_candidates[:5]:
                    log_info(
                        f"    - {rejected['image']} "
                        f"({rejected['layer_count']} layers, {rejected['relationship']})"
                    )

        # Security checks: report each scope separately. The config metadata and
        # final-filesystem scans really ran; the layer scan needs an archive.
        self.security_status.layer_scan = SecurityCheckState.SKIPPED_DRY_RUN.value
        log_info("Security check status:")
        log_info(
            f"  config_metadata_scan:  {self.security_status.config_metadata_scan}"
        )
        log_info(
            f"  final_filesystem_scan: {self.security_status.final_filesystem_scan}"
        )
        log_info(f"  layer_scan:            {self.security_status.layer_scan}")
        log_info("Image config/history credential scan (performed in dry-run):")
        log_info(f"  Config scanner version: {CONFIG_SCANNER_VERSION}")
        log_info(
            "  Scope: Config.Env"
            + (", ContainerConfig.Env" if self.config_scan.container_config_present
               else " (ContainerConfig.Env not reported by this daemon)")
            + ", Cmd, Entrypoint, Labels, history CreatedBy"
        )
        log_info(
            f"  Env vars scanned: {self.config_scan.env_vars_scanned}, "
            f"labels: {self.config_scan.labels_scanned}, "
            f"history entries: {self.config_scan.history_entries_scanned}"
        )
        log_info("  Policy: credential-like env key or value -> EXPORT BLOCKED")
        log_info("          (env values are never logged or recorded)")
        log_info("Full image-layer secret scan planned for the real export:")
        log_info(f"  Scanner version: {SCANNER_VERSION}")
        log_info("  Scope: every layer archive inside docker save output")
        log_info("  Policy: secret-like path in ANY layer -> EXPORT BLOCKED")
        log_info("          (whiteout deletions do not make a layer safe)")
        log_warn("[SKIP] Full image-layer secret scan not performed in dry-run")
        log_info("  A dry run does not docker-save the multi-GB image.")
        log_warn("Export safety is NOT fully verified in dry-run")
        log_info("  dry-run success != export safety verified")

        # Workspace: the archive source is the authoritative src bind mount,
        # never the workspace root (portable config is a separate collector).
        src_root = self._resolve_src_archive_root()
        if src_root:
            log_info(f"Would archive workspace src: {src_root}")
            if self.inspection.workspace_path:
                log_info(f"  Workspace root (NOT archived): {self.inspection.workspace_path}")
            log_info("  Portable Docker config is collected separately into docker/config/")
        elif self.inspection.workspace_path:
            log_warn(
                f"No src directory found under workspace: {self.inspection.workspace_path}"
            )

        # Mounts and volumes
        bind_mounts = [m for m in self.inspection.mounts if m.mount_type == "bind"]
        volume_mounts = [m for m in self.inspection.mounts if m.mount_type == "volume"]
        log_info(f"Bind mounts detected: {len(bind_mounts)}")
        for mount in bind_mounts:
            marker = " [workspace src]" if mount.is_workspace else ""
            log_info(
                f"  - {mount.host_source} -> {mount.container_target} "
                f"({mount.mode}){marker}"
            )
        named_volumes = len(volume_mounts) + len(self.inspection.volumes)
        log_info(f"Named volumes: {named_volumes if named_volumes else 'none'}")

        # Excludes: printed from the same policy the archive uses
        log_info("Would exclude (workspace src exclusion policy):")
        for pattern in self.excludes:
            log_info(f"  - {pattern}")

        # Large files: the exclusion policy is applied before the large-file
        # list is reported, so an excluded file can never appear as "include".
        included, excluded = partition_large_files(
            self.inspection.large_files, self.excludes
        )
        if included:
            log_info("Large files to include:")
            for lf in included[:5]:
                log_info(f"  - {lf.path} ({lf.size_bytes / (1024**2):.1f} MB)")

        audit_excluded = list(self.inspection.excluded_large_files) + excluded
        if audit_excluded:
            log_info("Large files EXCLUDED by policy (not archived, not checksummed):")
            for ex in audit_excluded[:5]:
                log_info(
                    f"  - {ex.path} ({ex.size_bytes / (1024**2):.1f} MB) "
                    f"excluded_by: {ex.excluded_by}"
                )

        # Secrets
        if self.inspection.secrets:
            log_info("Secrets to EXCLUDE:")
            for s in self.inspection.secrets:
                log_info(f"  - {s.kind}: {s.path}")

        # Sudo required
        log_info("\nSudo will be required on import for:")
        log_info("  - udev rule installation")

    def _create_bundle_structure(self) -> None:
        """Create bundle directory structure."""
        log_step("Creating bundle directory structure...")

        dirs = [
            self.output_dir,
            self.output_dir / "docker" / "image",
            self.output_dir / "docker" / "config",
            self.output_dir / "workspace",
            self.output_dir / "git",
            self.output_dir / "packages",
            self.output_dir / "host",
            self.output_dir / "hardware",
            self.output_dir / "configuration",
            self.output_dir / "verification",
        ]

        for d in dirs:
            ensure_directory(d)

        self.manifest.components = [
            "docker/image",
            "docker/config",
            "workspace",
            "git",
            "packages",
            "host",
            "hardware",
            "configuration",
            "verification",
        ]

    def _export_image(self) -> None:
        """Export the clean parent image and scan every layer of the archive.

        The image is saved exactly once: the same artifact that is scanned is
        the one adopted as the bundle image (no save -> scan -> delete -> save
        again cycle). If the scan fails the archive is removed, because it may
        contain credential bytes.

        Raises:
            ExportBlockedError: Credential path in any layer, or an archive
                format this scanner does not understand
        """
        log_step("Exporting clean parent image...")

        clean_image = f"{self.inspection.clean_base_image.repository}:{self.inspection.clean_base_image.tag}"
        image_path = self.output_dir / "docker" / "image" / "base-image.tar"

        try:
            docker_save(clean_image, image_path)
            log_ok(f"Image saved: {image_path.name}")
        except DockerError as e:
            log_error(f"Failed to export image: {e}")
            raise

        # Gate 4: full layer secret scan of the archive we just wrote
        self._scan_image_layers(image_path)

        # Checksum the adopted artifact (unchanged since the scan)
        sha256 = compute_sha256_file(image_path)
        self.checksums["docker/image/base-image.tar"] = sha256
        self.manifest.checksums["docker/image/base-image.tar"] = sha256

        # Write image info
        image_info = {
            "schema_version": "1.0.0",
            "repository": self.inspection.clean_base_image.repository,
            "tag": self.inspection.clean_base_image.tag,
            "image_id": self.inspection.clean_base_image.image_id,
            "digest": self.inspection.clean_base_image.digest,
            "size_bytes": self.inspection.clean_base_image.size_bytes,
            "layer_count": self.inspection.clean_base_image.layer_count,
            "is_clean_parent": True,
            "is_snapshot": False,
            "note": "This is the clean Dockerfile-built image, not the snapshot with credentials",
            # Security metadata (mirrors MANIFEST.json; import checks both)
            "parent_relationship_verified": self.manifest.parent_relationship_verified,
            "parent_relationship_method": self.manifest.parent_relationship_method,
            "runtime_layer_count": self.manifest.runtime_layer_count,
            "clean_image_layer_count": self.manifest.clean_image_layer_count,
            "layer_secret_scan": self.manifest.layer_secret_scan,
            "layer_secret_scan_result": self.manifest.layer_secret_scan_result,
            "final_filesystem_scan_result": self.manifest.final_filesystem_scan_result,
            "image_config_scan": self.manifest.image_config_scan,
            "image_config_scan_result": self.manifest.image_config_scan_result,
            "config_scanner_version": self.manifest.config_scanner_version,
            "config_env_vars_scanned": self.config_scan.env_vars_scanned,
            "config_history_entries_scanned": self.config_scan.history_entries_scanned,
            "scanner_version": self.manifest.scanner_version,
            "archive_format": self.layer_scan.archive_format,
            "layers_scanned": self.layer_scan.layers_scanned,
        }

        info_path = self.output_dir / "docker" / "image" / "IMAGE_INFO.json"
        with open(info_path, "w") as f:
            json.dump(image_info, f, indent=2)

    def _scan_image_layers(self, image_path: Path) -> None:
        """Scan every layer of the saved image archive for credential paths.

        Policy: a credential-like path in ANY layer blocks the export. A later
        whiteout is never accepted as mitigation - `docker save` still ships the
        lower layer blob that holds the bytes.

        Only the layer id, path and secret kind are ever recorded or logged;
        file contents are never read.

        Args:
            image_path: The `docker save` archive to scan

        Raises:
            ExportBlockedError: On findings or an unsupported archive format
        """
        log_step("Scanning all image layers for secret paths...")

        try:
            self.layer_scan = scan_image_archive(image_path)
        except UnsupportedImageArchiveError as e:
            self.layer_scan = LayerScanResult(
                performed=True,
                result="unsupported_format",
                scanner_version=SCANNER_VERSION,
                message=str(e),
            )
            self._record_layer_scan()
            self._discard_unsafe_archive(image_path)
            log_error(f"EXPORT BLOCKED: unsupported image archive format ({e})")
            raise ExportBlockedError(
                f"EXPORT BLOCKED: unsupported image archive format ({e}). "
                "An unscanned image archive is never treated as safe."
            ) from e
        except (ImageArchiveError, tarfile.TarError, OSError) as e:
            self.layer_scan = LayerScanResult(
                performed=True,
                result="failed",
                scanner_version=SCANNER_VERSION,
                message=f"image archive could not be scanned: {e}",
            )
            self._record_layer_scan()
            self._discard_unsafe_archive(image_path)
            log_error(f"EXPORT BLOCKED: image archive could not be scanned ({e})")
            raise ExportBlockedError(
                f"EXPORT BLOCKED: image archive could not be scanned ({e})."
            ) from e

        self._record_layer_scan()

        for anomaly in self.layer_scan.anomalies:
            log_warn(f"  layer anomaly: {anomaly}")

        if not self.layer_scan.passed:
            log_error("EXPORT BLOCKED: secret path found in image layers")
            for finding in self.layer_scan.findings:
                suffix = " (whiteout marker; lower layer still ships the file)" \
                    if finding.whiteout else ""
                log_error(
                    f"  layer: {finding.layer}\n"
                    f"    path: {finding.path}\n"
                    f"    kind: {finding.kind}{suffix}"
                )

            self._discard_unsafe_archive(image_path)

            raise ExportBlockedError(
                f"EXPORT BLOCKED: {len(self.layer_scan.findings)} credential-like "
                f"path(s) found in the image layers of "
                f"{self.manifest.clean_base_image}. A later whiteout does not "
                "make the image safe: docker save still ships the lower layer "
                "that contains the file. The image must be rebuilt from the "
                "Dockerfile without credentials."
            )

        self.security_status.layer_scan = SecurityCheckState.PASSED.value
        log_ok(
            f"Full image-layer secret scan passed: "
            f"{self.layer_scan.layers_scanned} layer(s), "
            f"{self.layer_scan.entries_scanned} entries, "
            f"format={self.layer_scan.archive_format}"
        )

        # Only now - with the config metadata scan, the final-filesystem scan
        # and the full layer scan all passed - may a blanket success be reported.
        if self.security_status.all_required_checks_passed:
            log_ok("Clean image passed all required security checks")
            log_info(
                f"  config_metadata_scan:  {self.security_status.config_metadata_scan}"
            )
            log_info(
                f"  final_filesystem_scan: {self.security_status.final_filesystem_scan}"
            )
            log_info(f"  layer_scan:            {self.security_status.layer_scan}")

    def _record_layer_scan(self) -> None:
        """Copy the layer scan verdict into the manifest and internal status."""
        self.manifest.layer_secret_scan = self.layer_scan.performed
        self.manifest.layer_secret_scan_result = self.layer_scan.result
        self.manifest.scanner_version = (
            self.layer_scan.scanner_version or SCANNER_VERSION
        )
        # Keep the internal status in step with the recorded verdict so a log
        # line can never claim a state the metadata contradicts.
        self.security_status.layer_scan = self.layer_scan.result

    @staticmethod
    def _discard_unsafe_archive(image_path: Path) -> None:
        """Remove an image archive that failed (or could not complete) the scan.

        The archive may contain credential bytes, so it must not be left behind
        in a bundle directory that a user might ship.
        """
        try:
            image_path.unlink()
        except OSError:
            log_warn(f"Could not remove unsafe image archive: {image_path}")

    def _resolve_src_archive_root(self) -> Path | None:
        """Resolve the directory that becomes workspace/src.tar.zst.

        Used by both the real archive and the dry-run report so the reported
        source and the archived source cannot diverge. The authoritative source
        is the detected workspace bind mount (the host side of the container's
        colcon `src`); the workspace root itself is never archived.
        """
        if self.inspection.workspace_src_path:
            candidate = Path(self.inspection.workspace_src_path)
            if candidate.exists():
                return candidate

        bind_mount = None
        for mount in self.inspection.mounts:
            if mount.is_workspace and mount.mount_type == "bind":
                bind_mount = Path(mount.host_source)
                break

        workspace_path = (
            Path(self.inspection.workspace_path)
            if self.inspection.workspace_path else None
        )
        return resolve_src_archive_root(workspace_path, bind_mount)

    def _export_workspace(self) -> None:
        """Export the authoritative workspace `src` archive.

        Only `src` is archived. Dockerfile, docker-compose.yml, env.sh,
        common.sh, config.sh, udev rules and the xauthority scripts are
        collected by _export_docker_config() into docker/config/, so they are
        stored exactly once.
        """
        src_path = self._resolve_src_archive_root()
        if src_path is None:
            log_warn("No workspace src directory to export")
            return

        log_step("Archiving workspace src...")
        log_info(f"  Archive source: {src_path}")

        archive_path = self.output_dir / "workspace" / "src.tar.zst"

        # Exclusion policy comes from the single source of truth, so the archive
        # drops exactly what the dry-run report said it would.
        excludes = self.excludes

        create_archive(src_path, archive_path, excludes=excludes)
        log_ok(f"Workspace archived: {archive_path.name}")

        # Compute checksum
        sha256 = compute_sha256_file(archive_path)
        self.checksums["workspace/src.tar.zst"] = sha256
        self.manifest.checksums["workspace/src.tar.zst"] = sha256

        # Write excluded files list
        excluded_path = self.output_dir / "workspace" / "EXCLUDED.txt"
        with open(excluded_path, "w") as f:
            f.write("# Files excluded from workspace archive\n")
            f.write("# These are either regenerable or should not be migrated\n")
            f.write(f"# Archive source: {src_path}\n\n")
            for exclude in excludes:
                f.write(f"{exclude}\n")

        # Write large files manifest. The policy is re-applied here so an
        # excluded file (e.g. a core dump) can never be recorded as included.
        included, excluded_large = partition_large_files(
            self.inspection.large_files, excludes
        )
        for ex in excluded_large:
            log_info(f"  Large file excluded by policy: {ex.path} ({ex.excluded_by})")

        if included:
            large_files = []
            for lf in included:
                large_files.append({
                    "path": lf.path,
                    "size_bytes": lf.size_bytes,
                    "sha256": lf.sha256,
                    "is_gitignored": lf.is_gitignored,
                })
            lf_path = self.output_dir / "workspace" / "LARGE_FILES.json"
            with open(lf_path, "w") as f:
                json.dump(large_files, f, indent=2)

        # Audit record for large files the policy dropped (paths and sizes only)
        audit = list(self.inspection.excluded_large_files) + excluded_large
        if audit:
            audit_path = self.output_dir / "workspace" / "EXCLUDED_LARGE_FILES.json"
            with open(audit_path, "w") as f:
                json.dump(
                    [
                        {
                            "path": ex.path,
                            "size_bytes": ex.size_bytes,
                            "excluded_by": ex.excluded_by,
                        }
                        for ex in audit
                    ],
                    f,
                    indent=2,
                )

    def _export_git_state(self) -> None:
        """Export git repository state."""
        log_step("Exporting git state...")

        repos = []
        for repo in self.inspection.git_repos:
            repo_data = {
                "path": repo.path,
                "remote_url": repo.remote_url,  # Preserve exactly, no re-encoding
                "branch": repo.branch,
                "head_commit": repo.head_commit,
                "upstream": repo.upstream,
                "ahead": repo.ahead,
                "behind": repo.behind,
                "is_dirty": repo.is_dirty,
                "modified_files": repo.modified_files,
                "untracked_files": repo.untracked_files,
                "submodules": [
                    {
                        "path": sub.path,
                        "remote_url": sub.remote_url,
                        "head_commit": sub.head_commit,
                        "is_dirty": sub.is_dirty,
                    }
                    for sub in repo.submodules
                ],
            }
            repos.append(repo_data)

        repos_path = self.output_dir / "git" / "repos.json"
        with open(repos_path, "w") as f:
            json.dump({"schema_version": "1.0.0", "repositories": repos}, f, indent=2)

        # Warn about dirty state
        dirty_count = sum(1 for r in self.inspection.git_repos if r.is_dirty)
        untracked_count = sum(len(r.untracked_files) for r in self.inspection.git_repos)

        if dirty_count > 0:
            log_warn(f"{dirty_count} repositories have uncommitted changes")
        if untracked_count > 0:
            log_warn(f"{untracked_count} untracked files found")

        log_ok(f"Git state for {len(repos)} repositories saved")

    def _export_packages(self) -> None:
        """Export package manifests."""
        log_step("Exporting package manifests...")

        if not self.inspection.packages:
            log_warn("No package information to export")
            return

        packages_dir = self.output_dir / "packages"

        # apt manual packages
        apt_manual_path = packages_dir / "apt_manual.txt"
        with open(apt_manual_path, "w") as f:
            f.write("# Manually installed apt packages\n")
            for pkg in self.inspection.packages.apt_manual:
                f.write(f"{pkg}\n")

        # apt versions
        apt_versions_path = packages_dir / "apt_versions.txt"
        with open(apt_versions_path, "w") as f:
            f.write("# Apt package versions\n")
            for pkg, ver in sorted(self.inspection.packages.apt_versions.items()):
                f.write(f"{pkg}={ver}\n")

        # pip freeze
        pip_freeze_path = packages_dir / "pip_freeze.txt"
        with open(pip_freeze_path, "w") as f:
            f.write("# pip freeze --user output\n")
            for pkg in self.inspection.packages.pip_freeze:
                f.write(f"{pkg}\n")

        # Metadata
        meta_path = packages_dir / "packages_meta.json"
        with open(meta_path, "w") as f:
            json.dump({
                "schema_version": "1.0.0",
                "python_version": self.inspection.packages.python_version,
                "ros_distro": self.inspection.packages.ros_distro,
                "has_install_script": self.inspection.packages.has_install_script,
                "install_script_path": self.inspection.packages.install_script_path,
            }, f, indent=2)

        # Copy INSTALLED_DEPENDENCIES.md if exists
        if self.inspection.workspace_path:
            deps_md = Path(self.inspection.workspace_path) / "src" / "_container_setup" / "INSTALLED_DEPENDENCIES.md"
            if deps_md.exists():
                shutil.copy(deps_md, packages_dir / "INSTALLED_DEPENDENCIES.md")

        log_ok("Package manifests saved")

    def _export_docker_config(self) -> None:
        """Export portable Docker configuration."""
        log_step("Exporting Docker configuration...")

        if not self.inspection.docker_config:
            log_warn("No Docker configuration to export")
            return

        config_dir = self.output_dir / "docker" / "config"

        # Copy portable files only
        portable_attrs = [
            ("dockerfile_path", "Dockerfile"),
            ("compose_yml_path", "docker-compose.yml"),
            ("env_sh_path", "env.sh"),
            ("common_sh_path", "common.sh"),
            ("config_sh_path", "config.sh"),
            ("dockerignore_path", ".dockerignore"),
        ]

        for attr, filename in portable_attrs:
            src_path = getattr(self.inspection.docker_config, attr)
            if src_path and Path(src_path).exists():
                shutil.copy(src_path, config_dir / filename)

        # Copy udev rules
        if self.inspection.docker_config.udev_rules_path:
            udev_dir = config_dir / "udev"
            ensure_directory(udev_dir)
            shutil.copy(
                self.inspection.docker_config.udev_rules_path,
                udev_dir / "99-robotics-docker.rules"
            )

        # Copy install scripts
        if self.inspection.docker_config.udev_install_script:
            shutil.copy(
                self.inspection.docker_config.udev_install_script,
                config_dir / "install_host_udev_rules.sh"
            )

        if self.inspection.docker_config.xauthority_install_script:
            shutil.copy(
                self.inspection.docker_config.xauthority_install_script,
                config_dir / "install_user_xauthority_sync.sh"
            )

        # Copy xauthority scripts
        if self.inspection.docker_config.xauthority_sync_script:
            xauth_dir = config_dir / "xauthority"
            ensure_directory(xauth_dir)
            shutil.copy(
                self.inspection.docker_config.xauthority_sync_script,
                xauth_dir / "sync-robotics-xauthority.sh"
            )

        if self.inspection.docker_config.xauthority_desktop_template:
            xauth_dir = config_dir / "xauthority"
            ensure_directory(xauth_dir)
            shutil.copy(
                self.inspection.docker_config.xauthority_desktop_template,
                xauth_dir / "robotics-docker-xauthority.desktop.in"
            )

        # Write note about generated files
        note_path = config_dir / "GENERATED_FILES_NOTE.txt"
        with open(note_path, "w") as f:
            f.write("# IMPORTANT: Generated Files Not Included\n\n")
            f.write("The following files are NOT included in this bundle:\n")
            f.write("  - .env\n")
            f.write("  - docker-compose.override.yml\n")
            f.write("  - compose.generated.yml\n")
            f.write("  - .docker.xauth\n")
            f.write("  - robotics-xauthority\n\n")
            f.write("These files are host-specific and must be regenerated on\n")
            f.write("User B's machine by running config.sh\n")

        log_ok("Docker configuration saved")

    def _export_host_info(self) -> None:
        """Export host information."""
        log_step("Exporting host information...")

        if not self.inspection.host:
            log_warn("No host information to export")
            return

        host_info = {
            "schema_version": "1.0.0",
            "note": "For compatibility comparison only, not for direct application",
            "os_name": self.inspection.host.os_name,
            "os_version": self.inspection.host.os_version,
            "kernel": self.inspection.host.kernel,
            "architecture": self.inspection.host.architecture,
            "cpu": self.inspection.host.cpu,
            "ram_gb": self.inspection.host.ram_gb,
            "docker_version": self.inspection.host.docker_version,
            "compose_version": self.inspection.host.compose_version,
            "gpu_model": self.inspection.host.gpu_model,
            "nvidia_driver": self.inspection.host.nvidia_driver,
            "nvidia_toolkit": self.inspection.host.nvidia_toolkit,
            "uid": self.inspection.host.uid,
            "gid": self.inspection.host.gid,
            "groups": self.inspection.host.groups,
            "disk_free_gb": self.inspection.host.disk_free_gb,
            "display": self.inspection.host.display,
        }

        host_path = self.output_dir / "host" / "host_info.json"
        with open(host_path, "w") as f:
            json.dump(host_info, f, indent=2)

        log_ok("Host information saved")

    def _export_hardware_info(self) -> None:
        """Export hardware inventory."""
        log_step("Exporting hardware inventory...")

        if not self.inspection.hardware:
            log_warn("No hardware information to export")
            return

        hardware = {
            "schema_version": "1.0.0",
            "note": "Device identifiers are host-specific and must be re-detected on User B's machine",
            "cameras_by_id": self.inspection.hardware.cameras_by_id,
            "serial_by_id": self.inspection.hardware.serial_by_id,
            "serial_by_path": self.inspection.hardware.serial_by_path,
            "usb_devices": self.inspection.hardware.usb_devices,
            "dri_devices": self.inspection.hardware.dri_devices,
            "sound_devices": self.inspection.hardware.sound_devices,
            "dri_gid": self.inspection.hardware.dri_gid,
            "audio_gid": self.inspection.hardware.audio_gid,
            "render_gid": self.inspection.hardware.render_gid,
        }

        hw_path = self.output_dir / "hardware" / "devices.json"
        with open(hw_path, "w") as f:
            json.dump(hardware, f, indent=2)

        # Network intents
        if self.inspection.network_intents:
            network = {
                "schema_version": "1.0.0",
                "note": "Network intents only - no credentials included",
                "interfaces": [
                    {
                        "interface_name": n.interface_name,
                        "interface_type": n.interface_type,
                        "address": n.address,
                        "subnet": n.subnet,
                        "gateway": n.gateway,
                        "connection_name": n.connection_name,
                        "purpose": n.purpose,
                    }
                    for n in self.inspection.network_intents
                ]
            }
            net_path = self.output_dir / "hardware" / "network.json"
            with open(net_path, "w") as f:
                json.dump(network, f, indent=2)

        log_ok("Hardware inventory saved")

    def _export_secrets_required(self) -> None:
        """Export list of secrets User B must supply."""
        log_step("Creating secrets required list...")

        config_dir = self.output_dir / "configuration"

        content = """# Secrets Required for User B

The following credentials/secrets were detected in User A's environment
but are NOT included in this migration bundle. User B must supply their
own credentials for these services.

## AI/ML Service Credentials

These are typically found in:
- `~/.config/claude-bedrock/env` - AWS Bedrock / Anthropic credentials
- `~/.codex/auth.json` - Codex authentication
- `~/.claude.json` - Claude CLI configuration

User B should set up their own accounts and credentials.

## Repository Access

The workspace git remotes are recorded in `git/repos.json`. User B needs their
own credentials (SSH key or access token) for whichever hosting services those
remotes point to; no git credential is ever included in this bundle.

## Application Secrets

- `config/secrets.yaml` - Application-specific secrets (if the workspace
  uses this pattern). This file is gitignored and must be created manually.

## X11 Cookie

The X11 authentication cookie is regenerated by running:
```bash
./install_user_xauthority_sync.sh
```

## Network Credentials

Wi-Fi passwords and NetworkManager credentials are NOT included.
User B must configure their own network connections.

---

IMPORTANT: Never share this bundle with credentials included.
The bundle creator ensures no secrets are exported.
"""

        secrets_path = config_dir / "SECRETS_REQUIRED.md"
        with open(secrets_path, "w") as f:
            f.write(content)

        # Also write detected secrets (path/kind only)
        if self.inspection.secrets:
            detected = {
                "schema_version": "1.0.0",
                "note": "Existence only - contents never read or stored",
                "detected_secrets": [
                    {
                        "path": s.path,
                        "kind": s.kind,
                        "location": s.location,
                    }
                    for s in self.inspection.secrets
                ]
            }
            detected_path = config_dir / "detected_secrets.json"
            with open(detected_path, "w") as f:
                json.dump(detected, f, indent=2)

        log_ok("Secrets required list created")

    def _export_verification(self) -> None:
        """Export verification checks."""
        log_step("Creating verification checks...")

        checks = [
            {"name": "docker_installed", "type": "automated", "description": "Docker is installed"},
            {"name": "docker_accessible", "type": "automated", "description": "Docker daemon is accessible"},
            {"name": "docker_group", "type": "automated", "description": "User is in docker group"},
            {"name": "compose_installed", "type": "automated", "description": "Docker Compose is available"},
            {"name": "disk_space", "type": "automated", "description": "Sufficient disk space (60GB)"},
            {"name": "image_loaded", "type": "automated", "description": "Base image is loaded"},
            {"name": "udev_installed", "type": "automated", "description": "udev rules are installed"},
            {"name": "workspace_restored", "type": "automated", "description": "Workspace is restored"},
            {"name": "git_state", "type": "automated", "description": "Git repositories restored"},
            {"name": "container_running", "type": "automated", "description": "Container starts and runs"},
            {"name": "gpu_host", "type": "automated", "description": "nvidia-smi works on host"},
            {"name": "gpu_container", "type": "automated", "description": "GPU accessible in container"},
            {"name": "ros_packages", "type": "automated", "description": "ROS packages build successfully"},
            {"name": "model_weights", "type": "automated", "description": "Large model files present with correct checksums"},
            {"name": "x11_display", "type": "manual", "description": "GUI applications display correctly"},
            {"name": "audio", "type": "manual", "description": "Audio works"},
            {"name": "camera", "type": "manual", "description": "Camera devices accessible"},
            {"name": "serial", "type": "manual", "description": "Serial devices accessible (if attached)"},
        ]

        checks_path = self.output_dir / "verification" / "checks.json"
        with open(checks_path, "w") as f:
            json.dump({"schema_version": "1.0.0", "checks": checks}, f, indent=2)

        log_ok("Verification checks created")

    def _write_manifest(self) -> None:
        """Write bundle manifest."""
        log_step("Writing manifest...")

        self.manifest.checksums = self.checksums

        manifest_dict = asdict(self.manifest)
        manifest_path = self.output_dir / "MANIFEST.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest_dict, f, indent=2)

        log_ok("Manifest written")

    def _write_readme(self) -> None:
        """Write bundle README."""
        readme_content = f"""# Migration Bundle

Created: {self.manifest.created_at}
Tool Version: {self.manifest.tool_version}

## Source Environment

- Workspace: {self.manifest.workspace_name}
- Container: {self.manifest.container_name}
- Source Image (NOT exported): {self.manifest.source_runtime_image}
- Clean Base Image (exported): {self.manifest.clean_base_image}
- ROS Distro: {self.manifest.ros_distro}

## Important Notes

### Why the snapshot image is NOT exported

The runtime snapshot image contains credentials (AI service tokens, etc.)
in its layers. These cannot be safely removed without rebuilding.

This bundle exports:
1. The clean Dockerfile-built parent image
2. Package manifests for restoring dependencies
3. The workspace with all source and model files

### Import Process

1. Run `docker-migration import <bundle_path>`
2. The tool will:
   - Validate checksums
   - Load the clean base image
   - Restore the workspace
   - Run the dependency installation script
   - Regenerate host-specific configuration
3. Manual steps required:
   - Supply your own credentials (see `configuration/SECRETS_REQUIRED.md`)
   - Configure network interfaces
   - Verify camera/serial device paths

### Host-Specific Regeneration

The following are regenerated on User B's machine:
- `.env` (via config.sh)
- `docker-compose.override.yml` (via config.sh)
- X11 cookie (via xauthority sync script)
- udev rules (via install script)

## Bundle Contents

- `docker/image/` - Clean base image
- `docker/config/` - Portable Docker configuration
- `workspace/` - Workspace archive
- `git/` - Git repository state
- `packages/` - Package manifests
- `host/` - Source host info (for comparison)
- `hardware/` - Hardware inventory
- `configuration/` - Secrets list, ROS config
- `verification/` - Verification checks

## Checksums

See `MANIFEST.json` for file checksums.
"""

        readme_path = self.output_dir / "README.md"
        with open(readme_path, "w") as f:
            f.write(readme_content)


def create_bundle(inspection: InspectionResult, output_dir: Path,
                  dry_run: bool = False) -> Path:
    """Create a migration bundle.

    Args:
        inspection: Inspection results
        output_dir: Output directory
        dry_run: If True, don't create anything

    Returns:
        Path to bundle
    """
    creator = BundleCreator(inspection, output_dir, dry_run)
    return creator.create()
