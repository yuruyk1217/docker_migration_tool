"""Tests for P0/P1/P2 fixes discovered during real A-to-B migration.

These tests verify:
- P0: Snapshot RUNTIME_IMAGE_TAG_OVERRIDE normalization in export
- P0: Import preflight runtime image consistency check
- P1: Portable Docker config checksum verification
- P1: Dry-run workspace path output (not "None")
- P2: Workspace rename semantics
"""

import json
import os
import re
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from docker_migration_tool.export.bundle import BundleCreator
from docker_migration_tool.importers.preflight import PreflightChecker
from docker_migration_tool.importers.restore import BundleRestorer
from docker_migration_tool.model import (
    BundleManifest,
    ContainerInfo,
    ImageConfigScanResult,
    ImageInfo,
    InspectionResult,
    ParentRelationship,
    PortableDockerConfig,
)


# Test layer chains
RUNTIME_LAYERS = [f"sha256:{i:064x}" for i in range(1, 27)]   # 26 layers
CLEAN_LAYERS = RUNTIME_LAYERS[:-1]                            # 25 layers

CLEAN_IMAGE = "example/workspace:ubuntu22.04-gpu-base"
SNAPSHOT_IMAGE = "example/workspace:ws-snapshot-0001"


def make_inspection(
    clean_image: str = CLEAN_IMAGE,
    snapshot_image: str = SNAPSHOT_IMAGE,
    workspace_path: str = "/tmp/test_workspace",
) -> InspectionResult:
    """Build a minimal inspection result with a proven parent relationship."""
    runtime = ImageInfo(
        repository="example/workspace",
        tag="ws-snapshot-0001",
        image_id="8ee74ea84746",
        layer_count=len(RUNTIME_LAYERS),
        is_snapshot=True,
        rootfs_layers=RUNTIME_LAYERS,
    )
    clean = ImageInfo(
        repository="example/workspace",
        tag="ubuntu22.04-gpu-base",
        image_id="b82eeced1ba2",
        size_bytes=22_800_000_000,
        layer_count=len(CLEAN_LAYERS),
        is_clean_parent=True,
        rootfs_layers=CLEAN_LAYERS,
    )
    return InspectionResult(
        container=ContainerInfo(
            name="test_ws-gpu",
            container_id="abc123",
            image=runtime.reference,
            image_id=runtime.image_id,
            state="running",
            created="2026-09-17T00:00:00Z",
            user="1000:1000",
            workspace_name="test_workspace",
        ),
        runtime_image=runtime,
        clean_base_image=clean,
        parent_relationship=ParentRelationship(
            verified=True,
            relationship="strict_prefix",
            runtime_image=runtime.reference,
            candidate_image=clean.reference,
            runtime_layer_count=len(RUNTIME_LAYERS),
            candidate_layer_count=len(CLEAN_LAYERS),
            candidate_source="env.sh",
        ),
        workspace_path=workspace_path,
        docker_config=PortableDockerConfig(),
    )


def passing_config_scan() -> ImageConfigScanResult:
    """A clean image config/history scan verdict."""
    return ImageConfigScanResult(
        performed=True,
        result="passed",
        scanner_version="1.0.0",
        env_vars_scanned=51,
        labels_scanned=4,
        history_entries_scanned=117,
    )


def patch_security_scans(monkeypatch):
    """Stub all security scans to pass."""
    from docker_migration_tool.export import bundle as bundle_module

    monkeypatch.setattr(bundle_module, "scan_image_config", lambda img: passing_config_scan())
    monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda img: [])


class TestSnapshotOverrideNormalization:
    """P0: Verify env.sh RUNTIME_IMAGE_TAG_OVERRIDE is normalized to clean parent."""

    def test_snapshot_override_replaced_with_clean_parent(self, tmp_path, monkeypatch):
        """Source env.sh with snapshot override -> bundle env.sh uses clean parent."""
        # Create source workspace with env.sh pointing to snapshot
        src_workspace = tmp_path / "src_workspace"
        src_docker = src_workspace / "docker"
        src_docker.mkdir(parents=True)

        env_sh_content = f'''#!/bin/bash
export IMAGE_NAMESPACE="example"
export UBUNTU_VERSION="22.04"
# This override points to the source snapshot - must be normalized
export RUNTIME_IMAGE_TAG_OVERRIDE="{SNAPSHOT_IMAGE}"
export ROS_DOMAIN_ID="1"
'''
        (src_docker / "env.sh").write_text(env_sh_content)

        # Create minimal docker-compose.yml and other files
        (src_docker / "docker-compose.yml").write_text("version: '3'\n")
        (src_docker / "Dockerfile").write_text("FROM ubuntu:22.04\n")

        # Create inspection result
        inspection = make_inspection(workspace_path=str(src_workspace))
        inspection.docker_config = PortableDockerConfig(
            env_sh_path=str(src_docker / "env.sh"),
            compose_yml_path=str(src_docker / "docker-compose.yml"),
            dockerfile_path=str(src_docker / "Dockerfile"),
        )

        # Stub security scans
        patch_security_scans(monkeypatch)

        # Create bundle
        bundle_path = tmp_path / "test_bundle"
        creator = BundleCreator(inspection, bundle_path, dry_run=False)

        # Mock the image export and layer scan
        def mock_docker_save(image, path):
            path.write_bytes(b"mock tar content")

        def mock_scan_archive(path):
            from docker_migration_tool.model import LayerScanResult
            return LayerScanResult(
                performed=True,
                result="passed",
                scanner_version="1.0.0",
                layers_scanned=25,
                entries_scanned=10000,
            )

        monkeypatch.setattr("docker_migration_tool.export.bundle.docker_save", mock_docker_save)
        monkeypatch.setattr("docker_migration_tool.export.bundle.scan_image_archive", mock_scan_archive)

        # Run export
        creator.create()

        # Verify the bundle's env.sh has the clean parent, not the snapshot
        bundle_env_sh = bundle_path / "docker" / "config" / "env.sh"
        assert bundle_env_sh.exists()

        content = bundle_env_sh.read_text()
        assert CLEAN_IMAGE in content
        # Should NOT contain the original snapshot image in RUNTIME_IMAGE_TAG_OVERRIDE
        # (it might still be in comments as provenance info)
        lines = [l for l in content.split('\n')
                 if 'RUNTIME_IMAGE_TAG_OVERRIDE' in l and not l.strip().startswith('#')]
        for line in lines:
            assert SNAPSHOT_IMAGE not in line, f"Snapshot still in non-comment: {line}"

    def test_no_override_leaves_env_sh_unchanged(self, tmp_path, monkeypatch):
        """env.sh without RUNTIME_IMAGE_TAG_OVERRIDE is not modified (except checksum)."""
        src_workspace = tmp_path / "src_workspace"
        src_docker = src_workspace / "docker"
        src_docker.mkdir(parents=True)

        env_sh_content = '''#!/bin/bash
export IMAGE_NAMESPACE="example"
export UBUNTU_VERSION="22.04"
export ROS_DOMAIN_ID="1"
'''
        (src_docker / "env.sh").write_text(env_sh_content)
        (src_docker / "docker-compose.yml").write_text("version: '3'\n")
        (src_docker / "Dockerfile").write_text("FROM ubuntu:22.04\n")

        inspection = make_inspection(workspace_path=str(src_workspace))
        inspection.docker_config = PortableDockerConfig(
            env_sh_path=str(src_docker / "env.sh"),
            compose_yml_path=str(src_docker / "docker-compose.yml"),
            dockerfile_path=str(src_docker / "Dockerfile"),
        )

        patch_security_scans(monkeypatch)

        bundle_path = tmp_path / "test_bundle"
        creator = BundleCreator(inspection, bundle_path, dry_run=False)

        def mock_docker_save(image, path):
            path.write_bytes(b"mock tar content")

        def mock_scan_archive(path):
            from docker_migration_tool.model import LayerScanResult
            return LayerScanResult(performed=True, result="passed", scanner_version="1.0.0",
                                   layers_scanned=25, entries_scanned=10000)

        monkeypatch.setattr("docker_migration_tool.export.bundle.docker_save", mock_docker_save)
        monkeypatch.setattr("docker_migration_tool.export.bundle.scan_image_archive", mock_scan_archive)

        creator.create()

        bundle_env_sh = bundle_path / "docker" / "config" / "env.sh"
        content = bundle_env_sh.read_text()

        # No RUNTIME_IMAGE_TAG_OVERRIDE should be added
        assert "RUNTIME_IMAGE_TAG_OVERRIDE" not in content


class TestRuntimeImageConsistencyCheck:
    """P0: Import preflight detects mismatch between bundle image and config."""

    def test_matching_images_pass(self, tmp_path):
        """Bundle clean image matches config runtime image -> pass."""
        bundle_path = tmp_path / "bundle"
        bundle_path.mkdir()

        # Create manifest with clean image
        manifest = {
            "schema_version": "1.0.0",
            "clean_base_image": CLEAN_IMAGE,
            "parent_relationship_verified": True,
            "layer_secret_scan_result": "passed",
            "image_config_scan_result": "passed",
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        # Create docker/config with matching env.sh
        config_dir = bundle_path / "docker" / "config"
        config_dir.mkdir(parents=True)
        env_sh = f'export RUNTIME_IMAGE_TAG_OVERRIDE="{CLEAN_IMAGE}"\n'
        (config_dir / "env.sh").write_text(env_sh)

        # Also need docker/image and workspace dirs for structure check
        (bundle_path / "docker" / "image").mkdir(parents=True)
        (bundle_path / "workspace").mkdir()

        checker = PreflightChecker(bundle_path)
        checker._check_runtime_image_consistency()

        # Should pass without errors
        assert not checker.errors
        passed_checks = [c for c in checker.checks if c.name == "runtime_image_consistency" and c.passed]
        assert len(passed_checks) == 1

    def test_mismatched_images_fail(self, tmp_path):
        """Bundle clean image != config runtime image -> fail."""
        bundle_path = tmp_path / "bundle"
        bundle_path.mkdir()

        manifest = {
            "schema_version": "1.0.0",
            "clean_base_image": CLEAN_IMAGE,
            "parent_relationship_verified": True,
            "layer_secret_scan_result": "passed",
            "image_config_scan_result": "passed",
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        config_dir = bundle_path / "docker" / "config"
        config_dir.mkdir(parents=True)
        # Deliberately use snapshot image in config (mismatch!)
        env_sh = f'export RUNTIME_IMAGE_TAG_OVERRIDE="{SNAPSHOT_IMAGE}"\n'
        (config_dir / "env.sh").write_text(env_sh)

        (bundle_path / "docker" / "image").mkdir(parents=True)
        (bundle_path / "workspace").mkdir()

        checker = PreflightChecker(bundle_path)
        checker._check_runtime_image_consistency()

        # Should fail with error
        assert len(checker.errors) == 1
        assert "not supplied by this bundle" in checker.errors[0]

    def test_no_override_assumes_clean_parent(self, tmp_path):
        """No RUNTIME_IMAGE_TAG_OVERRIDE in env.sh -> assume clean parent (pass)."""
        bundle_path = tmp_path / "bundle"
        bundle_path.mkdir()

        manifest = {
            "schema_version": "1.0.0",
            "clean_base_image": CLEAN_IMAGE,
            "parent_relationship_verified": True,
            "layer_secret_scan_result": "passed",
            "image_config_scan_result": "passed",
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        config_dir = bundle_path / "docker" / "config"
        config_dir.mkdir(parents=True)
        # No override - will use IMAGE_TAG or default
        env_sh = 'export IMAGE_NAMESPACE="example"\n'
        (config_dir / "env.sh").write_text(env_sh)

        (bundle_path / "docker" / "image").mkdir(parents=True)
        (bundle_path / "workspace").mkdir()

        checker = PreflightChecker(bundle_path)
        checker._check_runtime_image_consistency()

        # Should pass (unable to determine = assume correct)
        assert not checker.errors


class TestPortableConfigChecksum:
    """P1: Portable Docker config files are checksummed in MANIFEST."""

    def test_config_files_have_checksums(self, tmp_path, monkeypatch):
        """Export creates checksums for all portable config files."""
        src_workspace = tmp_path / "src_workspace"
        src_docker = src_workspace / "docker"
        src_docker.mkdir(parents=True)

        (src_docker / "env.sh").write_text("export FOO=bar\n")
        (src_docker / "common.sh").write_text("# common\n")
        (src_docker / "config.sh").write_text("# config\n")
        (src_docker / "docker-compose.yml").write_text("version: '3'\n")
        (src_docker / "Dockerfile").write_text("FROM ubuntu:22.04\n")

        inspection = make_inspection(workspace_path=str(src_workspace))
        inspection.docker_config = PortableDockerConfig(
            env_sh_path=str(src_docker / "env.sh"),
            common_sh_path=str(src_docker / "common.sh"),
            config_sh_path=str(src_docker / "config.sh"),
            compose_yml_path=str(src_docker / "docker-compose.yml"),
            dockerfile_path=str(src_docker / "Dockerfile"),
        )

        patch_security_scans(monkeypatch)

        bundle_path = tmp_path / "test_bundle"
        creator = BundleCreator(inspection, bundle_path, dry_run=False)

        def mock_docker_save(image, path):
            path.write_bytes(b"mock tar content")

        def mock_scan_archive(path):
            from docker_migration_tool.model import LayerScanResult
            return LayerScanResult(performed=True, result="passed", scanner_version="1.0.0",
                                   layers_scanned=25, entries_scanned=10000)

        monkeypatch.setattr("docker_migration_tool.export.bundle.docker_save", mock_docker_save)
        monkeypatch.setattr("docker_migration_tool.export.bundle.scan_image_archive", mock_scan_archive)

        creator.create()

        # Load manifest and check for config checksums
        manifest = json.loads((bundle_path / "MANIFEST.json").read_text())
        checksums = manifest.get("checksums", {})

        # All config files should have checksums
        expected_files = [
            "docker/config/env.sh",
            "docker/config/common.sh",
            "docker/config/config.sh",
            "docker/config/docker-compose.yml",
            "docker/config/Dockerfile",
        ]

        for expected in expected_files:
            assert expected in checksums, f"Missing checksum for {expected}"
            # Checksum should be a 64-char hex string (SHA256)
            assert len(checksums[expected]) == 64
            assert all(c in "0123456789abcdef" for c in checksums[expected])

    def test_tampered_config_fails_verify(self, tmp_path, monkeypatch):
        """Modifying a config file after export causes checksum failure."""
        src_workspace = tmp_path / "src_workspace"
        src_docker = src_workspace / "docker"
        src_docker.mkdir(parents=True)

        (src_docker / "env.sh").write_text("export FOO=bar\n")
        (src_docker / "docker-compose.yml").write_text("version: '3'\n")
        (src_docker / "Dockerfile").write_text("FROM ubuntu:22.04\n")

        inspection = make_inspection(workspace_path=str(src_workspace))
        inspection.docker_config = PortableDockerConfig(
            env_sh_path=str(src_docker / "env.sh"),
            compose_yml_path=str(src_docker / "docker-compose.yml"),
            dockerfile_path=str(src_docker / "Dockerfile"),
        )

        patch_security_scans(monkeypatch)

        bundle_path = tmp_path / "test_bundle"
        creator = BundleCreator(inspection, bundle_path, dry_run=False)

        def mock_docker_save(image, path):
            path.write_bytes(b"mock tar content")

        def mock_scan_archive(path):
            from docker_migration_tool.model import LayerScanResult
            return LayerScanResult(performed=True, result="passed", scanner_version="1.0.0",
                                   layers_scanned=25, entries_scanned=10000)

        monkeypatch.setattr("docker_migration_tool.export.bundle.docker_save", mock_docker_save)
        monkeypatch.setattr("docker_migration_tool.export.bundle.scan_image_archive", mock_scan_archive)

        creator.create()

        # Tamper with env.sh
        bundle_env_sh = bundle_path / "docker" / "config" / "env.sh"
        bundle_env_sh.write_text("export EVIL=hack\n")

        # Validate bundle - should detect tampering
        checker = PreflightChecker(bundle_path)
        checker._validate_bundle()

        # Should have a checksum mismatch error for env.sh
        checksum_errors = [e for e in checker.errors if "Checksum mismatch" in e]
        assert len(checksum_errors) >= 1


class TestDryRunWorkspacePath:
    """P1: Dry-run shows planned workspace path, not "None"."""

    def test_dry_run_returns_planned_workspace(self, tmp_path):
        """import --dry-run result includes the planned workspace path."""
        bundle_path = tmp_path / "bundle"
        bundle_path.mkdir()

        manifest = {
            "schema_version": "1.0.0",
            "workspace_name": "my_workspace",
            "clean_base_image": CLEAN_IMAGE,
            "parent_relationship_verified": True,
            "layer_secret_scan_result": "passed",
            "image_config_scan_result": "passed",
            "checksums": {},
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        # Create minimal bundle structure
        (bundle_path / "docker" / "image").mkdir(parents=True)
        (bundle_path / "docker" / "config").mkdir(parents=True)
        (bundle_path / "workspace").mkdir()

        # Mock preflight to avoid real Docker calls
        with patch.object(PreflightChecker, "_check_docker"):
            with patch.object(PreflightChecker, "_check_compose"):
                with patch.object(PreflightChecker, "_check_docker_group"):
                    with patch.object(PreflightChecker, "_check_disk_space"):
                        with patch.object(PreflightChecker, "_check_gpu"):
                            with patch.object(PreflightChecker, "_check_nvidia_toolkit"):
                                # Test with explicit workspace path
                                explicit_ws = tmp_path / "explicit_workspace"
                                restorer = BundleRestorer(
                                    bundle_path,
                                    target_workspace=explicit_ws,
                                    dry_run=True,
                                    interactive=False,
                                )
                                result = restorer.restore()

        assert result.success
        assert result.workspace_path is not None
        assert result.workspace_path != "None"
        assert str(explicit_ws) == result.workspace_path

    def test_dry_run_uses_default_workspace_when_not_specified(self, tmp_path, monkeypatch):
        """import --dry-run uses default workspace path when not specified."""
        bundle_path = tmp_path / "bundle"
        bundle_path.mkdir()

        manifest = {
            "schema_version": "1.0.0",
            "workspace_name": "my_workspace",
            "clean_base_image": CLEAN_IMAGE,
            "parent_relationship_verified": True,
            "layer_secret_scan_result": "passed",
            "image_config_scan_result": "passed",
            "checksums": {},
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        (bundle_path / "docker" / "image").mkdir(parents=True)
        (bundle_path / "docker" / "config").mkdir(parents=True)
        (bundle_path / "workspace").mkdir()

        # Set a custom home for predictable results
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))

        with patch.object(PreflightChecker, "_check_docker"):
            with patch.object(PreflightChecker, "_check_compose"):
                with patch.object(PreflightChecker, "_check_docker_group"):
                    with patch.object(PreflightChecker, "_check_disk_space"):
                        with patch.object(PreflightChecker, "_check_gpu"):
                            with patch.object(PreflightChecker, "_check_nvidia_toolkit"):
                                restorer = BundleRestorer(
                                    bundle_path,
                                    target_workspace=None,  # No explicit path
                                    dry_run=True,
                                    interactive=False,
                                )
                                result = restorer.restore()

        assert result.success
        assert result.workspace_path is not None
        # Should be under the default location
        assert "docker_workspaces" in result.workspace_path
        assert "my_workspace" in result.workspace_path


class TestWorkspaceRenameSemantics:
    """P2: Clarify what --workspace does to workspace identity."""

    def test_workspace_path_is_filesystem_target(self, tmp_path, monkeypatch):
        """--workspace specifies filesystem location, not logical workspace name."""
        bundle_path = tmp_path / "bundle"
        bundle_path.mkdir()

        manifest = {
            "schema_version": "1.0.0",
            "workspace_name": "original_workspace",  # Source workspace name
            "container_name": "original_container",
            "clean_base_image": CLEAN_IMAGE,
            "parent_relationship_verified": True,
            "layer_secret_scan_result": "passed",
            "image_config_scan_result": "passed",
            "checksums": {},
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        (bundle_path / "docker" / "image").mkdir(parents=True)
        (bundle_path / "docker" / "config").mkdir(parents=True)
        (bundle_path / "workspace").mkdir()

        # Specify a different filesystem path
        new_path = tmp_path / "new_ws_path"

        with patch.object(PreflightChecker, "_check_docker"):
            with patch.object(PreflightChecker, "_check_compose"):
                with patch.object(PreflightChecker, "_check_docker_group"):
                    with patch.object(PreflightChecker, "_check_disk_space"):
                        with patch.object(PreflightChecker, "_check_gpu"):
                            with patch.object(PreflightChecker, "_check_nvidia_toolkit"):
                                restorer = BundleRestorer(
                                    bundle_path,
                                    target_workspace=new_path,
                                    dry_run=True,
                                    interactive=False,
                                )
                                result = restorer.restore()

        # The workspace_path in result is the filesystem target
        assert result.workspace_path == str(new_path)

        # But the manifest's workspace_name (source identity) should be preserved
        # (this is provenance info - we don't modify the source manifest)
        manifest_data = json.loads((bundle_path / "MANIFEST.json").read_text())
        assert manifest_data["workspace_name"] == "original_workspace"


class TestBackwardCompatibility:
    """Existing bundles without new fields should still work."""

    def test_bundle_without_config_checksums_passes_verify(self, tmp_path):
        """Old bundles without config checksums should still pass basic verify."""
        bundle_path = tmp_path / "old_bundle"
        bundle_path.mkdir()

        # Older manifest without config checksums (only image and workspace)
        manifest = {
            "schema_version": "1.0.0",
            "clean_base_image": CLEAN_IMAGE,
            "parent_relationship_verified": True,
            "parent_relationship_method": "rootfs_layer_prefix",
            "layer_secret_scan": True,
            "layer_secret_scan_result": "passed",
            "image_config_scan": True,
            "image_config_scan_result": "passed",
            "checksums": {
                "docker/image/base-image.tar": "a" * 64,
                "workspace/src.tar.zst": "b" * 64,
            },
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        # Create the expected files
        img_dir = bundle_path / "docker" / "image"
        img_dir.mkdir(parents=True)
        (img_dir / "base-image.tar").write_bytes(b"x" * 100)

        ws_dir = bundle_path / "workspace"
        ws_dir.mkdir()
        (ws_dir / "src.tar.zst").write_bytes(b"y" * 100)

        (bundle_path / "docker" / "config").mkdir()

        checker = PreflightChecker(bundle_path)
        # This will fail checksum but the security metadata check should pass
        checker._check_bundle_security_metadata()

        # Security metadata is complete - no errors for missing metadata
        security_errors = [e for e in checker.errors if "unsafe legacy" in e.lower()]
        assert len(security_errors) == 0

    def test_bundle_missing_security_metadata_rejected(self, tmp_path):
        """Bundles without security metadata are rejected as unsafe."""
        bundle_path = tmp_path / "unsafe_bundle"
        bundle_path.mkdir()

        # Very old manifest without security fields
        manifest = {
            "schema_version": "1.0.0",
            "clean_base_image": CLEAN_IMAGE,
            # Missing: parent_relationship_verified, layer_secret_scan_result, etc.
        }
        (bundle_path / "MANIFEST.json").write_text(json.dumps(manifest))

        (bundle_path / "docker" / "image").mkdir(parents=True)
        (bundle_path / "docker" / "config").mkdir(parents=True)
        (bundle_path / "workspace").mkdir()

        checker = PreflightChecker(bundle_path)
        checker._check_bundle_security_metadata()

        # Should have an error about unsafe legacy bundle
        assert len(checker.errors) >= 1
        assert any("unsafe legacy bundle" in e for e in checker.errors)
