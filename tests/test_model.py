"""Tests for data models."""

import json
from dataclasses import asdict

import pytest

from docker_migration_tool.model import (
    Classification,
    MountInfo,
    ImageInfo,
    GitRepoInfo,
    BundleManifest,
    SecretFinding,
)


class TestClassification:
    """Tests for Classification enum."""

    def test_classification_values(self):
        """Test classification enum values."""
        assert Classification.A.value == "reproducible"
        assert Classification.B.value == "mutable_state"
        assert Classification.C.value == "host_dependent"
        assert Classification.D.value == "secret"

    def test_classification_from_string(self):
        """Test creating classification from string."""
        assert Classification("reproducible") == Classification.A
        assert Classification("secret") == Classification.D


class TestMountInfo:
    """Tests for MountInfo model."""

    def test_mount_creation(self):
        """Test creating a mount info."""
        mount = MountInfo(
            host_source="/home/user/ws/src",
            container_target="/home/user/colcon_ws/src",
            mode="rw",
            mount_type="bind",
        )
        assert mount.host_source == "/home/user/ws/src"
        assert mount.classification == Classification.C
        assert mount.migration_action == "regenerate"
        assert mount.is_workspace is False

    def test_mount_serialization(self):
        """Test mount serialization to dict."""
        mount = MountInfo(
            host_source="/home/user/ws/src",
            container_target="/home/user/colcon_ws/src",
            mode="rw",
            mount_type="bind",
            classification=Classification.B,
            migration_action="copy",
            is_workspace=True,
        )
        data = asdict(mount)
        assert data["host_source"] == "/home/user/ws/src"
        assert data["classification"] == Classification.B


class TestImageInfo:
    """Tests for ImageInfo model."""

    def test_image_creation(self):
        """Test creating image info."""
        image = ImageInfo(
            repository="example/workspace",
            tag="snapshot-0001",
            image_id="abc123",
            size_bytes=14_000_000_000,
            layer_count=26,
            is_snapshot=True,
        )
        assert image.repository == "example/workspace"
        assert image.is_snapshot is True
        assert image.is_clean_parent is False

    def test_clean_parent_image(self):
        """Test clean parent image flags."""
        image = ImageInfo(
            repository="example/workspace",
            tag="base-image",
            image_id="def456",
            is_snapshot=False,
            is_clean_parent=True,
        )
        assert image.is_snapshot is False
        assert image.is_clean_parent is True
        assert image.classification == Classification.A


class TestGitRepoInfo:
    """Tests for GitRepoInfo model."""

    def test_git_repo_creation(self):
        """Test creating git repo info."""
        repo = GitRepoInfo(
            path="/home/user/ws/src/example_app",
            remote_url="https://dev.azure.com/org/project/_git/repo",
            branch="main",
            head_commit="abc123def456",
            is_dirty=True,
            modified_files=["file1.py", "file2.py"],
            untracked_files=["new_file.py"],
        )
        assert repo.is_dirty is True
        assert len(repo.modified_files) == 2
        assert len(repo.untracked_files) == 1
        assert repo.classification == Classification.B

    def test_git_repo_with_submodules(self):
        """Test git repo with submodules."""
        submodule = GitRepoInfo(
            path="external/detector",
            remote_url="https://github.com/example-org/detector.git",
            head_commit="8e451d5eb43c",
            is_dirty=True,
        )
        repo = GitRepoInfo(
            path="/home/user/ws/src/detector_ros",
            remote_url="https://dev.azure.com/org/project/_git/detector_ros",
            branch="main",
            head_commit="a0d0ef6d066a",
            submodules=[submodule],
        )
        assert len(repo.submodules) == 1
        assert repo.submodules[0].is_dirty is True


class TestBundleManifest:
    """Tests for BundleManifest model."""

    def test_manifest_creation(self):
        """Test creating bundle manifest."""
        manifest = BundleManifest(
            workspace_name="sample_workspace",
            container_name="sample_workspace-gpu",
            clean_base_image="example/workspace:base",
            ros_distro="humble",
        )
        assert manifest.schema_version == "1.0.0"
        assert manifest.workspace_name == "sample_workspace"
        assert manifest.ros_distro == "humble"

    def test_manifest_serialization(self):
        """Test manifest serialization to JSON."""
        manifest = BundleManifest(
            workspace_name="test_ws",
            container_name="test-gpu",
            checksums={"file1": "abc123", "file2": "def456"},
        )
        data = asdict(manifest)
        json_str = json.dumps(data)
        restored = json.loads(json_str)

        assert restored["workspace_name"] == "test_ws"
        assert restored["checksums"]["file1"] == "abc123"

    def test_manifest_defaults(self):
        """Test manifest default values."""
        manifest = BundleManifest()
        assert manifest.schema_version == "1.0.0"
        assert manifest.tool_version == "1.0.0"
        assert manifest.created_at is not None
        assert manifest.components == []
        assert manifest.checksums == {}


class TestSecretFinding:
    """Tests for SecretFinding model."""

    def test_secret_finding_creation(self):
        """Test creating secret finding."""
        finding = SecretFinding(
            path="/home/user/.codex/auth.json",
            kind="codex_credential",
            exists=True,
            size_bytes=3996,
            location="container",
        )
        assert finding.kind == "codex_credential"
        assert finding.classification == Classification.D
        assert finding.exists is True

    def test_secret_finding_serialization(self):
        """Test secret finding serialization."""
        finding = SecretFinding(
            path="/home/user/.ssh/id_rsa",
            kind="ssh_key",
            exists=True,
            location="host",
        )
        data = asdict(finding)
        # Ensure no actual secret content
        assert "content" not in data
        assert data["path"] == "/home/user/.ssh/id_rsa"
        assert data["kind"] == "ssh_key"
