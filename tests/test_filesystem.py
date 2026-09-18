"""Tests for filesystem utilities."""

import os
import tempfile
import tarfile
from pathlib import Path

import pytest

from docker_migration_tool.utils.filesystem import (
    compute_sha256,
    compute_sha256_file,
    safe_path_join,
    safe_extract_archive,
    ArchiveSecurityError,
)


class TestSHA256:
    """Tests for SHA256 computation."""

    def test_compute_sha256_bytes(self):
        """Test SHA256 computation from bytes."""
        data = b"hello world"
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert compute_sha256(data) == expected

    def test_compute_sha256_empty(self):
        """Test SHA256 of empty bytes."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert compute_sha256(b"") == expected

    def test_compute_sha256_file(self, tmp_path):
        """Test SHA256 computation from file."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"hello world")
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert compute_sha256_file(test_file) == expected


class TestSafePathJoin:
    """Tests for safe path joining."""

    def test_normal_join(self, tmp_path):
        """Test normal path joining."""
        result = safe_path_join(tmp_path, "subdir", "file.txt")
        assert str(result).startswith(str(tmp_path))

    def test_absolute_path_blocked(self, tmp_path):
        """Test that absolute paths are blocked."""
        with pytest.raises(ArchiveSecurityError):
            safe_path_join(tmp_path, "/etc/passwd")

    def test_parent_traversal_blocked(self, tmp_path):
        """Test that parent directory traversal is blocked."""
        with pytest.raises(ArchiveSecurityError):
            safe_path_join(tmp_path, "..", "outside")

    def test_deep_traversal_blocked(self, tmp_path):
        """Test that deep traversal is blocked."""
        with pytest.raises(ArchiveSecurityError):
            safe_path_join(tmp_path, "a", "b", "..", "..", "..", "outside")

    def test_single_dot_allowed(self, tmp_path):
        """Test that single dots are allowed."""
        result = safe_path_join(tmp_path, ".", "file.txt")
        assert str(result).startswith(str(tmp_path))


class TestSafeExtractArchive:
    """Tests for safe archive extraction."""

    def test_normal_extraction(self, tmp_path):
        """Test normal archive extraction."""
        # Create a test archive
        archive_path = tmp_path / "test.tar"
        extract_path = tmp_path / "extracted"

        with tarfile.open(archive_path, "w") as tar:
            # Add a test file
            test_content = b"test content"
            import io
            info = tarfile.TarInfo(name="test.txt")
            info.size = len(test_content)
            tar.addfile(info, io.BytesIO(test_content))

        safe_extract_archive(archive_path, extract_path)

        assert (extract_path / "test.txt").exists()
        assert (extract_path / "test.txt").read_bytes() == test_content

    def test_directory_extraction(self, tmp_path):
        """Test directory extraction."""
        archive_path = tmp_path / "test.tar"
        extract_path = tmp_path / "extracted"

        with tarfile.open(archive_path, "w") as tar:
            # Add a directory
            info = tarfile.TarInfo(name="subdir/")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)

            # Add a file in the directory
            test_content = b"nested content"
            import io
            info = tarfile.TarInfo(name="subdir/nested.txt")
            info.size = len(test_content)
            tar.addfile(info, io.BytesIO(test_content))

        safe_extract_archive(archive_path, extract_path)

        assert (extract_path / "subdir").is_dir()
        assert (extract_path / "subdir" / "nested.txt").exists()

    def test_absolute_path_blocked(self, tmp_path):
        """Test that absolute paths in archives are blocked."""
        archive_path = tmp_path / "malicious.tar"
        extract_path = tmp_path / "extracted"

        with tarfile.open(archive_path, "w") as tar:
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = 0
            tar.addfile(info)

        with pytest.raises(ArchiveSecurityError):
            safe_extract_archive(archive_path, extract_path)

    def test_traversal_blocked(self, tmp_path):
        """Test that path traversal in archives is blocked."""
        archive_path = tmp_path / "malicious.tar"
        extract_path = tmp_path / "extracted"

        with tarfile.open(archive_path, "w") as tar:
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 0
            tar.addfile(info)

        with pytest.raises(ArchiveSecurityError):
            safe_extract_archive(archive_path, extract_path)

    def test_symlink_escape_blocked(self, tmp_path):
        """Test that symlink escapes are blocked."""
        archive_path = tmp_path / "malicious.tar"
        extract_path = tmp_path / "extracted"

        with tarfile.open(archive_path, "w") as tar:
            info = tarfile.TarInfo(name="link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)

        with pytest.raises(ArchiveSecurityError):
            safe_extract_archive(archive_path, extract_path)

    def test_symlink_traversal_blocked(self, tmp_path):
        """Test that symlink traversal is blocked."""
        archive_path = tmp_path / "malicious.tar"
        extract_path = tmp_path / "extracted"

        with tarfile.open(archive_path, "w") as tar:
            info = tarfile.TarInfo(name="link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../../etc/passwd"
            tar.addfile(info)

        with pytest.raises(ArchiveSecurityError):
            safe_extract_archive(archive_path, extract_path)

    def test_device_node_blocked(self, tmp_path):
        """Test that device nodes are blocked."""
        archive_path = tmp_path / "malicious.tar"
        extract_path = tmp_path / "extracted"

        with tarfile.open(archive_path, "w") as tar:
            info = tarfile.TarInfo(name="device")
            info.type = tarfile.CHRTYPE
            info.devmajor = 1
            info.devminor = 3
            tar.addfile(info)

        with pytest.raises(ArchiveSecurityError):
            safe_extract_archive(archive_path, extract_path)
