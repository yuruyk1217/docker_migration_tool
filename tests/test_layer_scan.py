"""Tests for the full-layer secret scan of `docker save` archives.

All fixtures use DUMMY paths only - no real credential content is ever created,
read or asserted on. Findings are identity only (layer, path, kind).
"""

import gzip
import hashlib
import io
import json
import tarfile

import pytest

from docker_migration_tool.security.layers import (
    SUPPORTED_ARCHIVE_FORMATS,
    UnsupportedImageArchiveError,
    detect_archive_format,
    normalize_layer_member_path,
    scan_image_archive,
)


# ---------------------------------------------------------------------------
# Synthetic archive helpers
# ---------------------------------------------------------------------------


def _make_layer_tar(member_names: list[str]) -> bytes:
    """Build an uncompressed layer tar containing zero-byte members."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name in member_names:
            info = tarfile.TarInfo(name=name)
            info.size = 0
            tar.addfile(info, io.BytesIO(b""))
    return buffer.getvalue()


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def build_oci_save_archive(path, layers: list[list[str]],
                           compress: bool = True) -> None:
    """Build a docker 29.x style save archive (OCI layout + manifest.json).

    Args:
        path: Output tar path
        layers: One list of member names per layer
        compress: gzip the layer blobs (as docker save does)
    """
    with tarfile.open(path, mode="w") as tar:
        _add_bytes(tar, "oci-layout", b'{"imageLayoutVersion": "1.0.0"}')

        layer_members = []
        for member_names in layers:
            blob = _make_layer_tar(member_names)
            if compress:
                blob = gzip.compress(blob)
            digest = hashlib.sha256(blob).hexdigest()
            member = f"blobs/sha256/{digest}"
            _add_bytes(tar, member, blob)
            layer_members.append(member)

        config = json.dumps({"architecture": "amd64", "os": "linux"}).encode()
        config_digest = hashlib.sha256(config).hexdigest()
        _add_bytes(tar, f"blobs/sha256/{config_digest}", config)

        manifest = [{
            "Config": f"blobs/sha256/{config_digest}",
            "RepoTags": ["dummy/image:test"],
            "Layers": layer_members,
        }]
        _add_bytes(tar, "manifest.json", json.dumps(manifest).encode())
        _add_bytes(tar, "index.json", json.dumps({
            "schemaVersion": 2,
            "manifests": [],
        }).encode())


def build_legacy_save_archive(path, layers: list[list[str]]) -> None:
    """Build a classic `docker save` archive (manifest.json + <hash>/layer.tar)."""
    with tarfile.open(path, mode="w") as tar:
        layer_members = []
        for index, member_names in enumerate(layers):
            blob = _make_layer_tar(member_names)
            digest = hashlib.sha256(f"{index}".encode()).hexdigest()
            member = f"{digest}/layer.tar"
            _add_bytes(tar, member, blob)
            layer_members.append(member)

        manifest = [{
            "Config": "config.json",
            "RepoTags": ["dummy/image:legacy"],
            "Layers": layer_members,
        }]
        _add_bytes(tar, "manifest.json", json.dumps(manifest).encode())


def build_oci_index_archive(path, layers: list[list[str]]) -> None:
    """Build an OCI layout archive without the docker manifest.json."""
    with tarfile.open(path, mode="w") as tar:
        _add_bytes(tar, "oci-layout", b'{"imageLayoutVersion": "1.0.0"}')

        descriptors = []
        for member_names in layers:
            blob = gzip.compress(_make_layer_tar(member_names))
            digest = hashlib.sha256(blob).hexdigest()
            _add_bytes(tar, f"blobs/sha256/{digest}", blob)
            descriptors.append({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": f"sha256:{digest}",
                "size": len(blob),
            })

        manifest = json.dumps({
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + "0" * 64},
            "layers": descriptors,
        }).encode()
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        _add_bytes(tar, f"blobs/sha256/{manifest_digest}", manifest)

        _add_bytes(tar, "index.json", json.dumps({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{manifest_digest}",
                "size": len(manifest),
            }],
        }).encode())


CLEAN_LAYER = [
    "./",
    "./usr/",
    "./usr/lib/libfoo.so",
    "./opt/ros/humble/setup.bash",
    "./home/dummy_user/workspace/src/pkg/pkg.py",
]


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


class TestDetectArchiveFormat:
    """Only known layouts may be scanned; unknown ones must be refused."""

    def test_docker_oci_layout(self):
        names = {"oci-layout", "index.json", "manifest.json",
                 "blobs/sha256/abc"}
        assert detect_archive_format(names) == "docker-oci-layout"

    def test_oci_layout_without_docker_manifest(self):
        names = {"oci-layout", "index.json", "blobs/sha256/abc"}
        assert detect_archive_format(names) == "oci-layout"

    def test_docker_legacy_layout(self):
        names = {"manifest.json", "abc123/layer.tar", "abc123/json"}
        assert detect_archive_format(names) == "docker-legacy"

    def test_unknown_layout_is_refused(self):
        with pytest.raises(UnsupportedImageArchiveError):
            detect_archive_format({"random.txt", "data/file.bin"})

    def test_supported_formats_are_enumerated(self):
        assert "docker-oci-layout" in SUPPORTED_ARCHIVE_FORMATS
        assert "docker-legacy" in SUPPORTED_ARCHIVE_FORMATS


class TestUnknownFormatBlocks:
    """An archive we cannot parse must never be reported as safe."""

    def test_unknown_docker_save_format_blocks(self, tmp_path):
        archive = tmp_path / "weird.tar"
        with tarfile.open(archive, mode="w") as tar:
            _add_bytes(tar, "surprise.txt", b"not an image")

        with pytest.raises(UnsupportedImageArchiveError):
            scan_image_archive(archive)


# ---------------------------------------------------------------------------
# Whiteout / path normalisation
# ---------------------------------------------------------------------------


class TestNormalizeLayerMemberPath:
    """Member name -> container path, including whiteout decoding."""

    def test_leading_dot_slash_is_stripped(self):
        assert normalize_layer_member_path("./usr/lib/x.so") == ("/usr/lib/x.so", False)

    def test_whiteout_marker_maps_to_deleted_path(self):
        path, whiteout = normalize_layer_member_path(
            "home/dummy_user/.codex/.wh.auth.json"
        )
        assert path == "/home/dummy_user/.codex/auth.json"
        assert whiteout is True

    def test_opaque_whiteout_maps_to_directory(self):
        path, whiteout = normalize_layer_member_path(
            "home/dummy_user/.codex/.wh..wh..opq"
        )
        assert path == "/home/dummy_user/.codex"
        assert whiteout is True

    def test_traversal_member_name_is_rejected(self):
        assert normalize_layer_member_path("../../etc/passwd") == (None, False)

    def test_absolute_member_name_is_rejected(self):
        assert normalize_layer_member_path("/etc/passwd") == (None, False)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


class TestScanImageArchive:
    """Layer scanning policy."""

    def test_clean_layers_pass(self, tmp_path):
        archive = tmp_path / "clean.tar"
        build_oci_save_archive(archive, [
            CLEAN_LAYER,
            CLEAN_LAYER + ["./opt/opencv/lib/libopencv_core.so"],
        ])

        result = scan_image_archive(archive)

        assert result.performed is True
        assert result.result == "passed"
        assert result.passed is True
        assert result.layers_scanned == 2
        assert result.findings == []
        assert result.archive_format == "docker-oci-layout"
        assert result.scanner_version

    def test_secret_in_first_layer_blocks(self, tmp_path):
        archive = tmp_path / "first.tar"
        build_oci_save_archive(archive, [
            ["./home/dummy_user/.codex/auth.json"],
            CLEAN_LAYER,
            CLEAN_LAYER + ["./usr/lib/libbar.so"],
        ])

        result = scan_image_archive(archive)

        assert result.result == "failed"
        assert result.passed is False
        assert len(result.findings) == 1
        assert result.findings[0].path == "home/dummy_user/.codex/auth.json"
        assert result.findings[0].kind == "codex_credential"

    def test_secret_in_middle_layer_blocks(self, tmp_path):
        archive = tmp_path / "middle.tar"
        build_oci_save_archive(archive, [
            CLEAN_LAYER,
            ["./home/dummy_user/.claude.json"],
            CLEAN_LAYER + ["./usr/share/doc/readme"],
        ])

        result = scan_image_archive(archive)

        assert result.result == "failed"
        assert result.findings[0].kind == "claude_credential"

    def test_secret_deleted_by_later_whiteout_still_blocks(self, tmp_path):
        """`later whiteout removed it` is never a reason to allow the export."""
        archive = tmp_path / "whiteout.tar"
        build_oci_save_archive(archive, [
            CLEAN_LAYER,
            ["./home/dummy_user/.codex/auth.json"],          # created here
            ["./home/dummy_user/.codex/.wh.auth.json"],      # "removed" here
        ])

        result = scan_image_archive(archive)

        assert result.result == "failed"
        # Both the original file and the whiteout marker are reported: the
        # lower layer blob still ships the bytes.
        paths = {(f.path, f.whiteout) for f in result.findings}
        assert ("home/dummy_user/.codex/auth.json", False) in paths
        assert ("home/dummy_user/.codex/auth.json", True) in paths

    def test_root_credential_path_detected(self, tmp_path):
        archive = tmp_path / "root.tar"
        build_oci_save_archive(archive, [["./root/.ssh/id_ed25519"]])

        result = scan_image_archive(archive)

        assert result.result == "failed"
        assert result.findings[0].path == "root/.ssh/id_ed25519"
        assert result.findings[0].kind == "ssh_key"

    def test_user_credential_path_detected(self, tmp_path):
        archive = tmp_path / "user.tar"
        build_oci_save_archive(archive, [
            ["./home/dummy_user/.config/claude-bedrock/env"]
        ])

        result = scan_image_archive(archive)

        assert result.result == "failed"
        assert result.findings[0].kind == "claude_credential"

    def test_nested_secret_directory_entries_detected(self, tmp_path):
        archive = tmp_path / "nested.tar"
        build_oci_save_archive(archive, [
            ["./home/dummy_user/.claude/sessions/dummy-session.json"]
        ])

        result = scan_image_archive(archive)

        assert result.result == "failed"

    def test_legacy_layout_is_scanned(self, tmp_path):
        archive = tmp_path / "legacy.tar"
        build_legacy_save_archive(archive, [
            CLEAN_LAYER,
            ["./home/dummy_user/.aws/credentials"],
        ])

        result = scan_image_archive(archive)

        assert result.archive_format == "docker-legacy"
        assert result.layers_scanned == 2
        assert result.result == "failed"
        assert result.findings[0].kind == "aws_credential"

    def test_oci_index_layout_is_scanned(self, tmp_path):
        archive = tmp_path / "ociindex.tar"
        build_oci_index_archive(archive, [CLEAN_LAYER])

        result = scan_image_archive(archive)

        assert result.archive_format in ("oci-layout", "docker-oci-layout")
        assert result.result == "passed"

    def test_uncompressed_layer_blobs_are_scanned(self, tmp_path):
        archive = tmp_path / "plain.tar"
        build_oci_save_archive(archive, [CLEAN_LAYER], compress=False)

        result = scan_image_archive(archive)

        assert result.result == "passed"
        assert result.entries_scanned == len(CLEAN_LAYER)

    def test_findings_never_contain_file_contents(self, tmp_path):
        """Findings record identity only: layer, path, kind."""
        archive = tmp_path / "identity.tar"
        build_oci_save_archive(archive, [["./home/dummy_user/.codex/auth.json"]])

        result = scan_image_archive(archive)
        finding = result.findings[0]

        assert finding.layer.startswith("sha256:")
        assert set(vars(finding)) == {
            "layer", "path", "kind", "whiteout", "classification"
        }

    def test_traversal_member_names_are_recorded_as_anomalies(self, tmp_path):
        archive = tmp_path / "traversal.tar"
        build_oci_save_archive(archive, [["../../etc/shadow", "./usr/lib/x.so"]])

        result = scan_image_archive(archive)

        assert result.result == "passed"
        assert any("unsafe member name" in a for a in result.anomalies)
