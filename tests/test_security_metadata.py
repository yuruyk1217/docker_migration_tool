"""Tests for export security metadata, the import gate and dry-run safety."""

import json
from dataclasses import asdict

import pytest

from docker_migration_tool.export.bundle import BundleCreator, ExportBlockedError
from docker_migration_tool.importers.preflight import PreflightChecker
from docker_migration_tool.model import (
    BundleManifest,
    ContainerInfo,
    ImageConfigScanResult,
    ImageInfo,
    InspectionResult,
    LayerScanResult,
    LayerSecretFinding,
    ParentRelationship,
)

from tests.test_layer_scan import CLEAN_LAYER, build_oci_save_archive


RUNTIME_LAYERS = [f"sha256:{i:064x}" for i in range(1, 27)]   # 26 layers
CLEAN_LAYERS = RUNTIME_LAYERS[:-1]                            # 25 layers


def passing_config_scan() -> ImageConfigScanResult:
    """A clean image config/history scan verdict."""
    return ImageConfigScanResult(
        performed=True,
        result="passed",
        scanner_version="1.0.0",
        env_vars_scanned=51,
        labels_scanned=4,
        history_entries_scanned=117,
        message="no credential-like items",
    )


def patch_config_scan(monkeypatch, result: ImageConfigScanResult | None = None):
    """Stub the image config/history scan.

    The real scan calls `docker image inspect` / `docker history`, which the
    fixture images in these tests do not have. Tests that exercise the scan
    itself call the scanner directly (see tests/test_image_config_scan.py).
    """
    from docker_migration_tool.export import bundle as bundle_module

    verdict = result if result is not None else passing_config_scan()
    monkeypatch.setattr(bundle_module, "scan_image_config", lambda image: verdict)
    return verdict


def make_inspection() -> InspectionResult:
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
            name="dummy_ws-gpu",
            container_id="abc123",
            image=runtime.reference,
            image_id=runtime.image_id,
            state="running",
            created="2026-09-17T00:00:00Z",
            user="1000:1000",
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
        workspace_path="/tmp/dummy_workspace",
    )


class TestSecurityMetadataSerialization:
    """Manifest security fields must serialize and default to "unsafe"."""

    def test_defaults_are_unverified(self):
        manifest = BundleManifest()
        assert manifest.parent_relationship_verified is False
        assert manifest.layer_secret_scan is False
        assert manifest.layer_secret_scan_result == "not_performed"

    def test_fields_round_trip_through_json(self):
        manifest = BundleManifest(
            parent_relationship_verified=True,
            parent_relationship_method="rootfs_layer_prefix",
            runtime_layer_count=26,
            clean_image_layer_count=25,
            layer_secret_scan=True,
            layer_secret_scan_result="passed",
            scanner_version="1.1.0",
        )

        data = json.loads(json.dumps(asdict(manifest)))

        assert data["parent_relationship_verified"] is True
        assert data["parent_relationship_method"] == "rootfs_layer_prefix"
        assert data["runtime_layer_count"] == 26
        assert data["clean_image_layer_count"] == 25
        assert data["layer_secret_scan"] is True
        assert data["layer_secret_scan_result"] == "passed"
        assert data["scanner_version"] == "1.1.0"

    def test_layer_scan_result_passed_property(self):
        assert LayerScanResult(performed=True, result="passed").passed is True
        assert LayerScanResult(performed=True, result="failed").passed is False
        assert LayerScanResult(performed=False, result="passed").passed is False

    def test_finding_records_identity_only(self):
        finding = LayerSecretFinding(
            layer="sha256:" + "a" * 64,
            path="home/dummy_user/.codex/auth.json",
            kind="codex_credential",
        )
        assert asdict(finding)["path"] == "home/dummy_user/.codex/auth.json"
        assert "content" not in asdict(finding)


class TestExportImageMetadata:
    """The single-save export path writes the verdict into the bundle."""

    @staticmethod
    def _creator(tmp_path, monkeypatch, layers):
        from docker_migration_tool.export import bundle as bundle_module

        def fake_docker_save(image, output_path, progress=False):
            build_oci_save_archive(output_path, layers)

        monkeypatch.setattr(bundle_module, "docker_save", fake_docker_save)

        creator = BundleCreator(make_inspection(), tmp_path / "bundle")
        creator._initialize_manifest()
        creator._create_bundle_structure()
        return creator

    def test_clean_image_records_passed_metadata(self, tmp_path, monkeypatch):
        creator = self._creator(tmp_path, monkeypatch, [CLEAN_LAYER])
        creator._export_image()

        assert creator.manifest.parent_relationship_verified is True
        assert creator.manifest.runtime_layer_count == 26
        assert creator.manifest.clean_image_layer_count == 25
        assert creator.manifest.layer_secret_scan is True
        assert creator.manifest.layer_secret_scan_result == "passed"
        assert creator.manifest.scanner_version

        info = json.loads(
            (tmp_path / "bundle" / "docker" / "image" / "IMAGE_INFO.json").read_text()
        )
        assert info["parent_relationship_verified"] is True
        assert info["layer_secret_scan_result"] == "passed"
        assert info["runtime_layer_count"] == 26
        assert info["clean_image_layer_count"] == 25
        assert info["archive_format"] == "docker-oci-layout"

        assert (tmp_path / "bundle" / "docker" / "image" / "base-image.tar").exists()

    def test_secret_layer_blocks_and_removes_archive(self, tmp_path, monkeypatch):
        creator = self._creator(tmp_path, monkeypatch, [
            ["./home/dummy_user/.codex/auth.json"],
        ])

        with pytest.raises(ExportBlockedError):
            creator._export_image()

        assert creator.manifest.layer_secret_scan_result == "failed"
        # The archive may contain credential bytes: it must not be left behind
        assert not (tmp_path / "bundle" / "docker" / "image" / "base-image.tar").exists()

    def test_unsupported_format_blocks_export(self, tmp_path, monkeypatch):
        from docker_migration_tool.export import bundle as bundle_module
        import tarfile

        def fake_docker_save(image, output_path, progress=False):
            with tarfile.open(output_path, mode="w") as tar:
                info = tarfile.TarInfo("surprise.txt")
                info.size = 0
                tar.addfile(info)

        monkeypatch.setattr(bundle_module, "docker_save", fake_docker_save)

        creator = BundleCreator(make_inspection(), tmp_path / "bundle")
        creator._initialize_manifest()
        creator._create_bundle_structure()

        with pytest.raises(ExportBlockedError, match="unsupported image archive format"):
            creator._export_image()

        assert creator.manifest.layer_secret_scan_result == "unsupported_format"
        assert not (tmp_path / "bundle" / "docker" / "image" / "base-image.tar").exists()


class TestParentRelationshipGate:
    """Export is blocked unless the layer relationship is proven."""

    def test_unverified_relationship_blocks_export(self, tmp_path):
        inspection = make_inspection()
        inspection.parent_relationship.verified = False
        inspection.parent_relationship.relationship = "not_prefix"

        creator = BundleCreator(inspection, tmp_path / "bundle", dry_run=True)

        with pytest.raises(ExportBlockedError,
                           match="Unable to prove clean parent image relationship"):
            creator.create()

    def test_missing_clean_image_blocks_export(self, tmp_path):
        inspection = make_inspection()
        inspection.clean_base_image = None

        creator = BundleCreator(inspection, tmp_path / "bundle", dry_run=True)

        with pytest.raises(ExportBlockedError):
            creator.create()


class TestDryRunSafety:
    """A dry run must not save the multi-GB image."""

    def test_dry_run_does_not_docker_save(self, tmp_path, monkeypatch, capsys):
        from docker_migration_tool.export import bundle as bundle_module

        def fail_docker_save(image, output_path, progress=False):
            raise AssertionError("docker save must not run during a dry run")

        monkeypatch.setattr(bundle_module, "docker_save", fail_docker_save)
        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda image: [])
        patch_config_scan(monkeypatch)

        creator = BundleCreator(make_inspection(), tmp_path / "bundle", dry_run=True)
        creator.create()

        output = capsys.readouterr().out
        # Match on meaning, not on an exact sentence: the layer scan must be
        # reported as skipped and the dry run must not claim verified safety.
        lower = output.lower()
        assert "skip" in lower and "layer" in lower
        assert "not fully verified" in lower or "!= export safety verified" in lower
        assert not (tmp_path / "bundle").exists()
        assert creator.manifest.layer_secret_scan is False
        assert creator.manifest.layer_secret_scan_result == "not_performed"
        assert creator.security_status.layer_scan == "skipped_dry_run"

    def test_dry_run_reports_layer_counts(self, tmp_path, monkeypatch, capsys):
        from docker_migration_tool.export import bundle as bundle_module

        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda image: [])
        patch_config_scan(monkeypatch)

        creator = BundleCreator(make_inspection(), tmp_path / "bundle", dry_run=True)
        creator.create()

        output = capsys.readouterr().out
        assert "Runtime layer count:      26" in output
        assert "Clean image layer count:  25" in output
        assert "strict_prefix" in output


def write_bundle(tmp_path, manifest: dict, image_info: dict | None = None):
    """Create a minimal bundle directory with the given metadata."""
    bundle = tmp_path / "bundle"
    (bundle / "docker" / "image").mkdir(parents=True)
    (bundle / "MANIFEST.json").write_text(json.dumps(manifest))
    if image_info is not None:
        (bundle / "docker" / "image" / "IMAGE_INFO.json").write_text(
            json.dumps(image_info)
        )
    return bundle


PASSING_METADATA = {
    "schema_version": "1.0.0",
    "parent_relationship_verified": True,
    "parent_relationship_method": "rootfs_layer_prefix",
    "runtime_layer_count": 26,
    "clean_image_layer_count": 25,
    "layer_secret_scan": True,
    "layer_secret_scan_result": "passed",
    "scanner_version": "1.1.0",
    "image_config_scan": True,
    "image_config_scan_result": "passed",
    "config_scanner_version": "1.0.0",
}


class TestImportSecurityGate:
    """Import refuses bundles without a passing security verdict."""

    def test_passing_metadata_is_accepted(self, tmp_path):
        bundle = write_bundle(tmp_path, dict(PASSING_METADATA))
        checker = PreflightChecker(bundle)
        checker._check_bundle_security_metadata()

        assert checker.errors == []
        names = {c.name for c in checker.checks}
        assert "parent_relationship_verified" in names
        assert "layer_secret_scan" in names

    def test_rejects_bundle_without_successful_layer_scan(self, tmp_path):
        manifest = dict(PASSING_METADATA)
        manifest["layer_secret_scan"] = False
        manifest["layer_secret_scan_result"] = "not_performed"

        checker = PreflightChecker(write_bundle(tmp_path, manifest))
        checker._check_bundle_security_metadata()

        assert any("layer_secret_scan_result" in e for e in checker.errors)

    def test_rejects_bundle_with_failed_layer_scan(self, tmp_path):
        manifest = dict(PASSING_METADATA)
        manifest["layer_secret_scan_result"] = "failed"

        checker = PreflightChecker(write_bundle(tmp_path, manifest))
        checker._check_bundle_security_metadata()

        assert any("layer_secret_scan_result" in e for e in checker.errors)

    def test_rejects_unverified_parent_relationship(self, tmp_path):
        manifest = dict(PASSING_METADATA)
        manifest["parent_relationship_verified"] = False

        checker = PreflightChecker(write_bundle(tmp_path, manifest))
        checker._check_bundle_security_metadata()

        assert any("parent_relationship_verified" in e for e in checker.errors)

    def test_rejects_legacy_bundle_without_metadata(self, tmp_path):
        """Missing security metadata is never treated as implicitly safe."""
        checker = PreflightChecker(write_bundle(tmp_path, {
            "schema_version": "1.0.0",
            "tool_version": "1.0.0",
        }))
        checker._check_bundle_security_metadata()

        assert any("unsafe legacy bundle" in e for e in checker.errors)

    def test_image_info_json_is_used_as_fallback(self, tmp_path):
        """A bundle whose manifest lacks the fields still gets checked."""
        bundle = write_bundle(
            tmp_path,
            {"schema_version": "1.0.0"},
            image_info=dict(PASSING_METADATA),
        )
        checker = PreflightChecker(bundle)
        checker._check_bundle_security_metadata()

        assert checker.errors == []

    def test_manifest_overrides_image_info(self, tmp_path):
        bundle = write_bundle(
            tmp_path,
            {"schema_version": "1.0.0",
             "parent_relationship_verified": False,
             "layer_secret_scan_result": "passed"},
            image_info=dict(PASSING_METADATA),
        )
        checker = PreflightChecker(bundle)
        checker._check_bundle_security_metadata()

        assert any("parent_relationship_verified" in e for e in checker.errors)
