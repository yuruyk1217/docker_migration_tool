"""Tests for security check reporting: scope must match what actually ran.

A dry run performs only the final-filesystem secret path scan; the full
image-layer scan needs a `docker save` archive that a dry run never creates.
The log must therefore never make a blanket "clean image passed security scan"
claim before the layer scan has passed.

Assertions here match on meaning (scope words, per-check state) rather than on
exact sentences, so wording can be reworded without breaking the suite.
"""

import pytest

from docker_migration_tool.export.bundle import BundleCreator
from docker_migration_tool.model import SecurityCheckState, SecurityStatus

from tests.test_layer_scan import CLEAN_LAYER, build_oci_save_archive
from tests.test_security_metadata import make_inspection, patch_config_scan


BLANKET_CLAIM = "clean image passed security scan"


def dry_run_output(tmp_path, monkeypatch, capsys) -> tuple[str, BundleCreator]:
    """Run a dry-run export with docker save forbidden."""
    from docker_migration_tool.export import bundle as bundle_module

    def fail_docker_save(image, output_path, progress=False):
        raise AssertionError("docker save must not run during a dry run")

    monkeypatch.setattr(bundle_module, "docker_save", fail_docker_save)
    monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda image: [])
    patch_config_scan(monkeypatch)

    creator = BundleCreator(make_inspection(), tmp_path / "bundle", dry_run=True)
    creator.create()
    return capsys.readouterr().out, creator


class TestSecurityStatusModel:
    """The two checks are tracked separately."""

    def test_defaults_are_not_performed(self):
        status = SecurityStatus()
        assert status.config_metadata_scan == "not_performed"
        assert status.final_filesystem_scan == "not_performed"
        assert status.layer_scan == "not_performed"
        assert status.all_required_checks_passed is False

    def test_final_filesystem_pass_alone_is_not_enough(self):
        status = SecurityStatus(
            config_metadata_scan=SecurityCheckState.PASSED.value,
            final_filesystem_scan=SecurityCheckState.PASSED.value,
            layer_scan=SecurityCheckState.SKIPPED_DRY_RUN.value,
        )
        assert status.all_required_checks_passed is False

    def test_path_scans_alone_are_not_enough(self):
        """A credential in the image config is not visible to the path scans."""
        status = SecurityStatus(
            final_filesystem_scan=SecurityCheckState.PASSED.value,
            layer_scan=SecurityCheckState.PASSED.value,
        )
        assert status.config_metadata_scan == "not_performed"
        assert status.all_required_checks_passed is False

    def test_all_three_passed_is_enough(self):
        status = SecurityStatus(
            config_metadata_scan=SecurityCheckState.PASSED.value,
            final_filesystem_scan=SecurityCheckState.PASSED.value,
            layer_scan=SecurityCheckState.PASSED.value,
        )
        assert status.all_required_checks_passed is True


class TestDryRunSecurityDisplay:
    """Dry-run output must state the scope of what it actually scanned."""

    def test_no_blanket_success_claim(self, tmp_path, monkeypatch, capsys):
        output, _ = dry_run_output(tmp_path, monkeypatch, capsys)
        assert BLANKET_CLAIM not in output.lower()
        assert "passed all required security checks" not in output.lower()

    def test_final_filesystem_scan_pass_is_explicit(self, tmp_path, monkeypatch,
                                                    capsys):
        output, _ = dry_run_output(tmp_path, monkeypatch, capsys)
        lower = output.lower()
        assert "final-filesystem" in lower or "final filesystem" in lower
        # reported as a pass, with its scope named
        assert "passed" in lower

    def test_layer_scan_skip_is_explicit(self, tmp_path, monkeypatch, capsys):
        output, _ = dry_run_output(tmp_path, monkeypatch, capsys)
        lower = output.lower()
        assert "skip" in lower
        skip_lines = [line for line in output.splitlines()
                      if "skip" in line.lower()]
        assert any("layer" in line.lower() for line in skip_lines)

    def test_unverified_safety_is_explicit(self, tmp_path, monkeypatch, capsys):
        output, _ = dry_run_output(tmp_path, monkeypatch, capsys)
        lower = output.lower()
        assert "not fully verified" in lower or "!= export safety verified" in lower

    def test_internal_state_matches_the_log(self, tmp_path, monkeypatch, capsys):
        output, creator = dry_run_output(tmp_path, monkeypatch, capsys)
        assert creator.security_status.config_metadata_scan == "passed"
        assert creator.security_status.final_filesystem_scan == "passed"
        assert creator.security_status.layer_scan == "skipped_dry_run"
        assert creator.security_status.all_required_checks_passed is False
        # The same states appear in the report
        assert "config_metadata_scan:  passed" in output
        assert "final_filesystem_scan: passed" in output
        assert "skipped_dry_run" in output

    def test_manifest_records_the_final_filesystem_verdict(self, tmp_path,
                                                           monkeypatch, capsys):
        _, creator = dry_run_output(tmp_path, monkeypatch, capsys)
        assert creator.manifest.final_filesystem_scan_result == "passed"
        # ... without inflating the layer scan metadata the import gate uses
        assert creator.manifest.layer_secret_scan is False
        assert creator.manifest.layer_secret_scan_result == "not_performed"


class TestRealExportSecurityDisplay:
    """A blanket success claim is allowed only after the layer scan passes."""

    @staticmethod
    def _export(tmp_path, monkeypatch, layers):
        from docker_migration_tool.export import bundle as bundle_module

        def fake_docker_save(image, output_path, progress=False):
            build_oci_save_archive(output_path, layers)

        monkeypatch.setattr(bundle_module, "docker_save", fake_docker_save)
        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda i: [])
        patch_config_scan(monkeypatch)

        creator = BundleCreator(make_inspection(), tmp_path / "bundle")
        creator._initialize_manifest()
        creator._scan_image_config_metadata()
        creator._security_scan_image()
        creator._create_bundle_structure()
        creator._export_image()
        return creator

    def test_blanket_claim_only_after_layer_scan(self, tmp_path, monkeypatch,
                                                 capsys):
        creator = self._export(tmp_path, monkeypatch, [CLEAN_LAYER])
        output = capsys.readouterr().out

        assert creator.security_status.all_required_checks_passed is True
        assert "passed all required security checks" in output.lower()

        # Ordering: the blanket claim must come after the layer scan result
        lower = output.lower()
        assert lower.index("full image-layer secret scan passed") < lower.index(
            "passed all required security checks"
        )
        assert BLANKET_CLAIM not in lower

    def test_final_filesystem_scan_alone_makes_no_blanket_claim(
        self, tmp_path, monkeypatch, capsys,
    ):
        from docker_migration_tool.export import bundle as bundle_module

        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda i: [])

        creator = BundleCreator(make_inspection(), tmp_path / "bundle")
        creator._security_scan_image()
        output = capsys.readouterr().out

        assert BLANKET_CLAIM not in output.lower()
        assert "passed all required security checks" not in output.lower()
        assert creator.security_status.layer_scan == "not_performed"

    def test_secret_layer_leaves_status_failed(self, tmp_path, monkeypatch,
                                               capsys):
        from docker_migration_tool.export.bundle import ExportBlockedError

        secret_layer = CLEAN_LAYER + ["./home/dummy_user/.codex/auth.json"]

        with pytest.raises(ExportBlockedError):
            self._export(tmp_path, monkeypatch, [secret_layer])

        output = capsys.readouterr().out
        assert "passed all required security checks" not in output.lower()
