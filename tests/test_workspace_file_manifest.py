"""Tests for the per-file workspace manifest (workspace/src.sha256).

The manifest lists exactly the files placed in workspace/src.tar.zst, so
import can detect a file that was lost between export and restore, without
reporting intentionally excluded files (build output, core dumps, generated
credentials) as missing.

No secret content is used: every path below is a dummy fixture path.
"""

import json
import shutil
import tarfile

import pytest

from docker_migration_tool.export.bundle import BundleCreator
from docker_migration_tool.importers.restore import BundleRestorer
from docker_migration_tool.inspect.workspace import get_workspace_excludes
from docker_migration_tool.utils.filesystem import (
    compute_sha256_file,
    create_archive,
    read_file_manifest,
    verify_file_manifest,
    write_file_manifest,
)

from tests.test_security_metadata import make_inspection
from tests.test_workspace_exclusion import elf_core


def make_source(root):
    """src/example_pkg with sources, a core dump and regenerable output."""
    pkg = root / "example_pkg"
    pkg.mkdir(parents=True)
    (pkg / "core.py").write_text("def run():\n    pass\n")
    (pkg / "core.cpp").write_text("int main() { return 0; }\n")
    (pkg / "core.12345").write_bytes(elf_core())
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "core.cpython-312.pyc").write_bytes(b"\x00")
    (pkg / "build").mkdir()
    (pkg / "build" / "artifact.bin").write_bytes(b"x")
    (root / ".env").write_text("DUMMY=fixture\n")
    return root


class TestManifestFormat:

    def test_round_trip(self, tmp_path):
        entries = {"a/core.py": "0" * 64, "b c/d.txt": "f" * 64}
        path = tmp_path / "src.sha256"
        write_file_manifest(path, entries)
        assert path.read_text() == (f"{'0' * 64}  a/core.py\n"
                                    f"{'f' * 64}  b c/d.txt\n")
        assert read_file_manifest(path) == entries

    def test_escaped_names_round_trip(self, tmp_path):
        entries = {"odd\\name": "1" * 64, "new\nline": "2" * 64}
        path = tmp_path / "src.sha256"
        write_file_manifest(path, entries)
        assert read_file_manifest(path) == entries

    @pytest.mark.parametrize("line", [
        f"{'0' * 64}  ../escape.py",
        f"{'0' * 64}  /etc/passwd",
        "not-a-hash  file.py",
        f"{'0' * 64} single-space.py",
    ])
    def test_malformed_or_unsafe_lines_are_rejected(self, tmp_path, line):
        path = tmp_path / "src.sha256"
        path.write_text(line + "\n")
        with pytest.raises(ValueError):
            read_file_manifest(path)


class TestManifestContents:

    def test_lists_archived_files_only(self, tmp_path):
        source = make_source(tmp_path / "src")
        included = {}
        create_archive(source, tmp_path / "src.tar", excludes=get_workspace_excludes(),
                       compression="none", included_files=included)
        with tarfile.open(tmp_path / "src.tar") as tar:
            archived = {m.name for m in tar.getmembers() if m.isfile()}
        assert set(included) == archived
        assert set(included) == {"example_pkg/core.py", "example_pkg/core.cpp"}
        assert included["example_pkg/core.py"] == compute_sha256_file(
            source / "example_pkg" / "core.py")

    def test_symlinks_are_not_hashed(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "real.py").write_text("x\n")
        (source / "link.py").symlink_to("real.py")
        included = {}
        create_archive(source, tmp_path / "src.tar", compression="none",
                       included_files=included)
        assert set(included) == {"real.py"}

    def test_export_writes_checksummed_manifest(self, tmp_path):
        make_source(tmp_path / "workspace" / "src")
        inspection = make_inspection()
        inspection.workspace_path = str(tmp_path / "workspace")
        output = tmp_path / "bundle"
        creator = BundleCreator(inspection, output)
        creator._create_bundle_structure()
        creator._export_workspace()

        manifest_path = output / "workspace" / "src.sha256"
        entries = read_file_manifest(manifest_path)
        assert "example_pkg/core.py" in entries
        assert "example_pkg/core.cpp" in entries
        for excluded in ("example_pkg/core.12345", ".env",
                         "example_pkg/build/artifact.bin",
                         "example_pkg/__pycache__/core.cpython-312.pyc"):
            assert excluded not in entries
        assert creator.manifest.checksums["workspace/src.sha256"] == \
            compute_sha256_file(manifest_path)

        audit = json.loads((output / "workspace" / "EXCLUDED_FILES.json").read_text())
        audited = {entry["path"] for entry in audit["files"]}
        assert not audited & set(entries)


def make_bundle(tmp_path, *, with_file_manifest=True):
    """Minimal bundle: workspace archive, optional file manifest, MANIFEST.json."""
    source = make_source(tmp_path / "source_src")
    bundle = tmp_path / "bundle"
    (bundle / "workspace").mkdir(parents=True)
    included = {}
    create_archive(source, bundle / "workspace" / "src.tar.zst",
                   excludes=get_workspace_excludes(), included_files=included)
    checksums = {"workspace/src.tar.zst":
                 compute_sha256_file(bundle / "workspace" / "src.tar.zst")}
    if with_file_manifest:
        write_file_manifest(bundle / "workspace" / "src.sha256", included)
        checksums["workspace/src.sha256"] = compute_sha256_file(
            bundle / "workspace" / "src.sha256")
    (bundle / "MANIFEST.json").write_text(json.dumps({"checksums": checksums}))
    return bundle


def restorer_for(bundle, tmp_path):
    return BundleRestorer(bundle, target_workspace=tmp_path / "restored",
                          interactive=False)


@pytest.mark.skipif(shutil.which("zstd") is None, reason="zstd not installed")
class TestImportVerification:

    def test_complete_restore_passes(self, tmp_path):
        restorer = restorer_for(make_bundle(tmp_path), tmp_path)
        restorer._restore_workspace()
        result = restorer.verifications[-1]
        assert result.name == "workspace_restored"
        assert result.passed and result.status == "ok"
        assert (tmp_path / "restored" / "src" / "example_pkg" / "core.py").is_file()
        # Intentionally excluded files are absent and not reported missing
        assert not (tmp_path / "restored" / "src" / "example_pkg" / "core.12345").exists()

    def test_missing_file_fails_with_path(self, tmp_path):
        bundle = make_bundle(tmp_path)
        manifest = bundle / "workspace" / "src.sha256"
        entries = read_file_manifest(manifest)
        entries["so101_demo/core.py"] = "0" * 64  # listed but not in the archive
        write_file_manifest(manifest, entries)
        restorer = restorer_for(bundle, tmp_path)
        with pytest.raises(ValueError, match="so101_demo/core.py"):
            restorer._restore_workspace()
        result = restorer.verifications[-1]
        assert result.name == "workspace_restored"
        assert not result.passed
        assert result.details["missing"] == ["so101_demo/core.py"]

    def test_hash_mismatch_fails_with_path(self, tmp_path):
        bundle = make_bundle(tmp_path)
        manifest = bundle / "workspace" / "src.sha256"
        entries = read_file_manifest(manifest)
        entries["example_pkg/core.cpp"] = "0" * 64
        write_file_manifest(manifest, entries)
        restorer = restorer_for(bundle, tmp_path)
        with pytest.raises(ValueError, match="example_pkg/core.cpp"):
            restorer._restore_workspace()
        assert restorer.verifications[-1].details["mismatched"] == ["example_pkg/core.cpp"]

    def test_legacy_bundle_without_manifest_is_compatible(self, tmp_path):
        restorer = restorer_for(make_bundle(tmp_path, with_file_manifest=False),
                                tmp_path)
        restorer._restore_workspace()
        result = restorer.verifications[-1]
        assert result.passed and result.status == "warning"
        assert "legacy" in result.message

    def test_preflight_requires_manifest_when_checksummed(self, tmp_path):
        """A new bundle whose src.sha256 was removed fails preflight."""
        from docker_migration_tool.importers.preflight import PreflightChecker
        bundle = make_bundle(tmp_path)
        (bundle / "workspace" / "src.sha256").unlink()
        for name in ("docker/image", "docker/config"):
            (bundle / name).mkdir(parents=True)
        checker = PreflightChecker(bundle)
        checker._validate_bundle()
        assert "Missing file: workspace/src.sha256" in checker.errors


def test_verify_ignores_unlisted_extra_files(tmp_path):
    (tmp_path / "kept.py").write_text("x\n")
    (tmp_path / "unrelated.txt").write_text("y\n")
    entries = {"kept.py": compute_sha256_file(tmp_path / "kept.py")}
    assert verify_file_manifest(tmp_path, entries) == ([], [])
