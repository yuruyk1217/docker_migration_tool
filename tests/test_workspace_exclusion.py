"""Tests for the workspace exclusion policy and the src archive source.

Two consistency bugs are covered here:

  1. `core.*` was reported as excluded while `core.12345` was simultaneously
     listed as a large file to include (and checksummed).
  2. the dry run reported the workspace root as the archive source while the
     real archive only ever contained the authoritative `src` directory.

No secret content is used: every path below is a dummy fixture path.
"""

import io
import json
import shutil

import pytest

from docker_migration_tool.export.bundle import BundleCreator
from docker_migration_tool.inspect.workspace import (
    DEFAULT_WORKSPACE_EXCLUDES,
    GENERATED_FILE_EXCLUDES,
    discover_large_files,
    find_large_files,
    get_workspace_excludes,
    partition_large_files,
    resolve_src_archive_root,
)
from docker_migration_tool.model import LargeFile, MountInfo
from docker_migration_tool.utils.filesystem import (
    create_archive,
    is_core_dump,
    is_excluded,
    matched_exclude_pattern_for_relative,
)

from tests.test_security_metadata import make_inspection, patch_config_scan


# Well below the real 10 MB threshold so fixtures stay small
SMALL_THRESHOLD = 1024


def elf_core():
    """Minimal ELF header with little-endian ET_CORE."""
    return b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x04\x00"


@pytest.fixture
def workspace(tmp_path):
    """Build a miniature workspace that mirrors the real layout.

    workspace_root/
        docker/{Dockerfile,env.sh,docker-compose.yml,.env,
                docker-compose.override.yml}
        src/
            detector_ros/external/detector/detector.pt        <- large, included
            vision_ros/weight/best.pt               <- large, included
            example_bot/core.12345            <- large, EXCLUDED (core.*)
            package/file.py                       <- small, included
            package/build/artifact.bin            <- large, EXCLUDED (**/build)
            package/session.jsonl                 <- large, EXCLUDED (*.jsonl)
    """
    root = tmp_path / "sample_workspace"
    src = root / "src"
    docker = root / "docker"

    def write(path, size):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)

    big = SMALL_THRESHOLD * 4
    write(src / "detector_ros" / "external" / "detector" / "detector.pt", big)
    write(src / "vision_ros" / "weight" / "best.pt", big)
    (src / "example_bot").mkdir(parents=True, exist_ok=True)
    (src / "example_bot" / "core.12345").write_bytes(elf_core() + b"x" * big)
    write(src / "package" / "file.py", 10)
    write(src / "package" / "build" / "artifact.bin", big)
    write(src / "package" / "session.jsonl", big)

    write(docker / "Dockerfile", 10)
    write(docker / "env.sh", 10)
    write(docker / "docker-compose.yml", 10)
    write(docker / ".env", 10)
    write(docker / "docker-compose.override.yml", 10)

    return root


class TestExclusionPolicySource:
    """The policy must have exactly one definition."""

    def test_policy_contains_required_patterns(self):
        excludes = get_workspace_excludes()
        for pattern in ("**/__pycache__", "**/build", "**/install", "**/log",
                        "core_dump", "*.jsonl"):
            assert pattern in excludes
        assert "core.*" not in excludes

    def test_generated_files_are_part_of_the_policy(self):
        excludes = get_workspace_excludes()
        for pattern in (".env", "docker-compose.override.yml",
                        "compose.generated.yml", ".docker.xauth",
                        "robotics-xauthority"):
            assert pattern in excludes

    def test_accessor_returns_a_copy(self):
        excludes = get_workspace_excludes()
        excludes.append("scribbled-on")
        assert "scribbled-on" not in DEFAULT_WORKSPACE_EXCLUDES
        assert "scribbled-on" not in GENERATED_FILE_EXCLUDES

    def test_core_dump_requires_file_inspection(self, workspace):
        assert matched_exclude_pattern_for_relative(
            "example_bot/core.12345", get_workspace_excludes()
        ) is None
        assert is_excluded(workspace / "src/example_bot/core.12345",
                           workspace / "src", get_workspace_excludes())
        assert not is_excluded(workspace / "src/example_bot/core.12345",
                               workspace / "src", [])

    @pytest.mark.parametrize("name", ["core.py", "core.cpp", "core.cc", "core.c",
        "core.h", "core.hpp", "core.rs", "core.go", "core.java", "core.js",
        "core.ts", "core.md", "core.txt", "core.yaml", "core.yml",
        "core.json", "core.xml", "core.launch.py", "core.sh"])
    def test_source_named_core_is_preserved(self, tmp_path, name):
        source = tmp_path / "src"
        path = source / "example_pkg" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ordinary source\n")
        assert matched_exclude_pattern_for_relative(
            f"example_pkg/{name}", get_workspace_excludes()) is None
        assert not is_excluded(path, source, get_workspace_excludes())

    @pytest.mark.parametrize("name", ["core", "core.12345"])
    def test_elf_core_is_excluded(self, tmp_path, name):
        path = tmp_path / name
        path.write_bytes(elf_core())
        assert is_core_dump(path)
        assert is_excluded(path, tmp_path, get_workspace_excludes())

    def test_text_with_core_pid_name_is_preserved(self, tmp_path):
        path = tmp_path / "core.12345"
        path.write_text("ordinary text\n")
        assert not is_core_dump(path)
        assert not is_excluded(path, tmp_path, get_workspace_excludes())

    def test_non_core_elf_and_symlink_are_preserved(self, tmp_path):
        executable = tmp_path / "core"
        executable.write_bytes(elf_core()[:16] + b"\x02\x00")
        assert not is_core_dump(executable)
        target = tmp_path / "elsewhere"
        target.write_bytes(elf_core())
        link = tmp_path / "core.12345"
        link.symlink_to(target)
        assert not is_core_dump(link)

    def test_unreadable_header_is_preserved(self, tmp_path, monkeypatch):
        path = tmp_path / "core.12345"
        path.write_bytes(elf_core())
        original_open = type(path).open

        def deny_candidate(candidate, *args, **kwargs):
            if candidate == path:
                raise PermissionError("fixture")
            return original_open(candidate, *args, **kwargs)

        monkeypatch.setattr(type(path), "open", deny_candidate)
        assert not is_core_dump(path)

    def test_archive_and_audit(self, tmp_path):
        import tarfile
        source = tmp_path / "src" / "example_pkg"
        source.mkdir(parents=True)
        for name in ("core.py", "core.cpp", "core.hpp", "core.md",
                     "core.yaml", "core.launch.py"):
            (source / name).write_text("source\n")
        (source / "core.12345").write_bytes(elf_core())
        (source / "core").write_bytes(elf_core())
        (source / "core.67890").write_text("ordinary text\n")
        (source / "build").mkdir()
        (source / "build" / "small.bin").write_bytes(b"x")
        archive = tmp_path / "src.tar"
        excluded = create_archive(tmp_path / "src", archive,
                                  excludes=get_workspace_excludes(), compression="none")
        with tarfile.open(archive) as tar:
            names = set(tar.getnames())
        for name in ("core.py", "core.cpp", "core.hpp", "core.md",
                     "core.yaml", "core.launch.py", "core.67890"):
            assert f"example_pkg/{name}" in names
        assert "example_pkg/core" not in names
        assert "example_pkg/core.12345" not in names
        by_path = {entry["path"]: entry for entry in excluded}
        assert by_path["example_pkg/core.12345"]["excluded_by"] == "core_dump"
        assert by_path["example_pkg/core.12345"]["size"] < 10 * 1024 * 1024
        assert by_path["example_pkg/build/small.bin"]["excluded_by"] == "**/build"
        assert "example_pkg/core.py" not in by_path

    def test_big_endian_elf_core_is_excluded(self, tmp_path):
        path = tmp_path / "core.433778"
        path.write_bytes(b"\x7fELF\x02\x02\x01" + b"\x00" * 9 + b"\x00\x04")
        assert is_core_dump(path)

    def test_truncated_elf_header_is_preserved(self, tmp_path):
        path = tmp_path / "core.12345"
        path.write_bytes(b"\x7fELF")
        assert not is_core_dump(path)

    def test_incident_path_so101_core_py_is_preserved(self, tmp_path):
        """Regression: so101_demo/core.py was silently dropped by `core.*`."""
        source = tmp_path / "src"
        path = source / "so101_demo" / "core.py"
        path.parent.mkdir(parents=True)
        path.write_text("def run():\n    pass\n")
        assert matched_exclude_pattern_for_relative(
            "so101_demo/core.py", get_workspace_excludes()) is None
        assert not is_excluded(path, source, get_workspace_excludes())

    @pytest.mark.skipif(shutil.which("zstd") is None, reason="zstd not installed")
    def test_zstd_archive_listing(self, tmp_path):
        """Integration with the real export format (src.tar.zst)."""
        import subprocess
        import tarfile
        source = tmp_path / "src" / "example_pkg"
        source.mkdir(parents=True)
        (source / "core.py").write_text("source\n")
        (source / "core.cpp").write_text("int main() { return 0; }\n")
        (source / "core.12345").write_bytes(elf_core())
        archive = tmp_path / "src.tar.zst"
        create_archive(tmp_path / "src", archive, excludes=get_workspace_excludes())
        listing = subprocess.run(["zstd", "-d", "-c", str(archive)],
                                 check=True, capture_output=True).stdout
        with tarfile.open(fileobj=io.BytesIO(listing)) as tar:
            names = set(tar.getnames())
        assert "example_pkg/core.py" in names
        assert "example_pkg/core.cpp" in names
        assert "example_pkg/core.12345" not in names

    def test_audit_records_metadata_only(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / ".env").write_text("DUMMY_TOKEN=fixture-value-not-a-secret\n")
        (source / "core").write_bytes(elf_core())
        excluded = create_archive(source, tmp_path / "src.tar",
                                  excludes=get_workspace_excludes(), compression="none")
        assert {entry["path"] for entry in excluded} == {".env", "core"}
        for entry in excluded:
            assert set(entry) == {"path", "size", "excluded_by", "reason"}
        assert "fixture-value" not in json.dumps(excluded)

    def test_model_weight_is_not_excluded(self):
        assert matched_exclude_pattern_for_relative(
            "detector_ros/external/detector/detector.pt", get_workspace_excludes()
        ) is None

    def test_build_directory_excluded_but_similar_name_kept(self):
        excludes = get_workspace_excludes()
        assert matched_exclude_pattern_for_relative(
            "package/build/artifact.bin", excludes) == "**/build"
        # A file whose name merely contains "build" must survive
        assert matched_exclude_pattern_for_relative(
            "package/rebuild_tool.py", excludes) is None
        assert matched_exclude_pattern_for_relative(
            "_container_setup/install_workspace_dependencies.sh", excludes) is None


class TestLargeFileDiscovery:
    """Exclusion policy runs before large-file judgement and checksums."""

    def test_core_dump_is_excluded_from_include_list(self, workspace):
        discovery = discover_large_files(
            workspace / "src", threshold=SMALL_THRESHOLD
        )
        included = [lf.path for lf in discovery.included]
        assert not any("core.12345" in path for path in included)

    def test_core_dump_is_recorded_as_excluded_with_pattern(self, workspace):
        discovery = discover_large_files(
            workspace / "src", threshold=SMALL_THRESHOLD
        )
        excluded = {ex.path: ex.excluded_by for ex in discovery.excluded}
        assert "example_bot/core.12345" in excluded
        assert excluded["example_bot/core.12345"] == "core_dump"

    def test_excluded_large_file_has_no_checksum(self, workspace):
        discovery = discover_large_files(
            workspace / "src", threshold=SMALL_THRESHOLD, compute_checksums=True
        )
        # An excluded file is audit-only: the record cannot even hold a checksum
        for ex in discovery.excluded:
            assert not hasattr(ex, "sha256")
        # ... and it is absent from every checksummed record
        for lf in discovery.included:
            assert "core.12345" not in lf.path
            assert lf.sha256 is not None

    def test_model_weight_stays_included(self, workspace):
        included = find_large_files(
            workspace / "src", threshold=SMALL_THRESHOLD, compute_checksums=False
        )
        paths = [lf.path for lf in included]
        assert "detector_ros/external/detector/detector.pt" in paths

    def test_yolo_weight_stays_included(self, workspace):
        included = find_large_files(
            workspace / "src", threshold=SMALL_THRESHOLD, compute_checksums=False
        )
        paths = [lf.path for lf in included]
        assert "vision_ros/weight/best.pt" in paths

    def test_build_and_jsonl_are_excluded(self, workspace):
        discovery = discover_large_files(
            workspace / "src", threshold=SMALL_THRESHOLD, compute_checksums=False
        )
        included = [lf.path for lf in discovery.included]
        # build/ is pruned as a directory, so its contents are never sized
        assert not any("build/artifact.bin" in path for path in included)
        assert not any(path.endswith(".jsonl") for path in included)
        # A file-level exclusion is recorded with the pattern that matched
        by_pattern = {ex.excluded_by for ex in discovery.excluded}
        assert "*.jsonl" in by_pattern
        assert not any("build/artifact.bin" in ex.path for ex in discovery.excluded)

    def test_partition_re_applies_policy_to_an_existing_list(self, workspace):
        included, excluded = partition_large_files([
            LargeFile(path="example_bot/core.12345", size_bytes=531_000_000),
            LargeFile(path="detector_ros/external/detector/detector.pt", size_bytes=3_371_000_000),
        ], src_path=workspace / "src")
        assert [lf.path for lf in included] == ["detector_ros/external/detector/detector.pt"]
        assert [ex.path for ex in excluded] == ["example_bot/core.12345"]
        assert excluded[0].excluded_by == "core_dump"


class TestDryRunAndExportShareOnePolicy:
    """Dry-run display, real archive, discovery and checksums agree."""

    def test_creator_uses_the_shared_policy(self, tmp_path):
        creator = BundleCreator(make_inspection(), tmp_path / "bundle",
                                dry_run=True)
        assert creator.excludes == get_workspace_excludes()

    def test_export_records_every_excluded_file(self, tmp_path):
        source = tmp_path / "workspace" / "src" / "example_pkg"
        source.mkdir(parents=True)
        (source / "core.py").write_text("source\n")
        (source / "core.12345").write_bytes(elf_core())
        (source / "session.jsonl").write_text("{}\n")
        inspection = make_inspection()
        inspection.workspace_path = str(tmp_path / "workspace")
        output = tmp_path / "bundle"
        creator = BundleCreator(inspection, output)
        creator._create_bundle_structure()
        creator._export_workspace()
        audit = json.loads((output / "workspace" / "EXCLUDED_FILES.json").read_text())
        by_path = {entry["path"]: entry for entry in audit["files"]}
        assert audit["schema_version"] == "1.0.0"
        assert "workspace/EXCLUDED_FILES.json" in creator.manifest.checksums
        assert by_path["example_pkg/core.12345"]["excluded_by"] == "core_dump"
        assert by_path["example_pkg/core.12345"]["size"] == len(elf_core())
        assert by_path["example_pkg/session.jsonl"]["excluded_by"] == "*.jsonl"
        assert "example_pkg/core.py" not in by_path

    def test_dry_run_does_not_list_excluded_large_file(self, workspace,
                                                      monkeypatch, capsys):
        from docker_migration_tool.export import bundle as bundle_module

        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda i: [])
        patch_config_scan(monkeypatch)

        inspection = make_inspection()
        inspection.workspace_path = str(workspace)
        discovery = discover_large_files(
            workspace / "src", threshold=SMALL_THRESHOLD, compute_checksums=False
        )
        inspection.large_files = discovery.included
        inspection.excluded_large_files = discovery.excluded

        BundleCreator(inspection, workspace.parent / "bundle",
                      dry_run=True).create()
        output = capsys.readouterr().out

        include_block = output.split("Large files to include:")[1]
        include_block = include_block.split("Large files EXCLUDED")[0]
        assert "detector.pt" in include_block
        assert "core.12345" not in include_block
        # The audit line may name it, but only as excluded
        assert "core.12345" not in output or "excluded_by: core_dump" in output

    def test_real_archive_and_dry_run_use_identical_excludes(self, workspace,
                                                            monkeypatch):
        from docker_migration_tool.export import bundle as bundle_module

        seen = {}

        def fake_create_archive(source, archive_path, excludes=None,
                                compression="zst", included_files=None):
            seen["source"] = source
            seen["excludes"] = list(excludes or [])
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            archive_path.write_bytes(b"fake archive")

        monkeypatch.setattr(bundle_module, "create_archive", fake_create_archive)

        inspection = make_inspection()
        inspection.workspace_path = str(workspace)
        inspection.large_files = [
            LargeFile(path="detector_ros/external/detector/detector.pt", size_bytes=3_371_000_000),
            LargeFile(path="example_bot/core.12345", size_bytes=531_000_000),
        ]

        creator = BundleCreator(inspection, workspace.parent / "bundle")
        creator._create_bundle_structure()
        creator._export_workspace()

        assert seen["excludes"] == get_workspace_excludes()
        assert seen["excludes"] == creator.excludes

        # LARGE_FILES.json is written from the same policy
        recorded = json.loads(
            (workspace.parent / "bundle" / "workspace" / "LARGE_FILES.json").read_text()
        )
        paths = [entry["path"] for entry in recorded]
        assert "detector_ros/external/detector/detector.pt" in paths
        assert "example_bot/core.12345" not in paths

        audit = json.loads(
            (workspace.parent / "bundle" / "workspace"
             / "EXCLUDED_LARGE_FILES.json").read_text()
        )
        assert audit[0]["path"] == "example_bot/core.12345"
        assert audit[0]["excluded_by"] == "core_dump"


class TestSrcArchiveSource:
    """workspace/src.tar.zst comes from the authoritative src directory."""

    def test_bind_mount_is_preferred(self, workspace):
        resolved = resolve_src_archive_root(workspace, workspace / "src")
        assert resolved == workspace / "src"

    def test_workspace_root_is_never_the_archive_root(self, workspace):
        resolved = resolve_src_archive_root(workspace)
        assert resolved == workspace / "src"
        assert resolved != workspace

    def test_missing_src_returns_none(self, tmp_path):
        assert resolve_src_archive_root(tmp_path / "no_such_ws") is None

    def test_creator_resolves_detected_bind_mount(self, workspace):
        inspection = make_inspection()
        inspection.workspace_path = str(workspace)
        inspection.mounts = [
            MountInfo(
                host_source=str(workspace / "src"),
                container_target="/home/dummy_user/colcon_ws/src",
                mode="rw",
                mount_type="bind",
                is_workspace=True,
            ),
            MountInfo(
                host_source="/tmp/.X11-unix",
                container_target="/tmp/.X11-unix",
                mode="rw",
                mount_type="bind",
            ),
        ]

        creator = BundleCreator(inspection, workspace.parent / "bundle")
        assert creator._resolve_src_archive_root() == workspace / "src"

    def test_archive_source_is_src_not_root(self, workspace, monkeypatch):
        from docker_migration_tool.export import bundle as bundle_module

        seen = {}

        def fake_create_archive(source, archive_path, excludes=None,
                                compression="zst", included_files=None):
            seen["source"] = source
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            archive_path.write_bytes(b"fake archive")

        monkeypatch.setattr(bundle_module, "create_archive", fake_create_archive)

        inspection = make_inspection()
        inspection.workspace_path = str(workspace)

        creator = BundleCreator(inspection, workspace.parent / "bundle")
        creator._create_bundle_structure()
        creator._export_workspace()

        assert seen["source"] == workspace / "src"
        assert seen["source"] != workspace

    def test_generated_files_cannot_enter_the_src_archive(self, workspace):
        """.env and the compose override live outside src and are excluded."""
        from docker_migration_tool.utils.filesystem import create_archive
        import tarfile

        # Simulate a workspace that (wrongly) carries generated files in src
        (workspace / "src" / ".env").write_text("LOCAL_UID=1000\n")
        (workspace / "src" / "docker-compose.override.yml").write_text("services:\n")

        archive = workspace.parent / "src.tar"
        create_archive(workspace / "src", archive,
                       excludes=get_workspace_excludes(), compression="none")

        with tarfile.open(archive) as tar:
            names = tar.getnames()

        assert not any(name.endswith(".env") for name in names)
        assert not any("docker-compose.override.yml" in name for name in names)
        assert not any("core.12345" in name for name in names)
        assert any(name.endswith("detector.pt") for name in names)
        # The archive root is src, so no docker/ config leaks in
        assert not any(name.startswith("docker/") for name in names)

    def test_portable_config_is_handled_by_the_config_collector(self, workspace):
        """Docker config is collected separately, not via the src archive."""
        from docker_migration_tool.inspect.workspace import inspect_docker_config

        config = inspect_docker_config(workspace / "docker")

        assert config.dockerfile_path == str(workspace / "docker" / "Dockerfile")
        assert config.env_sh_path == str(workspace / "docker" / "env.sh")
        assert config.compose_yml_path == str(
            workspace / "docker" / "docker-compose.yml"
        )
        # Generated files are never presented as portable config
        for value in vars(config).values():
            if isinstance(value, str):
                assert not value.endswith("/.env")
                assert not value.endswith("docker-compose.override.yml")

    def test_dry_run_reports_the_real_archive_source(self, workspace,
                                                    monkeypatch, capsys):
        from docker_migration_tool.export import bundle as bundle_module

        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda i: [])
        patch_config_scan(monkeypatch)

        inspection = make_inspection()
        inspection.workspace_path = str(workspace)

        creator = BundleCreator(inspection, workspace.parent / "bundle",
                                dry_run=True)
        creator.create()
        output = capsys.readouterr().out

        assert "Would archive workspace src:" in output
        assert str(workspace / "src") in output
        assert str(creator._resolve_src_archive_root()) in output
