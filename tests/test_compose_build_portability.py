"""Regression tests for Compose-built runtime portability."""

import json
from pathlib import Path

import pytest

from docker_migration_tool.inspect.compose_build import (
    BuildDependencyError, build_services, context_files, resolve_runtime_build,
)
from docker_migration_tool.importers.preflight import PreflightChecker
from docker_migration_tool.model import ImageInfo


def project(root: Path, dockerfile: str, *, image="app-user-alice-1000-1000",
            base="app:release"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: " + image + "\n"
        "    build:\n      context: .\n      dockerfile: Dockerfile.user\n"
        "      args:\n        BASE_IMAGE: " + base + "\n")
    (root / "Dockerfile.user").write_text(dockerfile)


def test_wrapper_resolves_portable_base(tmp_path, monkeypatch):
    project(tmp_path, "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n")
    runtime = ImageInfo("app-user-alice-1000-1000", "latest", "runtime",
                        rootfs_layers=["A", "B"])
    monkeypatch.setattr("docker_migration_tool.inspect.image.inspect_image",
                        lambda ref: ImageInfo("app", "release", "base", rootfs_layers=["A"]))
    resolved = resolve_runtime_build(tmp_path, runtime)
    assert resolved[0].reference == "app:release"
    assert resolved[1].verified
    assert resolved[2]["base"] == "app:release"
    from docker_migration_tool.export.bundle import BundleCreator
    from docker_migration_tool.model import InspectionResult, PortableDockerConfig
    creator = BundleCreator(InspectionResult(
        runtime_image=runtime, clean_base_image=resolved[0],
        parent_relationship=resolved[1], runtime_build=resolved[2],
        docker_config=PortableDockerConfig(compose_yml_path=str(tmp_path / "docker-compose.yml"))),
        tmp_path / "bundle")
    creator._initialize_manifest()
    assert creator.manifest.source_runtime_image == "app-user-alice-1000-1000:latest"
    assert creator.manifest.portable_base_image == "app:release"
    assert creator.manifest.runtime_image_rebuild_required
    assert creator.manifest.runtime_build_service == "app"


def test_unmatched_compose_build_does_not_silently_export_runtime(tmp_path):
    project(tmp_path, "FROM app:release\n")
    runtime = ImageInfo("other", "latest", "runtime", rootfs_layers=["A", "B"])
    with pytest.raises(BuildDependencyError, match="No Compose build output matches"):
        resolve_runtime_build(tmp_path, runtime)


def test_custom_dockerfile_and_scripts(tmp_path):
    project(tmp_path, "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
            "COPY create_user.sh /bin/\nCOPY entrypoint.sh /bin/\n")
    for name in ("create_user.sh", "entrypoint.sh"):
        (tmp_path / name).write_text("echo ok\n")
    build = build_services(tmp_path)[0]
    names = {p.name for p in context_files(build["context"], build["dockerfile"])}
    assert {"create_user.sh", "entrypoint.sh"} <= names


def test_copy_directory(tmp_path):
    project(tmp_path, "FROM app:release\nCOPY scripts/ /opt/scripts/\n")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("a.sh", "b.sh"):
        (scripts / name).write_text("echo ok\n")
    build = build_services(tmp_path)[0]
    assert {"a.sh", "b.sh"} <= {p.name for p in context_files(build["context"], build["dockerfile"])}


def test_copy_dot_filters_secrets(tmp_path):
    project(tmp_path, "FROM app:release\nCOPY . /app\n")
    (tmp_path / ".dockerignore").write_text(".env*\n")
    (tmp_path / ".env").write_text("TOKEN=hidden")
    (tmp_path / ".env.backup_1").write_text("TOKEN=old")
    (tmp_path / "app.py").write_text("print(1)")
    files = {p.name for p in context_files(tmp_path, tmp_path / "Dockerfile.user")}
    assert "app.py" in files and ".env" not in files
    assert ".env.backup_1" not in files


def test_copy_secret_fails_closed(tmp_path):
    project(tmp_path, "FROM app:release\nCOPY .env /app/\n")
    (tmp_path / ".env").write_text("TOKEN=hidden")
    with pytest.raises(BuildDependencyError, match="excluded sensitive"):
        context_files(tmp_path, tmp_path / "Dockerfile.user")


def preflight(root: Path, base="app:release"):
    (root / "MANIFEST.json").write_text(json.dumps({"clean_base_image": base,
                                                  "portable_base_image": base}))
    checker = PreflightChecker(root)
    checker._check_build_dependencies()
    return checker


def test_missing_dockerfile_preflight(tmp_path):
    config = tmp_path / "docker" / "config"
    project(config, "FROM app:release\n")
    (config / "Dockerfile.user").unlink()
    assert "Missing build context or Dockerfile" in preflight(tmp_path).errors[0]


def test_missing_base_preflight(tmp_path):
    config = tmp_path / "docker" / "config"
    project(config, "FROM private-local:release\n", base="private-local:release")
    assert "neither supplied" in preflight(tmp_path).errors[0]


def test_legacy_without_build_passes(tmp_path):
    config = tmp_path / "docker" / "config"
    config.mkdir(parents=True)
    (config / "docker-compose.yml").write_text("services:\n  app:\n    image: app:release\n")
    assert not preflight(tmp_path).errors


def test_checksum_detects_context_tampering(tmp_path):
    from docker_migration_tool.verify.checks import BundleVerifier
    from docker_migration_tool.utils.filesystem import compute_sha256_file
    path = tmp_path / "docker/config/entrypoint.sh"
    path.parent.mkdir(parents=True)
    path.write_text("echo ok\n")
    digest = compute_sha256_file(path)
    (tmp_path / "MANIFEST.json").write_text(json.dumps({
        "checksums": {"docker/config/entrypoint.sh": digest}}))
    path.write_text("echo no\n")
    verifier = BundleVerifier(tmp_path)
    verifier._verify_checksums()
    assert not verifier.results[0].passed


def test_export_context_files_are_checksummed(tmp_path):
    from docker_migration_tool.export.bundle import BundleCreator
    from docker_migration_tool.model import InspectionResult, PortableDockerConfig
    workspace = tmp_path / "source"
    docker = workspace / "docker"
    project(docker, "FROM app:release\nCOPY entrypoint.sh /bin/\n")
    (docker / "entrypoint.sh").write_text("echo ok\n")
    config = PortableDockerConfig(compose_yml_path=str(docker / "docker-compose.yml"))
    creator = BundleCreator(InspectionResult(workspace_path=str(workspace),
                                             docker_config=config), tmp_path / "bundle")
    (creator.output_dir / "docker/config").mkdir(parents=True)
    creator._export_docker_config()
    for name in ("Dockerfile.user", "entrypoint.sh"):
        relative = f"docker/config/{name}"
        assert (creator.output_dir / relative).is_file()
        assert creator.manifest.checksums[relative]


def test_parent_workspace_context_keeps_relative_paths(tmp_path):
    from docker_migration_tool.export.bundle import BundleCreator
    from docker_migration_tool.model import InspectionResult, PortableDockerConfig
    workspace = tmp_path / "source"
    docker = workspace / "docker"
    docker.mkdir(parents=True)
    (docker / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: app-user:latest\n"
        "    build:\n      context: ..\n      dockerfile: docker/Dockerfile.user\n")
    (docker / "Dockerfile.user").write_text("FROM app:release\nCOPY scripts/ /scripts/\n")
    scripts = workspace / "scripts"
    scripts.mkdir()
    (scripts / "a.sh").write_text("echo ok\n")
    creator = BundleCreator(InspectionResult(workspace_path=str(workspace),
        docker_config=PortableDockerConfig(compose_yml_path=str(docker / "docker-compose.yml"))),
        tmp_path / "bundle")
    (creator.output_dir / "docker/config").mkdir(parents=True)
    creator._export_docker_config()
    assert (creator.output_dir / "workspace/build_context/scripts/a.sh").is_file()


def test_import_start_failure_is_not_complete(tmp_path, monkeypatch, capsys):
    from docker_migration_tool.importers.restore import BundleRestorer
    from docker_migration_tool.importers.preflight import PreflightResult
    from docker_migration_tool.cli import cmd_import
    from docker_migration_tool.utils.docker import DockerError
    from argparse import Namespace

    (tmp_path / "MANIFEST.json").write_text("{}")
    monkeypatch.setattr("docker_migration_tool.importers.restore.run_preflight",
                        lambda _: PreflightResult(True, [], [], []))
    for method in ("_load_image", "_restore_workspace", "_restore_docker_config",
                   "_setup_udev", "_setup_xauthority", "_regenerate_config",
                   "_handle_ros_domain_id", "_collect_manual_actions"):
        monkeypatch.setattr(BundleRestorer, method, lambda self: None)
    monkeypatch.setattr("docker_migration_tool.importers.restore.run_docker_compose",
                        lambda *args, **kwargs: (_ for _ in ()).throw(DockerError("up failed")))
    workspace = tmp_path / "restored"
    script = workspace / "src/_container_setup/install_workspace_dependencies.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n")
    result = cmd_import(Namespace(bundle_path=str(tmp_path), workspace=str(workspace),
                                  ros_domain_id=None, dry_run=False, non_interactive=True))
    output = capsys.readouterr().out
    assert result != 0
    assert "Import Complete" not in output
    assert "Import Incomplete" in output


def test_legacy_import_without_build_or_installer_starts_container(tmp_path, monkeypatch):
    from docker_migration_tool.importers.restore import BundleRestorer
    from docker_migration_tool.importers.preflight import PreflightResult
    from subprocess import CompletedProcess
    (tmp_path / "MANIFEST.json").write_text("{}")
    monkeypatch.setattr("docker_migration_tool.importers.restore.run_preflight",
                        lambda _: PreflightResult(True, [], [], []))
    for method in ("_load_image", "_restore_workspace", "_restore_docker_config",
                   "_setup_udev", "_setup_xauthority", "_regenerate_config",
                   "_handle_ros_domain_id", "_collect_manual_actions"):
        monkeypatch.setattr(BundleRestorer, method, lambda self: None)
    calls = []
    def compose(args, **kwargs):
        calls.append(args)
        return CompletedProcess(args, 0, stdout="container-id\n")
    monkeypatch.setattr("docker_migration_tool.importers.restore.run_docker_compose", compose)
    result = BundleRestorer(tmp_path, target_workspace=tmp_path / "target",
                            interactive=False).restore()
    assert result.success
    assert "container_start" in result.completed_stages
    assert "post_import_verification" in result.completed_stages
    assert ["up", "-d"] in calls
