"""Command-line interface for the migration tool.

Usage:
    docker-migration inspect --container <name>
    docker-migration export --container <name> --output <path>
    docker-migration export --container <name> --dry-run
    docker-migration import <bundle_path>
    docker-migration verify <bundle_path>
    docker-migration bundle-info <bundle_path>
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from docker_migration_tool import __version__
from docker_migration_tool.model import InspectionResult
from docker_migration_tool.utils.logging import (
    log_ok, log_warn, log_error, log_info, log_step, log_header,
    log_detail, set_color_output,
)


def cmd_inspect(args: argparse.Namespace) -> int:
    """Run inspect command."""
    from docker_migration_tool.inspect import (
        inspect_container,
        discover_workspace_from_container,
        inspect_image,
        resolve_clean_parent_image,
        inspect_host,
        inspect_hardware,
        inspect_network,
        inspect_workspace,
        inspect_git_repos,
        discover_large_files,
        resolve_src_archive_root,
        inspect_docker_config,
        inspect_packages,
    )
    from docker_migration_tool.security import scan_container_for_secrets

    log_header(f"Inspecting Container: {args.container}")

    result = InspectionResult()

    # Container
    log_step("Inspecting container...")
    try:
        result.container = inspect_container(args.container)
        log_ok(f"Container: {result.container.name}")
        log_detail("Image", result.container.image)
        log_detail("State", result.container.state)
        log_detail("User", result.container.user)
    except Exception as e:
        log_error(f"Failed to inspect container: {e}")
        return 1

    # Workspace discovery
    log_step("Discovering workspace...")
    workspace_info = discover_workspace_from_container(result.container)
    result.workspace_path = workspace_info.get("workspace_path")
    if result.workspace_path:
        log_ok(f"Workspace: {result.workspace_path}")
    else:
        log_warn("Workspace path not found")

    # Runtime image
    log_step("Inspecting runtime image...")
    try:
        result.runtime_image = inspect_image(result.container.image)
        log_ok(f"Runtime image: {result.runtime_image.repository}:{result.runtime_image.tag}")
        log_detail("Layers", str(result.runtime_image.layer_count))
        log_detail("Is snapshot", str(result.runtime_image.is_snapshot))
    except Exception as e:
        log_warn(f"Failed to inspect image: {e}")

    # Clean parent image (candidate discovery + RootFS layer proof)
    log_step("Finding clean parent image...")
    if result.runtime_image:
        docker_dir = workspace_info.get("docker_dir")
        env_sh = f"{docker_dir}/env.sh" if docker_dir else None
        try:
            result.clean_base_image, result.parent_relationship = (
                resolve_clean_parent_image(
                    result.container.image, env_sh,
                    runtime_info=result.runtime_image,
                )
            )
            relationship = result.parent_relationship
            if result.clean_base_image:
                log_ok(f"Clean parent: {result.clean_base_image.reference}")
                log_detail("Discovered via", relationship.candidate_source or "unknown")
                log_detail("Verification", relationship.method)
                log_detail("Relationship", relationship.relationship)
                log_detail("Runtime layers", str(relationship.runtime_layer_count))
                log_detail("Clean parent layers", str(relationship.candidate_layer_count))
            else:
                log_warn("Clean parent image not proven")
                log_detail("Runtime layers", str(relationship.runtime_layer_count))
                log_detail("Relationship", relationship.relationship)
                if relationship.reason:
                    log_detail("Reason", relationship.reason)
                log_info("Export will not be possible without a proven clean parent")
            if relationship.rejected_candidates:
                log_info(
                    f"  Rejected candidates: {len(relationship.rejected_candidates)}"
                )
                for rejected in relationship.rejected_candidates[:5]:
                    log_detail(
                        f"  {rejected['image']}",
                        f"{rejected['layer_count']} layers, {rejected['relationship']}",
                    )
        except Exception as e:
            log_warn(f"Failed to find clean parent: {e}")

    # Host
    log_step("Inspecting host...")
    try:
        result.host = inspect_host()
        log_ok(f"Host: {result.host.os_name} {result.host.os_version}")
        log_detail("Docker", result.host.docker_version or "unknown")
        log_detail("GPU", result.host.gpu_model or "none")
    except Exception as e:
        log_warn(f"Failed to inspect host: {e}")

    # Hardware
    log_step("Inspecting hardware...")
    try:
        result.hardware = inspect_hardware()
        log_ok(f"Cameras: {len(result.hardware.cameras_by_id)} by-id")
        log_detail("Serial by-id", str(len(result.hardware.serial_by_id)) if result.hardware.serial_by_id else "not detected")
    except Exception as e:
        log_warn(f"Failed to inspect hardware: {e}")

    # Network
    log_step("Inspecting network...")
    try:
        result.network_intents = inspect_network()
        log_ok(f"Network interfaces: {len(result.network_intents)}")
    except Exception as e:
        log_warn(f"Failed to inspect network: {e}")

    # Mounts
    result.mounts = result.container.mounts
    log_ok(f"Mounts: {len(result.mounts)}")
    for m in result.mounts:
        log_detail(f"  {m.container_target}", f"{m.classification.value} ({m.migration_action})")

    # Git repos
    if result.workspace_path:
        log_step("Inspecting git repositories...")
        src_path = Path(result.workspace_path) / "src"
        if src_path.exists():
            result.git_repos = inspect_git_repos(src_path)
            log_ok(f"Git repositories: {len(result.git_repos)}")
            dirty = sum(1 for r in result.git_repos if r.is_dirty)
            if dirty > 0:
                log_warn(f"  {dirty} repos have uncommitted changes")

    # Large files. Discovery applies the workspace exclusion policy first, so
    # this list only contains files the archive would actually include.
    if result.workspace_path:
        log_step("Finding large files...")
        src_path = resolve_src_archive_root(Path(result.workspace_path))
        if src_path:
            result.workspace_src_path = str(src_path)
            discovery = discover_large_files(src_path, compute_checksums=False)
            result.large_files = discovery.included
            result.excluded_large_files = discovery.excluded
            log_ok(f"Large files (>10MB): {len(result.large_files)}")
            for lf in result.large_files[:5]:
                log_detail(f"  {lf.path}", f"{lf.size_bytes / (1024**2):.1f} MB")
            if result.excluded_large_files:
                log_info(
                    f"  Excluded by policy: {len(result.excluded_large_files)} "
                    "large file(s)"
                )
                for ex in result.excluded_large_files[:5]:
                    log_detail(
                        f"  {ex.path}",
                        f"{ex.size_bytes / (1024**2):.1f} MB "
                        f"(excluded_by: {ex.excluded_by})",
                    )

    # Docker config
    if workspace_info.get("docker_dir"):
        log_step("Inspecting Docker configuration...")
        result.docker_config = inspect_docker_config(Path(workspace_info["docker_dir"]))
        log_ok("Docker configuration found")

    # Packages
    log_step("Inspecting packages...")
    try:
        result.packages = inspect_packages(args.container, result.container.container_username)
        log_ok(f"apt manual: {len(result.packages.apt_manual)}")
        log_ok(f"pip freeze: {len(result.packages.pip_freeze)}")
        log_detail("Python", result.packages.python_version or "unknown")
        log_detail("ROS", result.packages.ros_distro or "unknown")
    except Exception as e:
        log_warn(f"Failed to inspect packages: {e}")

    # Secrets
    log_step("Scanning for secrets...")
    try:
        result.secrets = scan_container_for_secrets(
            args.container, result.container.container_username
        )
        if result.secrets:
            log_warn(f"Secrets detected: {len(result.secrets)}")
            for s in result.secrets:
                log_detail(f"  {s.kind}", s.path)
        else:
            log_ok("No secrets detected in container")
    except Exception as e:
        log_warn(f"Failed to scan for secrets: {e}")

    # Summary
    log_header("Inspection Summary")

    if result.clean_base_image:
        log_ok("Clean parent image proven - export is possible")
    else:
        log_error("Clean parent image NOT proven - cannot export")

    if result.runtime_image and result.runtime_image.is_snapshot:
        log_warn("Runtime image is a snapshot (docker commit)")
        log_info("  Snapshot will NOT be exported (may contain credentials)")
        log_info("  Dependencies will be restored from manifests")

    if args.output:
        # Save inspection to JSON
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            # Convert to serializable dict
            from dataclasses import asdict
            data = {
                "inspection_date": datetime.now().isoformat(),
                "tool_version": __version__,
                "container": asdict(result.container) if result.container else None,
                "workspace_path": result.workspace_path,
                "workspace_src_path": result.workspace_src_path,
                "mounts": [asdict(m) for m in result.mounts],
                "git_repos": [asdict(r) for r in result.git_repos],
                "large_files": [asdict(f) for f in result.large_files],
                "excluded_large_files": [
                    asdict(f) for f in result.excluded_large_files
                ],
                "secrets": [asdict(s) for s in result.secrets],
                "errors": result.errors,
                "warnings": result.warnings,
            }
            json.dump(data, f, indent=2, default=str)
        log_ok(f"Inspection saved to: {output_path}")

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Run export command."""
    from docker_migration_tool.inspect import (
        inspect_container,
        discover_workspace_from_container,
        inspect_image,
        resolve_clean_parent_image,
        inspect_host,
        inspect_hardware,
        inspect_network,
        inspect_workspace,
        inspect_git_repos,
        discover_large_files,
        resolve_src_archive_root,
        inspect_docker_config,
        inspect_packages,
    )
    from docker_migration_tool.security import scan_container_for_secrets
    from docker_migration_tool.export import create_bundle
    from docker_migration_tool.export.bundle import ExportBlockedError

    log_header(f"Exporting Container: {args.container}")

    # --output is only required for a real export; a dry run writes nothing
    if not args.output and not args.dry_run:
        log_error("--output/-o is required (except with --dry-run)")
        return 1

    # Build inspection result
    result = InspectionResult()

    log_step("Inspecting container...")
    try:
        result.container = inspect_container(args.container)
    except Exception as e:
        log_error(f"Failed to inspect container: {e}")
        return 1

    # Workspace discovery
    workspace_info = discover_workspace_from_container(result.container)
    result.workspace_path = workspace_info.get("workspace_path")

    if not result.workspace_path:
        log_error("Workspace path not found - cannot export")
        return 1

    # Images: candidate discovery followed by RootFS layer proof
    log_step("Inspecting images...")
    try:
        result.runtime_image = inspect_image(result.container.image)
        docker_dir = workspace_info.get("docker_dir")
        env_sh = f"{docker_dir}/env.sh" if docker_dir else None
        result.clean_base_image, result.parent_relationship = (
            resolve_clean_parent_image(
                result.container.image, env_sh, runtime_info=result.runtime_image
            )
        )
    except Exception as e:
        log_error(f"Failed to inspect images: {e}")
        return 1

    relationship = result.parent_relationship

    if not result.clean_base_image or not relationship.verified:
        log_error("EXPORT BLOCKED: Unable to prove clean parent image relationship")
        log_detail("Snapshot / runtime image", str(relationship.runtime_image))
        log_detail("Candidate image", str(relationship.candidate_image))
        log_detail("Runtime layer count", str(relationship.runtime_layer_count))
        log_detail("Candidate layer count", str(relationship.candidate_layer_count))
        log_detail("Relationship", relationship.relationship)
        if relationship.reason:
            log_detail("Reason", relationship.reason)
        log_error("Cannot export snapshot image (contains credentials)")
        log_info("Solutions:")
        log_info("  1. Identify the clean Dockerfile-built parent image")
        log_info("  2. Rebuild from Dockerfile without credentials")
        return 1

    log_ok(f"Runtime image: {relationship.runtime_image}")
    log_ok(f"Clean parent image: {relationship.candidate_image}")
    log_detail("Discovered via", relationship.candidate_source or "unknown")
    log_detail("Verification method", relationship.method)
    log_detail("Relationship", relationship.relationship)
    log_detail("Runtime layer count", str(relationship.runtime_layer_count))
    log_detail("Clean image layer count", str(relationship.candidate_layer_count))
    if relationship.rejected_candidates:
        log_detail("Rejected candidates", str(len(relationship.rejected_candidates)))

    # Host info
    try:
        result.host = inspect_host()
        result.hardware = inspect_hardware()
        result.network_intents = inspect_network()
    except Exception as e:
        log_warn(f"Failed to inspect host: {e}")

    # Mounts
    result.mounts = result.container.mounts

    # Git repos and large files. The authoritative src directory is the
    # workspace bind mount; the exclusion policy is applied before large-file
    # discovery so excluded files are never checksummed.
    workspace_bind = next(
        (Path(m.host_source) for m in result.mounts
         if m.is_workspace and m.mount_type == "bind"),
        None,
    )
    src_path = resolve_src_archive_root(Path(result.workspace_path), workspace_bind)
    if src_path:
        result.workspace_src_path = str(src_path)
        result.git_repos = inspect_git_repos(src_path)
        # A dry run never writes LARGE_FILES.json, so multi-GB checksums are
        # pointless work there.
        discovery = discover_large_files(
            src_path, compute_checksums=not args.dry_run
        )
        result.large_files = discovery.included
        result.excluded_large_files = discovery.excluded

    # Docker config
    if workspace_info.get("docker_dir"):
        result.docker_config = inspect_docker_config(Path(workspace_info["docker_dir"]))

    # Packages
    try:
        result.packages = inspect_packages(args.container, result.container.container_username)
    except Exception as e:
        log_warn(f"Failed to inspect packages: {e}")

    # Secrets
    result.secrets = scan_container_for_secrets(
        args.container, result.container.container_username
    )

    # Create output directory (dry run writes nothing, so cwd is only a label)
    output_path = Path(args.output) if args.output else Path.cwd()
    workspace_name = result.container.workspace_name or "workspace"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle_name = f"migration_bundle_{workspace_name}_{timestamp}"
    bundle_path = output_path / bundle_name

    # Create bundle
    try:
        create_bundle(result, bundle_path, dry_run=args.dry_run)
    except ExportBlockedError as e:
        log_error(f"Export blocked: {e}")
        return 1
    except Exception as e:
        log_error(f"Export failed: {e}")
        return 1

    if args.dry_run:
        log_info("Dry run complete - no bundle created")
    else:
        log_ok(f"Bundle created: {bundle_path}")

    return 0


def cmd_import(args: argparse.Namespace) -> int:
    """Run import command."""
    from docker_migration_tool.importers import restore_bundle

    bundle_path = Path(args.bundle_path)
    if not bundle_path.exists():
        log_error(f"Bundle not found: {bundle_path}")
        return 1

    target = Path(args.workspace) if args.workspace else None
    ros_domain_id = args.ros_domain_id

    result = restore_bundle(
        bundle_path,
        target_workspace=target,
        ros_domain_id=ros_domain_id,
        dry_run=args.dry_run,
        interactive=not args.non_interactive,
    )

    if result.success:
        log_header("Import Complete")
        log_ok(f"Workspace: {result.workspace_path}")

        if result.manual_actions_required:
            log_warn("\nManual actions required:")
            for action in result.manual_actions_required:
                log_info(f"  • {action}")

        return 0
    else:
        log_error("Import failed")
        for error in result.errors:
            log_error(f"  {error}")
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Run verify command."""
    from docker_migration_tool.verify import verify_bundle, verify_workspace

    path = Path(args.path)

    if not path.exists():
        log_error(f"Path not found: {path}")
        return 1

    # Determine if this is a bundle or workspace
    if (path / "MANIFEST.json").exists():
        # Bundle
        results = verify_bundle(path)
    elif (path / "docker").exists() or (path / "src").exists():
        # Workspace
        results = verify_workspace(path, args.container)
    else:
        log_error("Path is neither a bundle nor a workspace")
        return 1

    # Summary
    log_header("Verification Summary")
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    failed = total - passed

    log_info(f"Checks: {passed}/{total} passed")

    if failed > 0:
        log_warn(f"  {failed} checks failed")
        return 1

    log_ok("All checks passed")
    return 0


def cmd_bundle_info(args: argparse.Namespace) -> int:
    """Show bundle information."""
    bundle_path = Path(args.bundle_path)

    manifest_path = bundle_path / "MANIFEST.json"
    if not manifest_path.exists():
        log_error(f"Bundle manifest not found: {manifest_path}")
        return 1

    with open(manifest_path) as f:
        manifest = json.load(f)

    log_header("Bundle Information")

    log_detail("Created", manifest.get("created_at", "unknown"))
    log_detail("Tool version", manifest.get("tool_version", "unknown"))
    log_detail("Source host", manifest.get("source_host", "unknown"))
    log_detail("Workspace", manifest.get("workspace_name", "unknown"))
    log_detail("Container", manifest.get("container_name", "unknown"))

    log_info("")
    log_detail("Runtime image (NOT exported)", manifest.get("source_runtime_image", "unknown"))
    log_detail("Clean base image", manifest.get("clean_base_image", "unknown"))
    log_detail("Base image size", f"{manifest.get('clean_base_image_size', 0) / (1024**3):.1f} GB")

    log_info("")
    log_info("Security metadata:")
    log_detail("Parent relationship verified",
               str(manifest.get("parent_relationship_verified", False)))
    log_detail("Verification method",
               str(manifest.get("parent_relationship_method", "none")))
    log_detail("Runtime layer count", str(manifest.get("runtime_layer_count", 0)))
    log_detail("Clean image layer count",
               str(manifest.get("clean_image_layer_count", 0)))
    log_detail("Layer secret scan", str(manifest.get("layer_secret_scan", False)))
    log_detail("Layer secret scan result",
               str(manifest.get("layer_secret_scan_result", "not_performed")))
    log_detail("Scanner version", str(manifest.get("scanner_version", "unknown")))

    log_info("")
    log_detail("ROS distro", manifest.get("ros_distro", "unknown"))
    log_detail("ROS domain ID", str(manifest.get("ros_domain_id", "unknown")))

    if manifest.get("components"):
        log_info("")
        log_info("Components:")
        for comp in manifest["components"]:
            log_info(f"  • {comp}")

    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="docker-migration",
        description="Docker Migration Tool for robotics development environments",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a container")
    inspect_parser.add_argument(
        "--container", "-c", required=True, help="Container name"
    )
    inspect_parser.add_argument(
        "--output", "-o", help="Save inspection to JSON file"
    )

    # export
    export_parser = subparsers.add_parser("export", help="Export migration bundle")
    export_parser.add_argument(
        "--container", "-c", required=True, help="Container name"
    )
    export_parser.add_argument(
        "--output", "-o",
        help="Output directory (required unless --dry-run is used)"
    )
    export_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be done"
    )

    # import
    import_parser = subparsers.add_parser("import", help="Import migration bundle")
    import_parser.add_argument("bundle_path", help="Path to bundle")
    import_parser.add_argument(
        "--workspace", "-w", help="Target workspace path"
    )
    import_parser.add_argument(
        "--ros-domain-id", type=int, help="ROS domain ID to use"
    )
    import_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be done"
    )
    import_parser.add_argument(
        "--non-interactive", action="store_true", help="Don't prompt for input"
    )

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify bundle or workspace")
    verify_parser.add_argument("path", help="Path to bundle or workspace")
    verify_parser.add_argument(
        "--container", "-c", help="Container name (for workspace verification)"
    )

    # bundle-info
    info_parser = subparsers.add_parser("bundle-info", help="Show bundle information")
    info_parser.add_argument("bundle_path", help="Path to bundle")

    args = parser.parse_args()

    if args.no_color:
        set_color_output(False)

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "inspect": cmd_inspect,
        "export": cmd_export,
        "import": cmd_import,
        "verify": cmd_verify,
        "bundle-info": cmd_bundle_info,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
