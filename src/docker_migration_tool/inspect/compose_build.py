"""Compose build graph and portable context validation.

Compose itself parses YAML and interpolation; Dockerfiles are parsed only for
the small, deliberately supported ARG/FROM and local COPY/ADD subset. Unknown
build features fail closed instead of producing a bundle that cannot rebuild.
"""

import json
import fnmatch
import re
import shlex
import subprocess
from pathlib import Path

from docker_migration_tool.security.scanner import is_generated_config, is_secret_path
from docker_migration_tool.inspect.workspace import get_workspace_excludes
from docker_migration_tool.utils.filesystem import matched_exclude_pattern


class BuildDependencyError(ValueError):
    pass


def compose_services(docker_dir: Path, *, interpolate: bool = True) -> dict:
    compose = docker_dir / "docker-compose.yml"
    if not compose.is_file():
        return {}
    command = ["docker", "compose", "-f", str(compose), "config", "--format", "json"]
    if not interpolate:
        command += ["--no-interpolate", "--no-env-resolution"]
    result = subprocess.run(command, cwd=docker_dir, capture_output=True,
                            text=True, timeout=30)
    if result.returncode:
        raise BuildDependencyError(f"Compose config failed: {result.stderr.strip()}")
    return json.loads(result.stdout).get("services", {})


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _safe_relative(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if not _inside(path, root.resolve()):
        raise BuildDependencyError(f"Build path escapes context: {value}")
    return path


def _logical_lines(content: str):
    return re.sub(r"\\\s*\n", " ", content).splitlines()


def dockerfile_sources(dockerfile: Path, context: Path) -> list[Path]:
    if not dockerfile.is_file():
        raise BuildDependencyError(f"Missing build Dockerfile: {dockerfile}")
    sources = []
    for line in _logical_lines(dockerfile.read_text()):
        match = re.match(r"^\s*(COPY|ADD)\s+(.+)$", line, re.I)
        if not match:
            continue
        raw = match.group(2).strip()
        if raw.startswith("["):
            try:
                parts = json.loads(raw)
            except ValueError as exc:
                raise BuildDependencyError(f"Invalid COPY/ADD in {dockerfile}") from exc
        else:
            try:
                parts = shlex.split(raw)
            except ValueError as exc:
                raise BuildDependencyError(f"Invalid COPY/ADD in {dockerfile}") from exc
        while parts and parts[0].startswith("--"):
            flag = parts.pop(0)
            if flag.startswith("--from="):
                parts = []  # multi-stage source, not local context
                break
        for source in parts[:-1]:
            if source.startswith(("http://", "https://", "git@")):
                continue
            if any(c in source for c in "*$?"):
                raise BuildDependencyError(f"Unsupported dynamic COPY/ADD source: {source}")
            path = _safe_relative(context, source.lstrip("/"))
            if not path.exists():
                raise BuildDependencyError(f"Missing build dependency: {source}")
            sources.append(path)
    return sources


def dockerfile_base(dockerfile: Path, args: dict) -> str:
    values = {str(k): str(v) for k, v in args.items() if v is not None}
    for line in _logical_lines(dockerfile.read_text()):
        match = re.match(r"^\s*ARG\s+([\w]+)(?:=(\S+))?", line, re.I)
        if match:
            values.setdefault(match.group(1), match.group(2) or "")
            continue
        match = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.I)
        if match:
            base = match.group(1)
            base = re.sub(r"\$\{([\w]+)(?::?-[^}]*)?\}|\$([\w]+)",
                          lambda m: values.get(m.group(1) or m.group(2), ""), base)
            if not base or "$" in base:
                raise BuildDependencyError(f"Unresolved FROM in {dockerfile}")
            return base
    raise BuildDependencyError(f"No FROM in {dockerfile}")


def build_services(docker_dir: Path, *, interpolate: bool = True,
                   expected_base: str | None = None) -> list[dict]:
    result = []
    for name, service in compose_services(docker_dir, interpolate=interpolate).items():
        build = service.get("build")
        if not build:
            continue
        if isinstance(build, str):
            build = {"context": build}
        context = Path(build.get("context", "."))
        if not context.is_absolute():
            context = docker_dir / context
        context = context.resolve()
        dockerfile = Path(build.get("dockerfile", "Dockerfile"))
        if not dockerfile.is_absolute():
            dockerfile = context / dockerfile
        dockerfile = dockerfile.resolve()
        if not context.is_dir() or not dockerfile.is_file():
            raise BuildDependencyError(f"Missing build context or Dockerfile: {context}, {dockerfile}")
        dockerfile_sources(dockerfile, context)
        args = build.get("args") or {}
        if isinstance(args, list):
            args = dict(item.split("=", 1) for item in args if "=" in item)
        if expected_base:
            args = {key: (expected_base if "$" in str(value) else value)
                    for key, value in args.items()}
        result.append({"service": name, "image": service.get("image"),
                       "context": context, "dockerfile": dockerfile,
                       "base": dockerfile_base(dockerfile, args)})
    return result


def context_files(context: Path, dockerfile: Path) -> list[Path]:
    """Collect the context tree; exclude secrets even when .dockerignore allows them."""
    required = dockerfile_sources(dockerfile, context)
    specific_ignore = dockerfile.with_name(dockerfile.name + ".dockerignore")
    ignore = specific_ignore if specific_ignore.is_file() else context / ".dockerignore"
    patterns = [line.strip() for line in ignore.read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")] if ignore.is_file() else []

    def ignored(relative: Path) -> bool:
        verdict = False
        for pattern in patterns:
            include = pattern.startswith("!")
            token = pattern[1:] if include else pattern
            if fnmatch.fnmatch(relative.as_posix(), token) or fnmatch.fnmatch(relative.name, token):
                verdict = not include
        return verdict

    files = []
    for path in context.rglob("*"):
        relative = path.relative_to(context)
        if path.is_symlink():
            raise BuildDependencyError(f"Symlink in build context: {relative}")
        if not path.is_file():
            continue
        excluded = matched_exclude_pattern(path, context, get_workspace_excludes())
        if excluded or any(is_generated_config(part) or is_secret_path(part)[0]
               or part.startswith((".env.", "docker-compose.override.yml."))
               or part.startswith("id_")
               or part.endswith((".pem", ".key"))
               or part in {".ssh", ".aws", ".azure", ".codex", ".claude",
                           ".claude.json", ".docker", ".git", ".git-credentials",
                           ".netrc", ".npmrc", ".pypirc", ".bash_history",
                           ".zsh_history", ".Xauthority", "gcloud"}
               for part in relative.parts):
            if any(path == source or (source.is_dir() and source in path.parents
                                      and not ignored(relative))
                   for source in required):
                raise BuildDependencyError(
                    f"build dependency requires excluded sensitive file: {relative}")
            continue
        files.append(path)
    return files


def resolve_runtime_build(docker_dir: Path, runtime_info):
    """Return a proven Compose build base, or None when no service matches."""
    from docker_migration_tool.inspect.image import inspect_image, verify_layer_relationship
    from docker_migration_tool.model import LayerRelationship, ParentRelationship

    builds = build_services(docker_dir)
    for build in builds:
        image = build["image"]
        if image != runtime_info.reference and (
            not image or f"{image}:latest" != runtime_info.reference
        ):
            continue
        base = build["base"]
        try:
            base_info = inspect_image(base)
        except Exception as exc:
            raise BuildDependencyError(f"Portable build base is not local: {base}") from exc
        relationship, reason = verify_layer_relationship(
            runtime_info.rootfs_layers, base_info.rootfs_layers)
        if relationship is not LayerRelationship.STRICT_PREFIX or base_info.is_snapshot:
            raise BuildDependencyError(
                f"Compose base {base} is not a proven clean ancestor: {reason}")
        base_info.is_clean_parent = True
        proof = ParentRelationship(
            verified=True, runtime_image=runtime_info.reference,
            candidate_image=base_info.reference, candidate_source="compose_build_graph",
            relationship=relationship.value,
            runtime_layer_count=len(runtime_info.rootfs_layers),
            candidate_layer_count=len(base_info.rootfs_layers), reason=reason)
        return base_info, proof, build
    if builds:
        raise BuildDependencyError(
            f"No Compose build output matches runtime image {runtime_info.reference}")
    return None
