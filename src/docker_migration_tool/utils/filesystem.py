"""Filesystem utilities for the migration tool.

Includes secure archive extraction with path traversal prevention, and the
single exclude-pattern matcher used by every consumer of an exclusion policy
(archive creation, file collection and large-file discovery). Having one matcher
is what keeps the dry-run report and the real archive from disagreeing.
"""

import fnmatch
import hashlib
import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import IO, Iterable, Iterator


class ArchiveSecurityError(Exception):
    """Security error during archive operation."""
    pass


def _pattern_matches_relative(rel_path: str, pattern: str) -> bool:
    """Check one relative path against one exclude pattern.

    This is the only place where exclude-pattern semantics are defined:

        ``**/<glob>``  matches the whole relative path, or any single path
                       component (so ``**/build`` drops every ``build``
                       directory but keeps ``rebuild_tool.py``)
        ``<glob>``     matches the relative path or the basename
        ``<literal>``  matches the relative path, a prefix directory of it,
                       or the basename

    Args:
        rel_path: Path relative to the exclusion root, in posix form
        pattern: One exclude pattern

    Returns:
        True if the pattern excludes this path
    """
    rel = PurePosixPath(rel_path)
    name = rel.name

    if pattern.startswith("**/"):
        tail = pattern[3:]
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path, tail):
            return True
        return any(fnmatch.fnmatch(part, tail) for part in rel.parts)

    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(name, pattern)

    if rel_path == pattern or rel_path.startswith(pattern + "/"):
        return True
    return name == pattern


def matched_exclude_pattern_for_relative(
    rel_path: str, patterns: Iterable[str] | None,
) -> str | None:
    """Return the first exclude pattern matching a relative path.

    Args:
        rel_path: Path relative to the exclusion root
        patterns: Exclude patterns

    Returns:
        The matching pattern, or None if the path is included
    """
    if not patterns:
        return None

    rel_path = PurePosixPath(rel_path.replace(os.sep, "/")).as_posix()
    for pattern in patterns:
        if _pattern_matches_relative(rel_path, pattern):
            return pattern
    return None


def matched_exclude_pattern(
    path: Path, root: Path, patterns: Iterable[str] | None,
) -> str | None:
    """Return the first exclude pattern matching an absolute path.

    Args:
        path: File or directory path
        root: Root the exclusion policy is relative to
        patterns: Exclude patterns

    Returns:
        The matching pattern, or None if the path is included
    """
    try:
        rel_path = path.relative_to(root).as_posix()
    except ValueError:
        rel_path = path.name
    return matched_exclude_pattern_for_relative(rel_path, patterns)


def is_excluded(path: Path, root: Path, patterns: Iterable[str] | None) -> bool:
    """Check whether a path is excluded by an exclusion policy."""
    return matched_exclude_pattern(path, root, patterns) is not None


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of bytes.

    Args:
        data: Bytes to hash

    Returns:
        Hex digest
    """
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(path: Path, chunk_size: int = 8192) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        path: File path
        chunk_size: Read chunk size

    Returns:
        Hex digest
    """
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_disk_free(path: Path) -> int:
    """Get free disk space in bytes.

    Args:
        path: Path to check

    Returns:
        Free space in bytes
    """
    stat_result = os.statvfs(path)
    return stat_result.f_frsize * stat_result.f_bavail


def safe_path_join(base: Path, *parts: str) -> Path:
    """Safely join path components, preventing traversal.

    Args:
        base: Base directory (must exist)
        parts: Path components to join

    Returns:
        Resolved path under base

    Raises:
        ArchiveSecurityError: If path escapes base
    """
    # Resolve base to absolute
    base = base.resolve()

    # Join and resolve
    joined = base.joinpath(*parts).resolve()

    # Check it's under base
    try:
        joined.relative_to(base)
    except ValueError:
        raise ArchiveSecurityError(
            f"Path traversal detected: {'/'.join(parts)} escapes {base}"
        )

    return joined


def _check_tar_member_safe(member: tarfile.TarInfo, dest: Path) -> Path:
    """Check if tar member is safe to extract.

    Args:
        member: Tar member info
        dest: Destination directory

    Returns:
        Safe extraction path

    Raises:
        ArchiveSecurityError: If member is unsafe
    """
    # Check for absolute path
    if member.name.startswith("/"):
        raise ArchiveSecurityError(f"Absolute path in archive: {member.name}")

    # Check for path traversal
    if ".." in member.name.split("/"):
        raise ArchiveSecurityError(f"Path traversal in archive: {member.name}")

    # Get safe path
    safe_path = safe_path_join(dest, member.name)

    # Check for symlink escape
    if member.issym():
        link_target = member.linkname
        if link_target.startswith("/"):
            raise ArchiveSecurityError(
                f"Absolute symlink target in archive: {member.name} -> {link_target}"
            )
        # Check resolved target
        link_dir = safe_path.parent
        try:
            resolved = (link_dir / link_target).resolve()
            resolved.relative_to(dest.resolve())
        except ValueError:
            raise ArchiveSecurityError(
                f"Symlink escapes destination: {member.name} -> {link_target}"
            )

    # Check for hardlink escape
    if member.islnk():
        if member.linkname.startswith("/") or ".." in member.linkname.split("/"):
            raise ArchiveSecurityError(
                f"Hardlink escape in archive: {member.name} -> {member.linkname}"
            )

    # Check for special files (device nodes, etc.)
    if member.isdev():
        raise ArchiveSecurityError(f"Device node in archive: {member.name}")

    return safe_path


def safe_extract_archive(archive_path: Path, dest: Path,
                         strip_components: int = 0) -> None:
    """Safely extract a tar archive with path traversal prevention.

    Args:
        archive_path: Path to tar archive
        dest: Destination directory
        strip_components: Number of leading path components to strip

    Raises:
        ArchiveSecurityError: If archive contains unsafe paths
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)

    # Detect compression
    suffix = archive_path.suffix.lower()
    if suffix == ".zst":
        # Use zstd for decompression
        mode = "r|"
        open_func = lambda p: subprocess.Popen(
            ["zstd", "-d", "-c", str(p)],
            stdout=subprocess.PIPE
        ).stdout
    elif suffix == ".gz" or archive_path.name.endswith(".tar.gz"):
        mode = "r:gz"
        open_func = None
    elif suffix == ".xz":
        mode = "r:xz"
        open_func = None
    elif suffix == ".bz2":
        mode = "r:bz2"
        open_func = None
    else:
        mode = "r"
        open_func = None

    if open_func:
        fileobj = open_func(archive_path)
        tar = tarfile.open(fileobj=fileobj, mode=mode)
    else:
        tar = tarfile.open(archive_path, mode=mode)

    try:
        for member in tar:
            # Strip components if requested
            if strip_components > 0:
                parts = member.name.split("/")
                if len(parts) <= strip_components:
                    continue
                member.name = "/".join(parts[strip_components:])
                if not member.name:
                    continue

            # Security check
            safe_path = _check_tar_member_safe(member, dest)

            # Extract
            if member.isdir():
                safe_path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                safe_path.parent.mkdir(parents=True, exist_ok=True)
                with open(safe_path, "wb") as f:
                    if member.size > 0:
                        reader = tar.extractfile(member)
                        if reader:
                            shutil.copyfileobj(reader, f)
                # Restore mode
                os.chmod(safe_path, member.mode)
            elif member.issym():
                safe_path.parent.mkdir(parents=True, exist_ok=True)
                if safe_path.exists() or safe_path.is_symlink():
                    safe_path.unlink()
                os.symlink(member.linkname, safe_path)
            elif member.islnk():
                safe_path.parent.mkdir(parents=True, exist_ok=True)
                link_target = safe_path_join(dest, member.linkname)
                if safe_path.exists() or safe_path.is_symlink():
                    safe_path.unlink()
                os.link(link_target, safe_path)
    finally:
        tar.close()
        if open_func and hasattr(fileobj, 'close'):
            fileobj.close()


def create_archive(source: Path, archive_path: Path,
                   excludes: list[str] | None = None,
                   compression: str = "zst") -> None:
    """Create a tar archive of a directory.

    Args:
        source: Source directory
        archive_path: Output archive path
        excludes: List of glob patterns to exclude
        compression: Compression type (none, gz, zst, xz)
    """
    excludes = excludes or []
    source = source.resolve()

    def should_exclude(path: Path) -> bool:
        """Check if path matches any exclude pattern (shared matcher)."""
        return is_excluded(path, source, excludes)

    # Create tar first, then compress
    if compression == "zst":
        # Create tar, then pipe to zstd
        tar_path = archive_path.with_suffix("")
        if not str(tar_path).endswith(".tar"):
            tar_path = archive_path.parent / (archive_path.stem.replace(".tar", "") + ".tar")

        with tarfile.open(tar_path, "w") as tar:
            for root, dirs, files in os.walk(source):
                root_path = Path(root)

                # Filter excluded directories
                dirs[:] = [d for d in dirs if not should_exclude(root_path / d)]

                for file in files:
                    file_path = root_path / file
                    if not should_exclude(file_path):
                        arcname = str(file_path.relative_to(source))
                        tar.add(file_path, arcname=arcname)

        # Compress with zstd
        subprocess.run(
            ["zstd", "-T0", "--rm", "-q", str(tar_path), "-o", str(archive_path)],
            check=True,
        )
    else:
        mode = "w"
        if compression == "gz":
            mode = "w:gz"
        elif compression == "xz":
            mode = "w:xz"
        elif compression == "bz2":
            mode = "w:bz2"

        with tarfile.open(archive_path, mode) as tar:
            for root, dirs, files in os.walk(source):
                root_path = Path(root)

                # Filter excluded directories
                dirs[:] = [d for d in dirs if not should_exclude(root_path / d)]

                for file in files:
                    file_path = root_path / file
                    if not should_exclude(file_path):
                        arcname = str(file_path.relative_to(source))
                        tar.add(file_path, arcname=arcname)


def collect_files(directory: Path, excludes: list[str] | None = None) -> Iterator[Path]:
    """Collect files from directory respecting excludes.

    Args:
        directory: Directory to scan
        excludes: Patterns to exclude

    Yields:
        File paths
    """
    excludes = excludes or []
    directory = directory.resolve()

    def should_exclude(path: Path) -> bool:
        """Check if path matches any exclude pattern (shared matcher)."""
        return is_excluded(path, directory, excludes)

    for root, dirs, files in os.walk(directory):
        root_path = Path(root)

        # Filter excluded directories
        dirs[:] = [d for d in dirs if not should_exclude(root_path / d)]

        for file in files:
            file_path = root_path / file
            if not should_exclude(file_path):
                yield file_path


def ensure_directory(path: Path) -> Path:
    """Ensure directory exists.

    Args:
        path: Directory path

    Returns:
        The path
    """
    path.mkdir(parents=True, exist_ok=True)
    return path
