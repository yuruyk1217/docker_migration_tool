"""Image-layer secret scanner for `docker save` archives.

Why this exists
---------------
The final filesystem of an image can look clean while a credential still sits
in a lower layer:

    RUN create_secret      # layer N   -> blob still contains the secret
    RUN rm secret          # layer N+1 -> whiteout only

`docker save` ships *every* layer blob, so a final-filesystem-only scan is not
sufficient evidence that an image is safe to hand to another person.

Policy (deliberately conservative)
----------------------------------
A credential-like path appearing in ANY layer blocks the export. A later
whiteout is never accepted as justification: the deleted bytes are still
present in the lower layer blob that `docker save` writes out.

Safety properties
-----------------
* Nothing is extracted to the host filesystem: layer archives are read as
  streams and only tar *member names* are examined.
* File contents are never read, stored or logged. Findings record the layer
  identifier, the path and the secret kind - nothing else.
* Path traversal / symlink escape / device nodes cannot harm us because no
  member is ever written out; suspicious member names are recorded as
  anomalies instead.
* Unknown archive layouts are refused (never assumed safe).
"""

import gzip
import io
import json
import shutil
import subprocess
import tarfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator

from docker_migration_tool.model import LayerScanResult, LayerSecretFinding
from docker_migration_tool.security.scanner import (
    SCANNER_VERSION,
    is_layer_secret_path,
)

# Archive layouts this version understands. Anything else is refused.
SUPPORTED_ARCHIVE_FORMATS = (
    # docker 29.x / containerd image store: oci-layout + index.json +
    # manifest.json + blobs/sha256/<digest> (verified on this host)
    "docker-oci-layout",
    # OCI layout without the docker compatibility manifest.json
    "oci-layout",
    # classic docker save: manifest.json + <hash>/layer.tar
    "docker-legacy",
)

# Layer blob compressions this version understands.
_MAGIC_GZIP = b"\x1f\x8b"
_MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
_MAGIC_XZ = b"\xfd7zXZ\x00"
_MAGIC_BZIP2 = b"BZh"

# OverlayFS/OCI whiteout markers
_WHITEOUT_PREFIX = ".wh."
_WHITEOUT_OPAQUE = ".wh..wh..opq"

# Cap on recorded findings (the count is always exact; the list is truncated
# so that an unexpected match storm cannot produce an unbounded report).
_MAX_RECORDED_FINDINGS = 200


class UnsupportedImageArchiveError(Exception):
    """The image archive layout is not one of SUPPORTED_ARCHIVE_FORMATS."""
    pass


class ImageArchiveError(Exception):
    """The image archive is malformed or unreadable."""
    pass


@dataclass
class LayerRef:
    """A layer blob inside the save archive."""
    layer_id: str      # "sha256:<digest>" or "<dir>/layer.tar" for legacy
    member_name: str   # tar member name inside the save archive


def detect_archive_format(member_names: set[str]) -> str:
    """Detect the `docker save` archive layout from its member names.

    Args:
        member_names: Every member name in the save archive

    Returns:
        One of SUPPORTED_ARCHIVE_FORMATS

    Raises:
        UnsupportedImageArchiveError: If the layout is not recognised
    """
    has_manifest = "manifest.json" in member_names
    has_index = "index.json" in member_names
    has_oci_layout = "oci-layout" in member_names
    has_blobs = any(name.startswith("blobs/sha256/") for name in member_names)
    has_legacy_layers = any(name.endswith("/layer.tar") for name in member_names)

    if has_manifest and has_blobs and (has_index or has_oci_layout):
        return "docker-oci-layout"
    if has_index and has_blobs and has_oci_layout:
        return "oci-layout"
    if has_manifest and has_legacy_layers:
        return "docker-legacy"

    raise UnsupportedImageArchiveError(
        "unsupported image archive format "
        f"(manifest.json={has_manifest}, index.json={has_index}, "
        f"oci-layout={has_oci_layout}, blobs/={has_blobs}, "
        f"legacy layer.tar={has_legacy_layers})"
    )


def _read_json_member(tar: tarfile.TarFile, name: str) -> object:
    """Read and parse a small JSON member of the save archive."""
    try:
        member = tar.getmember(name)
    except KeyError as exc:
        raise ImageArchiveError(f"Archive member not found: {name}") from exc

    reader = tar.extractfile(member)
    if reader is None:
        raise ImageArchiveError(f"Archive member is not a file: {name}")

    try:
        return json.loads(reader.read().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ImageArchiveError(f"Archive member is not valid JSON: {name}") from exc


def _blob_member_to_layer_id(member_name: str) -> str:
    """Turn 'blobs/sha256/<digest>' into 'sha256:<digest>'."""
    if member_name.startswith("blobs/sha256/"):
        return "sha256:" + member_name[len("blobs/sha256/"):]
    return member_name


def _layers_from_docker_manifest(tar: tarfile.TarFile) -> list[LayerRef]:
    """Collect layer refs from the docker-style manifest.json."""
    manifest = _read_json_member(tar, "manifest.json")
    if not isinstance(manifest, list) or not manifest:
        raise ImageArchiveError("manifest.json has an unexpected structure")

    refs: list[LayerRef] = []
    for entry in manifest:
        if not isinstance(entry, dict):
            raise ImageArchiveError("manifest.json entry is not an object")
        layers = entry.get("Layers")
        if not isinstance(layers, list) or not layers:
            raise ImageArchiveError("manifest.json entry has no Layers")
        for name in layers:
            if not isinstance(name, str):
                raise ImageArchiveError("manifest.json Layers entry is not a string")
            refs.append(LayerRef(layer_id=_blob_member_to_layer_id(name),
                                 member_name=name))
    return refs


def _layers_from_oci_index(tar: tarfile.TarFile) -> list[LayerRef]:
    """Collect layer refs by walking index.json -> manifest blob -> layers."""
    index = _read_json_member(tar, "index.json")
    if not isinstance(index, dict):
        raise ImageArchiveError("index.json has an unexpected structure")

    refs: list[LayerRef] = []
    pending = [m for m in index.get("manifests", []) if isinstance(m, dict)]
    seen: set[str] = set()

    while pending:
        descriptor = pending.pop(0)
        digest = descriptor.get("digest")
        if not isinstance(digest, str) or digest in seen:
            continue
        seen.add(digest)

        member_name = "blobs/" + digest.replace(":", "/")
        try:
            blob = _read_json_member(tar, member_name)
        except ImageArchiveError:
            continue
        if not isinstance(blob, dict):
            continue

        # Manifest list / image index -> recurse into child manifests
        children = blob.get("manifests")
        if isinstance(children, list) and children:
            pending.extend(m for m in children if isinstance(m, dict))
            continue

        for layer in blob.get("layers", []) or []:
            if not isinstance(layer, dict):
                continue
            layer_digest = layer.get("digest")
            if not isinstance(layer_digest, str):
                continue
            refs.append(LayerRef(
                layer_id=layer_digest,
                member_name="blobs/" + layer_digest.replace(":", "/"),
            ))

    if not refs:
        raise ImageArchiveError("index.json yielded no layer blobs")
    return refs


def enumerate_layers(tar: tarfile.TarFile, archive_format: str) -> list[LayerRef]:
    """Enumerate every layer archive contained in the save archive.

    Args:
        tar: Open save archive
        archive_format: One of SUPPORTED_ARCHIVE_FORMATS

    Returns:
        Ordered, de-duplicated list of layer refs
    """
    if archive_format in ("docker-oci-layout", "docker-legacy"):
        refs = _layers_from_docker_manifest(tar)
    elif archive_format == "oci-layout":
        refs = _layers_from_oci_index(tar)
    else:  # pragma: no cover - detect_archive_format guards this
        raise UnsupportedImageArchiveError(
            f"unsupported image archive format: {archive_format}"
        )

    unique: list[LayerRef] = []
    seen: set[str] = set()
    for ref in refs:
        if ref.member_name in seen:
            continue
        seen.add(ref.member_name)
        unique.append(ref)
    return unique


class _ZstdStream(io.RawIOBase):
    """Read-only stream that decompresses zstd via the `zstd` CLI.

    A feeder thread pipes the compressed member into `zstd -d -c`; only the
    decompressed bytes are read back. Nothing touches the filesystem.
    """

    def __init__(self, source: IO[bytes]):
        if shutil.which("zstd") is None:
            raise UnsupportedImageArchiveError(
                "unsupported image archive format: zstd-compressed layer but "
                "the 'zstd' tool is not available"
            )
        self._proc = subprocess.Popen(
            ["zstd", "-d", "-c"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self._source = source
        self._feeder = threading.Thread(target=self._feed, daemon=True)
        self._feeder.start()

    def _feed(self) -> None:
        try:
            shutil.copyfileobj(self._source, self._proc.stdin)  # type: ignore[arg-type]
        except (BrokenPipeError, ValueError, OSError):
            pass
        finally:
            try:
                self._proc.stdin.close()  # type: ignore[union-attr]
            except (BrokenPipeError, OSError):
                pass

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        chunk = self._proc.stdout.read(len(buffer))  # type: ignore[union-attr]
        if not chunk:
            return 0
        buffer[:len(chunk)] = chunk
        return len(chunk)

    def close(self) -> None:
        try:
            if self._proc.stdout:
                self._proc.stdout.close()
        finally:
            self._proc.kill()
            self._proc.wait()
            super().close()


def _open_layer_stream(reader: IO[bytes]) -> IO[bytes]:
    """Wrap a layer blob stream in the right decompressor.

    Supported: gzip, zstd, uncompressed tar. Anything else is refused rather
    than skipped, because an unscanned layer must never count as safe.

    Args:
        reader: Stream positioned at the start of the layer blob

    Returns:
        Stream of uncompressed tar bytes

    Raises:
        UnsupportedImageArchiveError: On unknown layer compression
    """
    head = reader.read(6)
    stream: IO[bytes] = io.BufferedReader(  # type: ignore[assignment]
        _ChainedStream(head, reader)
    )

    if head.startswith(_MAGIC_GZIP):
        return gzip.GzipFile(fileobj=stream)  # type: ignore[return-value]
    if head.startswith(_MAGIC_ZSTD):
        return io.BufferedReader(_ZstdStream(stream))  # type: ignore[arg-type,return-value]
    if head.startswith(_MAGIC_XZ):
        raise UnsupportedImageArchiveError(
            "unsupported image archive format: xz-compressed layer blob"
        )
    if head.startswith(_MAGIC_BZIP2):
        raise UnsupportedImageArchiveError(
            "unsupported image archive format: bzip2-compressed layer blob"
        )
    # Uncompressed tar (docker-legacy layer.tar, or an OCI
    # application/vnd.oci.image.layer.v1.tar layer)
    return stream


class _ChainedStream(io.RawIOBase):
    """Re-attach already consumed magic bytes in front of a stream."""

    def __init__(self, head: bytes, rest: IO[bytes]):
        self._head = head
        self._rest = rest

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        want = len(buffer)
        if self._head:
            take = self._head[:want]
            self._head = self._head[len(take):]
            buffer[:len(take)] = take
            return len(take)
        chunk = self._rest.read(want)
        if not chunk:
            return 0
        buffer[:len(chunk)] = chunk
        return len(chunk)


def normalize_layer_member_path(member_name: str) -> tuple[str | None, bool]:
    """Convert a layer tar member name into an absolute container path.

    Also decodes OverlayFS whiteout markers. A whiteout does NOT make the
    referenced path safe - it only tells us the path existed in a lower layer,
    which is exactly what we block on.

    Args:
        member_name: Raw tar member name (e.g. "./home/u/.codex/auth.json")

    Returns:
        (absolute_path, is_whiteout). absolute_path is None when the member
        name is unsafe/unusable (traversal attempt, empty name).
    """
    name = member_name.strip()
    if not name:
        return None, False

    # Reject absolute or traversing member names outright: we never extract,
    # but they must not be silently normalised into a matching path either.
    if name.startswith("/"):
        return None, False

    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None, False
    if not parts:
        # Root directory entry ("." / "./"): present in almost every layer.
        return "/", False

    is_whiteout = False
    basename = parts[-1]
    if basename == _WHITEOUT_OPAQUE:
        # Opaque directory marker: the *directory* existed below this layer.
        is_whiteout = True
        parts = parts[:-1]
        if not parts:
            return "/", True
    elif basename.startswith(_WHITEOUT_PREFIX):
        is_whiteout = True
        deleted = basename[len(_WHITEOUT_PREFIX):]
        if not deleted:
            return None, True
        parts[-1] = deleted

    return "/" + "/".join(parts), is_whiteout


def scan_layer_stream(layer_id: str, stream: IO[bytes],
                      findings: list[LayerSecretFinding],
                      anomalies: list[str]) -> tuple[int, int]:
    """Scan one layer archive for credential-like member names.

    Only member names are inspected; member data is skipped by the tar reader
    and never written anywhere.

    Args:
        layer_id: Layer identifier (e.g. "sha256:...")
        stream: Uncompressed tar byte stream
        findings: Accumulator for findings (identity only)
        anomalies: Accumulator for suspicious member names

    Returns:
        (entries_scanned, findings_found)
    """
    entries = 0
    found = 0

    tar = tarfile.open(fileobj=stream, mode="r|")
    try:
        for member in tar:
            entries += 1

            path, is_whiteout = normalize_layer_member_path(member.name)
            if path is None:
                note = f"{layer_id}: unsafe member name skipped"
                if note not in anomalies:
                    anomalies.append(note)
                continue

            if member.isdev():
                note = f"{layer_id}: device node member present (never extracted)"
                if note not in anomalies:
                    anomalies.append(note)

            is_secret, kind = is_layer_secret_path(path)
            if not is_secret:
                continue

            found += 1
            if len(findings) < _MAX_RECORDED_FINDINGS:
                findings.append(LayerSecretFinding(
                    layer=layer_id,
                    path=path.lstrip("/"),
                    kind=kind,
                    whiteout=is_whiteout,
                ))
    finally:
        tar.close()

    return entries, found


def scan_image_archive(archive_path: Path) -> LayerScanResult:
    """Scan every layer of a `docker save` archive for credential paths.

    Args:
        archive_path: Path to the uncompressed `docker save` tar archive

    Returns:
        LayerScanResult. `result` is "passed" only when every layer was read
        and no credential-like path was seen in any of them.

    Raises:
        UnsupportedImageArchiveError: Unknown archive layout / layer compression
        ImageArchiveError: Malformed archive
    """
    findings: list[LayerSecretFinding] = []
    anomalies: list[str] = []
    entries_total = 0
    layers_scanned = 0
    total_found = 0

    with tarfile.open(archive_path, mode="r") as tar:
        member_names = set(tar.getnames())
        archive_format = detect_archive_format(member_names)
        layer_refs = enumerate_layers(tar, archive_format)

        for ref in layer_refs:
            if ref.member_name not in member_names:
                raise ImageArchiveError(
                    f"Layer blob referenced by manifest is missing: {ref.member_name}"
                )

            member = tar.getmember(ref.member_name)
            reader = tar.extractfile(member)
            if reader is None:
                raise ImageArchiveError(
                    f"Layer blob is not a regular file: {ref.member_name}"
                )

            stream = _open_layer_stream(reader)
            try:
                entries, found = scan_layer_stream(
                    ref.layer_id, stream, findings, anomalies
                )
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

            layers_scanned += 1
            entries_total += entries
            total_found += found

    return LayerScanResult(
        performed=True,
        result="failed" if total_found else "passed",
        scanner_version=SCANNER_VERSION,
        archive_format=archive_format,
        layers_scanned=layers_scanned,
        entries_scanned=entries_total,
        findings=findings,
        anomalies=anomalies,
        message=(
            f"{total_found} credential-like path(s) found across "
            f"{layers_scanned} layer(s)"
            if total_found else
            f"no credential-like paths in {layers_scanned} layer(s)"
        ),
    )


def iter_layer_member_paths(archive_path: Path) -> Iterator[tuple[str, str, bool]]:
    """Yield (layer_id, path, is_whiteout) for every member of every layer.

    Provided for diagnostics; the export gate uses `scan_image_archive()`.
    """
    with tarfile.open(archive_path, mode="r") as tar:
        archive_format = detect_archive_format(set(tar.getnames()))
        for ref in enumerate_layers(tar, archive_format):
            member = tar.getmember(ref.member_name)
            reader = tar.extractfile(member)
            if reader is None:
                continue
            stream = _open_layer_stream(reader)
            try:
                inner = tarfile.open(fileobj=stream, mode="r|")
                try:
                    for entry in inner:
                        path, whiteout = normalize_layer_member_path(entry.name)
                        if path is not None:
                            yield ref.layer_id, path, whiteout
                finally:
                    inner.close()
            finally:
                try:
                    stream.close()
                except OSError:
                    pass
