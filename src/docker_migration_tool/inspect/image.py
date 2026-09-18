"""Image inspection module.

Key responsibility: Identify the clean parent image vs the snapshot image.
The snapshot contains credentials and must NOT be exported.
The clean parent (Dockerfile-derived) is safe to export.

Two clearly separated stages:

    Candidate discovery            (heuristics: env.sh, tag naming, history)
            |                       -> NEVER sufficient to allow export
            v
    Layer relationship verification (RootFS layer diff-ID chain prefix)
                                    -> the only accepted proof

A candidate is adopted as the clean parent only when its ordered RootFS layer
chain is a prefix of the runtime image's chain (or is identical to it, for the
case where the runtime image was never committed and is already clean).
"""

import re
from typing import Any

from docker_migration_tool.model import (
    Classification,
    ImageInfo,
    LayerRelationship,
    ParentRelationship,
)
from docker_migration_tool.utils.docker import (
    get_image_info,
    get_images_rootfs_layers,
    inspect_image_json,
    list_image_references,
    run_docker,
    DockerError,
)


def inspect_image(image: str) -> ImageInfo:
    """Inspect a Docker image.

    Args:
        image: Image name or ID

    Returns:
        ImageInfo with image details (including the ordered rootfs_layers)
    """
    data = get_image_info(image)
    full_data = inspect_image_json(image)

    # Get history
    history = get_image_history(image)

    # Determine if this is a snapshot (docker commit) or Dockerfile-built
    is_snapshot = _is_snapshot_image(history)

    rootfs_layers = data.get("rootfs_layers") or list(
        full_data.get("RootFS", {}).get("Layers", [])
    )

    return ImageInfo(
        repository=data.get("repository", ""),
        tag=data.get("tag", ""),
        image_id=data.get("id", ""),
        digest=data.get("digest"),
        size_bytes=data.get("size", 0),
        layer_count=data.get("layers", 0),
        created=data.get("created"),
        is_snapshot=is_snapshot,
        is_clean_parent=False,  # only set after layer relationship verification
        history=history,
        classification=Classification.A if not is_snapshot else Classification.B,
        rootfs_layers=rootfs_layers,
    )


def _is_snapshot_image(history: list[dict[str, Any]]) -> bool:
    """Determine if an image is a docker commit snapshot.

    A snapshot image has characteristic history entries:
    - A layer created by "/bin/bash" or similar interactive command
    - Large layer sizes from interactive use
    - Missing typical Dockerfile commands (RUN, COPY, etc.)

    Args:
        history: Image history from docker history

    Returns:
        True if image appears to be a snapshot
    """
    if not history:
        return False

    # Check the most recent layer(s)
    for entry in history[:3]:  # Check first few entries
        created_by = entry.get("CreatedBy", "")

        # Snapshot indicators
        if created_by in ["/bin/bash", "/bin/sh", "bash", "sh"]:
            return True

        # Check for commit-style layer (no command)
        if not created_by and entry.get("Size", 0) > 100_000_000:  # >100MB
            return True

    return False


# ---------------------------------------------------------------------------
# Stage 2: layer relationship verification (the only accepted proof)
# ---------------------------------------------------------------------------


def verify_layer_relationship(runtime_layers: list[str],
                              candidate_layers: list[str]) -> tuple[LayerRelationship, str]:
    """Compare two ordered RootFS layer chains.

    Accepted relationships:
      * STRICT_PREFIX: len(candidate) < len(runtime) and
        candidate_layers == runtime_layers[:len(candidate_layers)]
      * IDENTICAL: candidate_layers == runtime_layers (runtime already clean)

    Everything else is a refusal, including a candidate whose tag or env.sh
    entry matches: a chain such as [L1,L2,L3,X] is NOT a parent of
    [L1,L2,L3,L4,L5].

    Args:
        runtime_layers: Ordered layer diff IDs of the runtime image
        candidate_layers: Ordered layer diff IDs of the candidate image

    Returns:
        (relationship, human readable reason)
    """
    if not runtime_layers or not candidate_layers:
        return (
            LayerRelationship.MISSING_LAYER_DATA,
            "RootFS layer chain unavailable for runtime image or candidate",
        )

    if len(candidate_layers) > len(runtime_layers):
        return (
            LayerRelationship.CANDIDATE_LONGER,
            f"candidate has more layers ({len(candidate_layers)}) than the "
            f"runtime image ({len(runtime_layers)}); it cannot be a parent",
        )

    if candidate_layers == runtime_layers:
        return (
            LayerRelationship.IDENTICAL,
            "candidate layer chain is identical to the runtime image "
            "(runtime image is already clean)",
        )

    if candidate_layers == runtime_layers[:len(candidate_layers)]:
        return (
            LayerRelationship.STRICT_PREFIX,
            f"candidate layer chain is an exact prefix of the runtime chain "
            f"({len(candidate_layers)}/{len(runtime_layers)} layers)",
        )

    # Report where the chains diverge (layer index only, never contents)
    diverged_at = len(runtime_layers)
    for index, (candidate_layer, runtime_layer) in enumerate(
            zip(candidate_layers, runtime_layers)):
        if candidate_layer != runtime_layer:
            diverged_at = index
            break

    return (
        LayerRelationship.NOT_PREFIX,
        f"candidate layer chain diverges from the runtime chain at layer index "
        f"{diverged_at}; the candidate is not an ancestor",
    )


# ---------------------------------------------------------------------------
# Stage 1: candidate discovery (heuristics only)
# ---------------------------------------------------------------------------


def discover_clean_parent_candidates(runtime_info: ImageInfo,
                                     env_sh_path: str | None = None
                                     ) -> list[tuple[str, str]]:
    """Discover clean parent *candidates*. Discovery is not proof.

    Sources, in priority order:
      1. env.sh (LOCAL_BASE_TAG / namespace + version components)
      2. Non-snapshot tags in the same repository
      3. Every local image reference (layer-chain search)

    Args:
        runtime_info: Inspected runtime image
        env_sh_path: Path to env.sh, if available

    Returns:
        Ordered list of (image_reference, discovery_source) with duplicates
        removed. The runtime image itself is included last so that the
        "runtime image is already clean" case can be verified too.
    """
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    runtime_ref = runtime_info.reference

    def add(ref: str, source: str) -> None:
        ref = ref.strip()
        if not ref or "<none>" in ref or ref in seen:
            return
        seen.add(ref)
        candidates.append((ref, source))

    # 1. env.sh
    if env_sh_path:
        base_tag = _parse_base_tag_from_env_sh(env_sh_path)
        if base_tag:
            add(base_tag, "env.sh")

    # 2. Same repository, non-snapshot tags first
    if runtime_info.repository:
        for ref in _find_candidate_parent_images(runtime_info.repository):
            if ref == runtime_ref:
                continue
            if "snapshot" in ref.lower():
                continue
            add(ref, "repository tag naming")

    # 3. Every local image (the layer chain, not the name, decides)
    for ref in list_image_references():
        if ref == runtime_ref:
            continue
        add(ref, "local image layer-chain search")

    # 4. The runtime image itself (valid only when it is not a snapshot)
    add(runtime_ref, "runtime image itself")

    return candidates


def resolve_clean_parent_image(runtime_image: str,
                               env_sh_path: str | None = None,
                               runtime_info: ImageInfo | None = None
                               ) -> tuple[ImageInfo | None, ParentRelationship]:
    """Resolve and *prove* the clean parent image of a runtime image.

    Args:
        runtime_image: The runtime image reference (possibly a snapshot)
        env_sh_path: Path to env.sh for candidate discovery
        runtime_info: Pre-inspected runtime image (avoids a second inspect)

    Returns:
        (clean_parent_or_None, ParentRelationship). The ImageInfo is returned
        only when the RootFS layer relationship is proven; otherwise the
        relationship explains why export must be blocked.
    """
    if runtime_info is None:
        runtime_info = inspect_image(runtime_image)

    relationship = ParentRelationship(
        runtime_image=runtime_info.reference,
        runtime_layer_count=len(runtime_info.rootfs_layers),
    )

    if not runtime_info.rootfs_layers:
        relationship.relationship = LayerRelationship.MISSING_LAYER_DATA.value
        relationship.reason = (
            "runtime image has no .RootFS.Layers; cannot prove any parent "
            "relationship"
        )
        return None, relationship

    candidates = discover_clean_parent_candidates(runtime_info, env_sh_path)
    candidate_layers = get_images_rootfs_layers([ref for ref, _ in candidates])

    verified: list[tuple[str, str, LayerRelationship, list[str]]] = []

    for ref, source in candidates:
        layers = candidate_layers.get(ref)
        if layers is None:
            try:
                layers = get_images_rootfs_layers([ref]).get(ref, [])
            except DockerError:
                layers = []

        result, reason = verify_layer_relationship(runtime_info.rootfs_layers, layers)

        # The snapshot must never be exported: an identical chain is only
        # acceptable when the runtime image is not a commit snapshot.
        if result is LayerRelationship.IDENTICAL and runtime_info.is_snapshot:
            result = LayerRelationship.SNAPSHOT_ITSELF
            reason = (
                "candidate is the runtime snapshot image itself; a snapshot "
                "may contain credentials and is never exported"
            )

        if result in (LayerRelationship.STRICT_PREFIX, LayerRelationship.IDENTICAL):
            verified.append((ref, source, result, layers))
        else:
            relationship.rejected_candidates.append({
                "image": ref,
                "source": source,
                "layer_count": len(layers),
                "relationship": result.value,
                "reason": reason,
            })

    if not verified:
        relationship.relationship = LayerRelationship.NOT_PREFIX.value
        relationship.reason = (
            "no discovered candidate has a RootFS layer chain that is a prefix "
            f"of {runtime_info.reference} ({len(runtime_info.rootfs_layers)} layers)"
        )
        return None, relationship

    # Prefer the closest proven ancestor (most layers in common), so the
    # exported image is as complete as provably-clean allows.
    verified.sort(key=lambda item: len(item[3]), reverse=True)
    ref, source, result, layers = verified[0]

    try:
        parent_info = inspect_image(ref)
    except DockerError as exc:
        relationship.relationship = result.value
        relationship.candidate_image = ref
        relationship.candidate_source = source
        relationship.candidate_layer_count = len(layers)
        relationship.reason = f"failed to inspect proven parent {ref}: {exc}"
        return None, relationship

    if parent_info.is_snapshot:
        relationship.relationship = LayerRelationship.SNAPSHOT_ITSELF.value
        relationship.candidate_image = ref
        relationship.candidate_source = source
        relationship.candidate_layer_count = len(layers)
        relationship.reason = (
            f"proven ancestor {ref} is itself a commit snapshot; refusing to "
            "treat it as a clean parent"
        )
        return None, relationship

    parent_info.is_clean_parent = True
    parent_info.parent_image = None

    relationship.verified = True
    relationship.relationship = result.value
    relationship.candidate_image = parent_info.reference
    relationship.candidate_source = source
    relationship.candidate_layer_count = len(parent_info.rootfs_layers)
    relationship.reason = (
        "candidate layer chain is identical to the runtime image "
        "(runtime image is already clean)"
        if result is LayerRelationship.IDENTICAL else
        f"candidate layer chain is an exact prefix of the runtime chain "
        f"({len(parent_info.rootfs_layers)}/{len(runtime_info.rootfs_layers)} layers)"
    )

    return parent_info, relationship


def find_clean_parent_image(runtime_image: str,
                            env_sh_path: str | None = None) -> ImageInfo | None:
    """Find the *proven* clean parent image for a runtime image.

    Thin wrapper around `resolve_clean_parent_image()` that discards the
    relationship record. Returns None when the relationship cannot be proven -
    naming or env.sh agreement alone never yields a result here.

    Args:
        runtime_image: The runtime image (possibly a snapshot)
        env_sh_path: Path to env.sh for candidate discovery

    Returns:
        ImageInfo for the clean parent, or None if unproven
    """
    parent, _relationship = resolve_clean_parent_image(runtime_image, env_sh_path)
    return parent


def _parse_base_tag_from_env_sh(env_sh_path: str) -> str | None:
    """Parse the base image tag from env.sh.

    Looks for IMAGE_TAG or similar that's NOT the override.

    Args:
        env_sh_path: Path to env.sh

    Returns:
        Base image tag or None
    """
    try:
        with open(env_sh_path, "r") as f:
            content = f.read()

        # Look for variables that define the base image
        # Pattern: export VAR="value" or VAR="value"
        patterns = [
            r'LOCAL_BASE_TAG[=\s]+"([^"]+)"',
            r'LOCAL_BASE_TAG[=\s]+\'([^\']+)\'',
            r'IMAGE_NAMESPACE[=\s]+"([^"]+)"',
        ]

        namespace = None
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                value = match.group(1)
                if "LOCAL_BASE_TAG" in pattern:
                    return value
                elif "IMAGE_NAMESPACE" in pattern:
                    namespace = value

        # Try to construct from components
        if namespace:
            # Look for other components
            ubuntu = re.search(r'UBUNTU_VERSION[=\s]+"?(\d+\.\d+)"?', content)
            cuda = re.search(r'CUDA_VERSION[=\s]+"?([^"]+)"?', content)
            ros = re.search(r'ROS_DISTRO[=\s]+"?(\w+)"?', content)

            if ubuntu and cuda and ros:
                # Build conventional tag name
                # Format: namespace/workspace:...ubuntu{ver}-gpu-cuda{ver}-ros{distro}-...
                tag = f"{namespace}/workspace:ubuntu{ubuntu.group(1)}-gpu-cuda{cuda.group(1)}-ros{ros.group(1)}"
                return tag

    except (OSError, IOError):
        pass

    return None


def _find_candidate_parent_images(repository: str) -> list[str]:
    """Find candidate parent images by repository.

    Args:
        repository: Image repository

    Returns:
        List of image references
    """
    try:
        result = run_docker([
            "images", "--format", "{{.Repository}}:{{.Tag}}",
            "--filter", f"reference={repository}:*"
        ])
        images = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        return images
    except DockerError:
        return []


def get_image_history(image: str) -> list[dict[str, Any]]:
    """Get image history (layer information).

    Args:
        image: Image name or ID

    Returns:
        List of history entries
    """
    from docker_migration_tool.utils.docker import get_image_history as _get_history
    return _get_history(image)


def get_image_size_estimate(image: str) -> dict[str, int]:
    """Get size estimates for an image.

    Args:
        image: Image name or ID

    Returns:
        Dict with size estimates
    """
    info = inspect_image(image)

    # Size from inspect is compressed blob total (docker save size)
    # Actual disk usage is larger (uncompressed)
    return {
        "compressed_bytes": info.size_bytes,
        "estimated_save_bytes": info.size_bytes,
        # Rough estimate: uncompressed is ~3x compressed for typical images
        "estimated_disk_bytes": info.size_bytes * 3,
    }
