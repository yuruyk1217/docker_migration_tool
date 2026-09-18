"""Data models for the migration tool.

All collected data is classified into:
- A: Reproducible from image/repository
- B: Mutable user state (User A added after image build)
- C: Host-dependent (must be re-detected/configured on User B)
- D: Secret/personal state (must NOT be auto-migrated)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Classification(Enum):
    """Classification of migration items."""
    A = "reproducible"      # From image/repository
    B = "mutable_state"     # User A added after build
    C = "host_dependent"    # Must be re-detected on User B
    D = "secret"            # Must NOT be migrated


@dataclass
class MountInfo:
    """Information about a container mount."""
    host_source: str
    container_target: str
    mode: str  # rw, ro
    mount_type: str  # bind, volume
    propagation: str | None = None
    classification: Classification = Classification.C
    migration_action: str = "regenerate"
    is_workspace: bool = False


@dataclass
class VolumeInfo:
    """Information about a Docker volume."""
    name: str
    driver: str
    mountpoint: str
    labels: dict[str, str] = field(default_factory=dict)
    classification: Classification = Classification.B


@dataclass
class ImageInfo:
    """Information about a Docker image."""
    repository: str
    tag: str
    image_id: str
    digest: str | None = None
    size_bytes: int = 0
    size_compressed_bytes: int = 0
    layer_count: int = 0
    created: str | None = None
    is_snapshot: bool = False
    is_clean_parent: bool = False
    parent_image: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)
    classification: Classification = Classification.A
    # Ordered RootFS layer diff IDs (.RootFS.Layers from docker image inspect).
    # ORDER IS SIGNIFICANT: parent/child provenance is proven by prefix match.
    rootfs_layers: list[str] = field(default_factory=list)

    @property
    def reference(self) -> str:
        """Return repository:tag (or the image id when untagged)."""
        if self.repository and self.tag:
            return f"{self.repository}:{self.tag}"
        return self.image_id


class LayerRelationship(Enum):
    """Result of comparing two RootFS layer chains."""
    STRICT_PREFIX = "strict_prefix"          # candidate is a proper ancestor
    IDENTICAL = "identical"                  # runtime image is already clean
    NOT_PREFIX = "not_prefix"                # chains diverge -> unrelated image
    CANDIDATE_LONGER = "candidate_longer"    # candidate is a descendant, not a parent
    MISSING_LAYER_DATA = "missing_layer_data"  # no .RootFS.Layers available
    SNAPSHOT_ITSELF = "snapshot_itself"      # candidate == the snapshot we must not export


@dataclass
class ParentRelationship:
    """Proof (or refutation) that a candidate image is the clean parent.

    This is the hard gate for export: candidate discovery by tag naming,
    env.sh or docker history is never accepted as proof on its own.
    """
    verified: bool = False
    method: str = "rootfs_layer_prefix"
    relationship: str = LayerRelationship.MISSING_LAYER_DATA.value
    runtime_image: str | None = None
    candidate_image: str | None = None
    runtime_layer_count: int = 0
    candidate_layer_count: int = 0
    candidate_source: str | None = None  # how the candidate was discovered
    reason: str | None = None
    rejected_candidates: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class LayerSecretFinding:
    """A credential-like path found inside an image layer archive.

    Records identity only: layer id, path and secret kind.
    File contents are never read, stored or logged.
    """
    layer: str
    path: str
    kind: str
    whiteout: bool = False
    classification: Classification = Classification.D


@dataclass
class LayerScanResult:
    """Result of the full-layer secret scan of an image archive."""
    performed: bool = False
    result: str = "not_performed"  # passed | failed | unsupported_format | not_performed
    scanner_version: str | None = None
    archive_format: str | None = None
    layers_scanned: int = 0
    entries_scanned: int = 0
    findings: list[LayerSecretFinding] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    message: str | None = None

    @property
    def passed(self) -> bool:
        return self.performed and self.result == "passed"


@dataclass
class ImageConfigSecretFinding:
    """A credential-like item found in image config metadata or build history.

    Records identity only: the metadata surface, the key name (when the surface
    has one), the kind and - for name matches - which vocabulary pattern
    matched.

    An environment variable VALUE is NEVER stored here. A value-side detection
    records `matched=True` and kind "possible_credential_value" only: not the
    value, not a fragment of it, not which detector fired.
    """
    source: str          # image_config_env | image_container_config_env |
                         # image_config_cmd | image_config_entrypoint |
                         # image_config_labels | image_history_created_by
    kind: str            # credential_environment | credential_label |
                         # possible_credential_value
    key: str | None = None
    matched: bool = True
    matched_pattern: str | None = None  # e.g. "*TOKEN*", "AWS_*" (name matches)
    location: str | None = None         # e.g. "Config.Env", "history[12]"
    classification: Classification = Classification.D


@dataclass
class ImageConfigScanResult:
    """Result of the image config metadata / build history credential scan."""
    performed: bool = False
    result: str = "not_performed"  # passed | failed | error | not_performed
    scanner_version: str | None = None
    env_vars_scanned: int = 0
    labels_scanned: int = 0
    history_entries_scanned: int = 0
    container_config_present: bool = False
    findings: list[ImageConfigSecretFinding] = field(default_factory=list)
    # Keys whose NAME matched the secret vocabulary but which are allowlisted as
    # structurally non-credential (their values were still scanned).
    allowlisted_keys: list[str] = field(default_factory=list)
    message: str | None = None

    @property
    def passed(self) -> bool:
        return self.performed and self.result == "passed"


@dataclass
class ContainerInfo:
    """Information about a Docker container."""
    name: str
    container_id: str
    image: str
    image_id: str
    state: str
    created: str
    user: str  # uid:gid
    privileged: bool = False
    network_mode: str = "bridge"
    ipc: str = "private"
    shm_size: str | None = None
    mounts: list[MountInfo] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    # Derived from compose labels
    compose_project: str | None = None
    compose_working_dir: str | None = None
    compose_config_files: list[str] = field(default_factory=list)
    # Workspace info
    workspace_name: str | None = None
    workspace_path: str | None = None
    ros_workspace: str | None = None
    container_username: str | None = None


@dataclass
class GitRepoInfo:
    """Information about a git repository."""
    path: str
    remote_url: str | None = None
    branch: str | None = None
    head_commit: str | None = None
    upstream: str | None = None
    ahead: int = 0
    behind: int = 0
    is_dirty: bool = False
    modified_files: list[str] = field(default_factory=list)
    untracked_files: list[str] = field(default_factory=list)
    submodules: list["GitRepoInfo"] = field(default_factory=list)
    classification: Classification = Classification.B


@dataclass
class PackageManifest:
    """Package manifest for restoration."""
    apt_manual: list[str] = field(default_factory=list)
    apt_versions: dict[str, str] = field(default_factory=dict)
    pip_freeze: list[str] = field(default_factory=list)
    pip_constraints: list[str] = field(default_factory=list)
    python_version: str | None = None
    ros_distro: str | None = None
    has_install_script: bool = False
    install_script_path: str | None = None


@dataclass
class HostInfo:
    """Host system information for compatibility comparison."""
    os_name: str
    os_version: str
    kernel: str
    architecture: str
    cpu: str | None = None
    ram_gb: int = 0
    docker_version: str | None = None
    compose_version: str | None = None
    gpu_model: str | None = None
    nvidia_driver: str | None = None
    nvidia_toolkit: str | None = None
    uid: int = 0
    gid: int = 0
    groups: list[str] = field(default_factory=list)
    disk_free_gb: int = 0
    display: str | None = None
    classification: Classification = Classification.C


@dataclass
class HardwareInventory:
    """Hardware device inventory."""
    cameras_by_id: list[str] = field(default_factory=list)
    serial_by_id: list[str] = field(default_factory=list)
    serial_by_path: list[str] = field(default_factory=list)
    usb_devices: list[dict[str, str]] = field(default_factory=list)
    dri_devices: list[str] = field(default_factory=list)
    sound_devices: list[str] = field(default_factory=list)
    dri_gid: int | None = None
    audio_gid: int | None = None
    render_gid: int | None = None
    classification: Classification = Classification.C


@dataclass
class NetworkIntent:
    """Network configuration intent (no credentials)."""
    interface_name: str
    interface_type: str  # ethernet, wifi, usb-rndis
    address: str | None = None
    subnet: str | None = None
    gateway: str | None = None
    connection_name: str | None = None
    purpose: str | None = None
    classification: Classification = Classification.C


@dataclass
class SecretFinding:
    """A detected secret (existence only, never content)."""
    path: str
    kind: str
    exists: bool
    size_bytes: int | None = None
    location: str = "unknown"  # image, container, host
    classification: Classification = Classification.D


@dataclass
class LargeFile:
    """Information about a large file in the workspace."""
    path: str
    size_bytes: int
    sha256: str | None = None
    is_gitignored: bool = False
    classification: Classification = Classification.B


@dataclass
class ExcludedLargeFile:
    """A large file dropped by the workspace exclusion policy.

    Audit information only. An excluded file is not archived, not checksummed
    and never recorded in LARGE_FILES.json as an included file.
    """
    path: str
    size_bytes: int
    excluded_by: str  # the exclude pattern that matched
    classification: Classification = Classification.B


class SecurityCheckState(Enum):
    """State of one security check.

    The image security checks have different scopes and must never be
    collapsed into a single "passed" claim:

        config_metadata_scan:  image config metadata + build history (no files)
        final_filesystem_scan: the merged final filesystem of the clean image
        layer_scan:            every layer archive inside `docker save` output
    """
    NOT_PERFORMED = "not_performed"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED_DRY_RUN = "skipped_dry_run"
    UNSUPPORTED_FORMAT = "unsupported_format"
    ERROR = "error"


@dataclass
class SecurityStatus:
    """Per-check security state, kept separate so logs cannot overstate it."""
    config_metadata_scan: str = SecurityCheckState.NOT_PERFORMED.value
    final_filesystem_scan: str = SecurityCheckState.NOT_PERFORMED.value
    layer_scan: str = SecurityCheckState.NOT_PERFORMED.value

    @property
    def all_required_checks_passed(self) -> bool:
        """True only when EVERY required image security check passed.

        Required: the config metadata / history scan, the final-filesystem path
        scan and the full image-layer path scan. A dry run can perform the first
        two, so it can never satisfy this.
        """
        passed = SecurityCheckState.PASSED.value
        return (
            self.config_metadata_scan == passed
            and self.final_filesystem_scan == passed
            and self.layer_scan == passed
        )


@dataclass
class PortableDockerConfig:
    """Portable Docker configuration files."""
    dockerfile_path: str | None = None
    dockerfile_content: str | None = None
    compose_yml_path: str | None = None
    env_sh_path: str | None = None
    common_sh_path: str | None = None
    config_sh_path: str | None = None
    dockerignore_path: str | None = None
    udev_rules_path: str | None = None
    udev_install_script: str | None = None
    xauthority_install_script: str | None = None
    xauthority_sync_script: str | None = None
    xauthority_desktop_template: str | None = None


@dataclass
class BundleManifest:
    """Manifest for a migration bundle."""
    schema_version: str = "1.0.0"
    tool_version: str = "1.0.0"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    source_host: str | None = None
    workspace_name: str | None = None
    # Container-side path of the workspace src mount on the source machine.
    # Recorded so import can locate in-workspace helper scripts inside the
    # container instead of hardcoding anyone's home directory; it is a
    # container path, not a host path.
    workspace_container_target: str | None = None
    container_name: str | None = None
    # Image info
    source_runtime_image: str | None = None  # The snapshot (NOT exported)
    clean_base_image: str | None = None      # The clean parent (exported)
    clean_base_image_id: str | None = None
    clean_base_image_digest: str | None = None
    clean_base_image_size: int = 0
    # Components
    components: list[str] = field(default_factory=list)
    # Checksums
    checksums: dict[str, str] = field(default_factory=dict)  # path -> sha256
    # Metadata
    ros_distro: str | None = None
    ros_domain_id: int | None = None
    container_username: str | None = None
    # Classification summary
    classification_summary: dict[str, int] = field(default_factory=dict)
    # Security metadata (import refuses bundles that lack or fail these)
    parent_relationship_verified: bool = False
    parent_relationship_method: str | None = None
    runtime_layer_count: int = 0
    clean_image_layer_count: int = 0
    layer_secret_scan: bool = False
    layer_secret_scan_result: str = "not_performed"
    scanner_version: str | None = None
    # Recorded separately from the layer scan: a passing final-filesystem scan
    # is NOT evidence that the layers are clean. Import gates on the layer scan.
    final_filesystem_scan_result: str = "not_performed"
    # Image config metadata / build history credential scan (Config.Env,
    # ContainerConfig.Env, Cmd, Entrypoint, Labels, history CreatedBy).
    # Import gates on this too: a credential in the image config travels with
    # `docker save` even when every layer path is clean.
    image_config_scan: bool = False
    image_config_scan_result: str = "not_performed"
    config_scanner_version: str | None = None


@dataclass
class InspectionResult:
    """Complete inspection result."""
    container: ContainerInfo | None = None
    runtime_image: ImageInfo | None = None
    clean_base_image: ImageInfo | None = None
    parent_relationship: ParentRelationship | None = None
    host: HostInfo | None = None
    hardware: HardwareInventory | None = None
    mounts: list[MountInfo] = field(default_factory=list)
    volumes: list[VolumeInfo] = field(default_factory=list)
    git_repos: list[GitRepoInfo] = field(default_factory=list)
    packages: PackageManifest | None = None
    docker_config: PortableDockerConfig | None = None
    network_intents: list[NetworkIntent] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    large_files: list[LargeFile] = field(default_factory=list)
    excluded_large_files: list[ExcludedLargeFile] = field(default_factory=list)
    workspace_path: str | None = None
    workspace_src_path: str | None = None  # authoritative src archive source
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    """Result of a verification check."""
    name: str
    passed: bool
    status: str  # ok, warning, error, skipped, manual
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportResult:
    """Result of import operation."""
    success: bool
    workspace_path: str | None = None
    container_name: str | None = None
    verifications: list[VerificationResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    manual_actions_required: list[str] = field(default_factory=list)
