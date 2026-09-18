# Docker Migration Tool Real Migration Fixes

Report Date: 2026-09-18

## 1. Summary

This document records fixes for issues discovered during an actual User A → User B
migration test of the docker-migration-tool. The fixes address 2 P0 (critical),
2 P1 (important), and 1 P2 (enhancement) issues while maintaining the tool's
security guarantees and backward compatibility with existing bundles.

**Key changes:**
- Export now normalizes `RUNTIME_IMAGE_TAG_OVERRIDE` in env.sh to the clean parent image
- Import preflight now verifies runtime image consistency between bundle and config
- All portable Docker config files are now checksummed for integrity verification
- Dry-run import correctly shows the planned workspace path (not "None")
- `--workspace` semantics documented: filesystem path, not workspace rename
- Installation instructions updated for Ubuntu 24.04 / PEP 668

**Test impact:** 12 new regression tests added (296 → 308 total tests, all passing)

## 2. Issues Found During Real A-to-B Migration

| ID  | Priority | Issue |
|-----|----------|-------|
| 2.1 | P0 | Snapshot `RUNTIME_IMAGE_TAG_OVERRIDE` leaked into portable config |
| 2.2 | P0 | Import preflight did not verify runtime image consistency |
| 2.3 | P1 | Portable Docker config files were not checksummed |
| 2.4 | P1 | `import --dry-run` showed `Workspace: None` instead of planned path |
| 2.5 | P2 | `--workspace` rename semantics were unclear |

### 2.1 P0: Snapshot RUNTIME_IMAGE_TAG_OVERRIDE Leaked

**Symptom:** Source env.sh contained:
```bash
export RUNTIME_IMAGE_TAG_OVERRIDE="robotics_team/workspace:omori_humble_basic_ws-snapshot-20260917"
```

Bundle exported the clean parent:
```
robotics_team/workspace:ubuntu22.04-gpu-cuda12.8.1-roshumble-gazebo-opencv4.10.0-chrome
```

But the exported `docker/config/env.sh` still referenced the source snapshot.
On import, compose would try to start a container from an image that doesn't
exist in the bundle.

**Root cause:** `_export_docker_config()` copied env.sh verbatim without
normalizing the runtime image reference.

### 2.2 P0: Missing Runtime Image Consistency Check

**Symptom:** The mismatch in 2.1 was only discovered by manual grep.

**Root cause:** Import preflight verified security metadata but never checked
that the bundle's clean image matched what the config would actually use.

### 2.3 P1: Missing Config Checksums

**Symptom:** After User B manually edited env.sh to fix 2.1, running
`docker-migration verify` on the bundle did not detect the change.

**Root cause:** Only `docker/image/base-image.tar` and `workspace/src.tar.zst`
had checksums in MANIFEST.json. Portable config files could be tampered.

### 2.4 P1: Dry-run "Workspace: None"

**Symptom:**
```
=== Import Complete ===
[OK] Workspace: None
```

**Root cause:** Dry-run returned early without determining the workspace path,
and the CLI displayed the unset value.

### 2.5 P2: Unclear --workspace Semantics

**Symptom:** User unsure whether `--workspace /path/new_name` would rename the
workspace identity, change container names, etc.

**Root cause:** Not documented; required code inspection to understand.

## 3. Root Causes

### 3.1 Snapshot Runtime Override Leakage

The `_export_docker_config()` method in `export/bundle.py` used `shutil.copy()`
for all portable files without any content transformation. The env.sh from the
source workspace was copied byte-for-byte, preserving any `RUNTIME_IMAGE_TAG_OVERRIDE`
that pointed to the source runtime (often a snapshot).

When common.sh evaluates:
```bash
RUNTIME_IMAGE_TAG="${RUNTIME_IMAGE_TAG_OVERRIDE:-${IMAGE_TAG}}"
```

...and compose uses `RUNTIME_IMAGE_TAG`, the target machine would try to use
the source snapshot image that the bundle deliberately does not contain.

### 3.2 Missing Runtime Image Consistency Check

Import preflight (`importers/preflight.py`) verified:
- Docker / compose availability
- Disk space
- GPU availability (if needed)
- Bundle security metadata (parent_relationship_verified, layer_secret_scan_result)
- Bundle structure and existing checksums

But it did not verify that the bundle's clean_base_image matched the runtime
image the config would resolve to at startup time.

### 3.3 Incomplete Bundle Integrity Coverage

The checksum system in MANIFEST.json only covered:
- `docker/image/base-image.tar` (the exported clean image)
- `workspace/src.tar.zst` (the workspace archive)

Portable config files (`env.sh`, `common.sh`, `config.sh`, `docker-compose.yml`,
`Dockerfile`, udev rules, xauthority scripts) had no checksums, allowing
undetected modification.

### 3.4 Dry-run Workspace None Output

In `importers/restore.py`, the dry-run path returned early:
```python
if self.dry_run:
    self._dry_run_report()
    return ImportResult(
        success=True,
        verifications=self.verifications,
        warnings=["Dry run - no changes made"],
    )
```

The `workspace_path` field was not set because `_determine_workspace_path()`
was only called later in the non-dry-run path.

### 3.5 Workspace Rename Semantics

`--workspace` was documented only as "Target workspace path" without explaining:
- It's a filesystem path, not a workspace rename
- The logical `workspace_name` from the source is preserved in MANIFEST.json
- Container names / compose project names are derived from `workspace_name`
- Running multiple copies requires manual config edits

## 4. Design Decisions

### 4.1 Source Provenance vs Target Runtime Config

**Decision:** Separate audit/provenance information from executable configuration.

- **MANIFEST.json** keeps `source_runtime_image` (the snapshot) for audit
- **Exported env.sh** is normalized to `RUNTIME_IMAGE_TAG_OVERRIDE=<clean parent>`
- Import never sees the source snapshot tag as a runtime target

This ensures the bundle is self-consistent: what you import is what you get.

### 4.2 Clean Parent Image Guarantee

**Decision:** Export normalizes env.sh; import verifies consistency.

Defense in depth:
1. Export rewrites `RUNTIME_IMAGE_TAG_OVERRIDE` to the proven clean parent
2. Import preflight parses env.sh and verifies it matches `clean_base_image`
3. If mismatch (old tool version or tampering), import is blocked

### 4.3 Bundle Immutability

**Decision:** Bundles should be immutable artifacts after export.

- Export does all normalization (env.sh rewrite happens at export time)
- Import never modifies bundle files (it copies config to target workspace)
- Checksums cover all files that affect import behavior
- `verify` can detect any post-export tampering

### 4.4 Checksum Scope

**Decision:** Checksum all portable config files, not just archives.

Files now checksummed:
- `docker/image/base-image.tar`
- `workspace/src.tar.zst`
- `docker/config/Dockerfile`
- `docker/config/docker-compose.yml`
- `docker/config/env.sh`
- `docker/config/common.sh`
- `docker/config/config.sh`
- `docker/config/.dockerignore`
- `docker/config/udev/*`
- `docker/config/install_*.sh`
- `docker/config/xauthority/*`

Not checksummed (informational only):
- `MANIFEST.json` (self-reference problem)
- `README.md` (bundle's own readme)
- `GENERATED_FILES_NOTE.txt`

### 4.5 Backward Compatibility

**Decision:** Accept bundles with complete security metadata even if they lack config checksums.

- Bundles from older tool versions will pass import if:
  - `parent_relationship_verified = true`
  - `layer_secret_scan_result = "passed"`
  - `image_config_scan_result = "passed"`
- The runtime image consistency check may warn but not fail if env.sh is absent
- Config checksum verification only runs for files in `checksums{}` dict

## 5. Files Changed

### src/docker_migration_tool/export/bundle.py

- Added `import re` to imports
- Modified `_export_docker_config()`:
  - Track copied files for checksumming
  - Call `_normalize_env_sh_runtime_image()` after copying env.sh
  - Call `_checksum_portable_config()` before returning
- Added `_normalize_env_sh_runtime_image()`:
  - Reads env.sh, finds RUNTIME_IMAGE_TAG_OVERRIDE
  - Rewrites the value to `clean_base_image`
  - Adds comment indicating normalization
- Added `_checksum_portable_config()`:
  - Computes SHA256 for all portable config files
  - Stores in `self.checksums` and `self.manifest.checksums`

### src/docker_migration_tool/importers/preflight.py

- Added `_check_runtime_image_consistency()` call in `run()`
- Added `_check_runtime_image_consistency()` method:
  - Reads clean_base_image from manifest
  - Parses env.sh to find resolved runtime image
  - Errors if mismatch
- Added `_resolve_runtime_image_from_config()`:
  - Regex parsing of RUNTIME_IMAGE_TAG_OVERRIDE, IMAGE_TAG, LOCAL_BASE_TAG
  - Returns resolved image or None

### src/docker_migration_tool/importers/restore.py

- Modified dry-run path to call `_determine_workspace_path()` before report
- Modified dry-run result to include `workspace_path`
- Changed log message from "Would restore to:" to "Planned workspace:"

### src/docker_migration_tool/cli.py

- Modified `cmd_import()` to show different completion message for dry-run:
  - Dry-run: "Dry Run Complete" / "Planned workspace: ..."
  - Real import: "Import Complete" / "Workspace: ..."

### README.md

- Added Ubuntu 24.04 installation instructions with venv
- Added `--workspace` semantics section under Import
- Updated test count from 296 to 308

### README_ja.md

- Added Ubuntu 24.04 installation instructions with venv (Japanese)
- Added `--workspace` semantics section under import (Japanese)
- Updated test count from 296 to 308

### tests/test_real_migration_fixes.py (new file)

Created comprehensive test file with 12 tests covering all fixes.

## 6. Tests Added / Updated

### tests/test_real_migration_fixes.py (NEW - 12 tests)

| Test Class | Test Method | Validates |
|------------|-------------|-----------|
| TestSnapshotOverrideNormalization | test_snapshot_override_replaced_with_clean_parent | P0: Export normalizes RUNTIME_IMAGE_TAG_OVERRIDE |
| TestSnapshotOverrideNormalization | test_no_override_leaves_env_sh_unchanged | No false positive modification |
| TestRuntimeImageConsistencyCheck | test_matching_images_pass | P0: Matching bundle/config passes |
| TestRuntimeImageConsistencyCheck | test_mismatched_images_fail | P0: Mismatch detected and blocked |
| TestRuntimeImageConsistencyCheck | test_no_override_assumes_clean_parent | No env.sh = safe assumption |
| TestPortableConfigChecksum | test_config_files_have_checksums | P1: All config files checksummed |
| TestPortableConfigChecksum | test_tampered_config_fails_verify | P1: Tampering detected |
| TestDryRunWorkspacePath | test_dry_run_returns_planned_workspace | P1: Explicit path shown |
| TestDryRunWorkspacePath | test_dry_run_uses_default_workspace_when_not_specified | P1: Default path shown |
| TestWorkspaceRenameSemantics | test_workspace_path_is_filesystem_target | P2: Path vs identity |
| TestBackwardCompatibility | test_bundle_without_config_checksums_passes_verify | Old bundles work |
| TestBackwardCompatibility | test_bundle_missing_security_metadata_rejected | Unsafe bundles blocked |

## 7. Test Results

```
$ python -m pytest -o addopts="" -q
308 passed in 0.21s

$ python -m pytest -o addopts="" --collect-only -q
308 tests collected
```

### Per-file breakdown (after changes):

| Test File | Count |
|-----------|-------|
| test_image_config_scan.py | 89 |
| test_publication_safety.py | 54 |
| test_workspace_exclusion.py | 24 |
| test_layer_scan.py | 23 |
| test_security.py | 21 |
| test_security_metadata.py | 18 |
| test_filesystem.py | 15 |
| test_logging.py | 14 |
| test_security_display.py | 13 |
| test_model.py | 13 |
| test_real_migration_fixes.py | 12 |
| test_parent_relationship.py | 12 |
| **Total** | **308** |

## 8. README Changes

### English (README.md)

1. **Installation section**: Added Ubuntu 24.04 subsection with venv-based
   installation to avoid PEP 668 `externally-managed-environment` error.
   Explicitly warns against `--break-system-packages`.

2. **Import section**: Added `### --workspace semantics` subsection explaining:
   - `--workspace` is a filesystem path, not a workspace rename
   - Logical `workspace_name` preserved from source
   - Container/project names derived from `workspace_name`
   - Multiple copies require manual config edits

3. **Tests section**: Updated count from 296 to 308.

### Japanese (README_ja.md)

1. **インストール section**: Added Ubuntu 24.04 subsection with Japanese
   explanation of venv approach.

2. **import section**: Added `### --workspace の意味` subsection with
   equivalent Japanese documentation.

3. **テスト section**: Updated count from 296 to 308.

## 9. Backward Compatibility

### Bundles from older tool versions

✅ **Compatible** if they have:
- `parent_relationship_verified: true`
- `layer_secret_scan_result: "passed"`
- `image_config_scan_result: "passed"`

These bundles will:
- Pass security metadata checks
- Skip config checksum verification (no checksums in manifest)
- Potentially warn on runtime image consistency if env.sh has an old override

### Unsafe legacy bundles

❌ **Rejected** if they lack security metadata fields entirely.
This was already the case before these changes.

### Config checksum handling

- Checksums are verified only for files present in `manifest.checksums`
- Old bundles without config checksums will not fail verification
- New bundles will have comprehensive checksum coverage

## 10. Remaining Limitations

### Not addressed in this fix

1. **Automatic env.sh IMAGE_TAG resolution**: The consistency check looks for
   `RUNTIME_IMAGE_TAG_OVERRIDE` first, then falls back to `IMAGE_TAG` or
   `LOCAL_BASE_TAG`. Complex shell variable expansions in env.sh are not
   evaluated; the check may return "undetermined" in such cases.

2. **Workspace rename feature**: This fix documents that `--workspace` is a
   path, not a rename. A proper rename feature (`--workspace-name NEW_NAME`)
   would require additional work to update container/project names consistently.

3. **common.sh / config.sh evaluation**: The runtime image consistency check
   does not execute shell scripts to determine the final resolved image. It
   relies on pattern matching in env.sh. If the workspace uses unusual variable
   indirection, the check may not detect a mismatch.

4. **Migration between different workspace layouts**: The tool assumes a
   colcon-style `<workspace>/src` layout with bind mounts. Non-standard
   workspace structures may require manual adaptation.

### Security guarantees unchanged

All existing security gates remain intact:
- Snapshot images are never exported
- Clean parent is proven by RootFS layer prefix
- Image config/history scan blocks credential leakage in ENV/ARG/RUN
- Full layer scan blocks credential paths in any layer
- Archive extraction safety (path traversal, absolute paths, symlinks, devices)
- Host-side subprocesses use argument lists, never shell=True

---

*This report was generated as part of the real-migration-fixes task.*
