# Docker Migration Tool Compose Build Portability Fix

## 1. Summary

Compose-built runtime images now export their proven local build base, preserve
portable build contexts, validate build inputs before export and import, and
report required import stage failures as incomplete with a non-zero exit code.

## 2. Real Migration Incident

### 2.1 Wrong Image Exported

The SO101 source runtime used `so101-demo:20260930-cpu-v13-user-robotics-team-1000-1000`.
The target's `config.sh` generated a different identity tag, but the prior
bundle carried the source identity image instead of `so101-demo:20260930-cpu-v13`.
Docker attempted to pull that local-only base and failed.

### 2.2 Missing Build Context

The fixed Docker configuration allowlist omitted `Dockerfile.user`,
`create_container_user.sh`, `entrypoint.sh`, and `verify_container_user.sh`.
The restored Compose build could not read its Dockerfile.

### 2.3 Import False Success

A failed `docker compose up -d` was appended to an error list but the restore
method still returned `success=True`, leading to `Import Complete` and exit 0.

## 3. Root Causes

Image discovery did not use Compose's build graph. Portable config export and
restore used fixed filenames. Import did not check collected errors before
returning success.

## 4. Existing Architecture

Export inspects the container, proves a clean image using ordered RootFS layers,
scans image config/history, final filesystem and every saved layer, then archives
workspace source and Docker config. Import preflight checks security metadata
and bundle checksums before loading and restoring artifacts. These gates remain.
The existing `core.py` exclusion fix was preserved.

## 5. Portable Image Selection Design

Compose's normalized JSON config supplies service `image`, `build.context`,
`build.dockerfile`, and `build.args`. Dockerfile `ARG`/`FROM` resolves the base.
The runtime service image must match the inspected runtime image, the base must
exist locally, and its RootFS layers must be a strict prefix of the runtime
layers. A snapshot base is rejected. This graph plus layer proof selects the
portable base; otherwise existing clean-parent discovery remains the fallback.
An unmatched Compose build output blocks export instead of silently selecting
the runtime wrapper. For SO101, 18 base layers are a strict prefix of 23 runtime layers.

## 6. Docker Build Context Export Design

Export traverses each Compose context tree and retains portable files, including
custom Dockerfiles, scripts, `COPY directory/`, and `COPY .` sources. Context
paths are mapped back to their workspace-relative locations on restore.
The `.dockerignore` is retained; it is consulted when deciding whether an
excluded sensitive file is actually required by a broad `COPY .`. The bundle
may contain additional safe context files beyond what Docker sends to a build,
because migration also preserves scripts and configuration used outside build.
Missing Dockerfiles and local COPY/ADD sources block export.

## 7. Security Handling

The existing secret path, workspace artifact, and generated config policies
exclude `.env`, auth files, cloud/SSH/AI credentials, Xauthority, generated
build/log files and generated overrides. Timestamped
`.env` and override backups are excluded as well. A build that needs an excluded
sensitive file fails closed. Symlinks in build context are rejected rather than
followed. Existing image security scans and safe workspace extraction remain.

## 8. Import Preflight Changes

Before image load, import stages the portable Docker config and context files,
parses Compose without host interpolation, confirms each build context,
Dockerfile and local source, and checks that each resolved `FROM` is the bundled
base or an explicitly declared external image. Legacy no-build Compose bundles
remain accepted. Old build bundles missing a Dockerfile fail preflight.

## 9. Import Failure Semantics

Required stage failures now return `success=False`, print `Import Incomplete`,
show the failed and completed stages, retain restored files, and exit non-zero.
This includes host config regeneration, container start and dependency restore.
Post-import verification confirms a running Compose container. A legacy
workspace without an installer can start and requests manual dependency setup.
Dry-run has its own completion heading.

## 10. Manifest / Checksums

`source_runtime_image` remains. New metadata records `portable_base_image`,
`runtime_image_rebuild_required`, `runtime_build_service`,
`runtime_build_context`, and `runtime_build_dockerfile`. Each portable context file has an individual SHA256
entry in `MANIFEST.json`; verify and import preflight use existing checksum
validation. `bundle-info` and import dry-run display the base and rebuild plan.

## 11. Backward Compatibility

Build-free legacy bundles continue to import. Missing new metadata alone does
not reject them. Existing security metadata requirements remain. Old bundles
with incomplete Compose builds now fail preflight, as intended.

## 12. Files Changed

`src/docker_migration_tool/inspect/compose_build.py`, `model.py`, `cli.py`,
`export/bundle.py`, `importers/preflight.py`, `importers/restore.py`,
`tests/test_compose_build_portability.py`, `README.md`, and `README_ja.md`.
The pre-existing core dump fix files were left intact.

## 13. Tests

Before this task: 322 passed. New portability test functions: 14. Final suite:
338 passed (`.venv/bin/python -m pytest -o addopts='' -q`). The final collected
total includes two additional cases in the existing working-tree tests. New
tests cover graph/base proof, custom Dockerfile/scripts, directory and dot COPY,
excluded secrets, missing Dockerfile/base preflight, legacy no-build, context
checksums, and non-zero import after Compose start failure.

## 14. SO101 Real-World Verification

A final new bundle was generated only under `/tmp/docker-migration-compose-fix-final-20260930`.
Portable base selected: `so101-demo:20260930-cpu-v13`. The host wrapper was not
exported as the portable base. `Dockerfile.user`, `create_container_user.sh`,
`entrypoint.sh`, and `verify_container_user.sh` are included. `so101_demo/core.py`
remains in `workspace/src.tar.zst`. Bundle verify passed 21/21 checks. Import
dry-run passed preflight and reports the base load and runtime rebuild.

## 15. Remaining Limitations

Only local contexts within the discovered workspace are exported. Dynamic
COPY/ADD expressions and unsupported Dockerfile features fail closed. Multiple
Compose services requiring different local base images are rejected before
export; a future bundle schema could carry several proven bases. The
`.dockerignore` check covers common glob and negation rules, but complex Docker
pattern behavior may require an exact Docker parser. Actual import on a second
PC was not run; verification used the source host and a read-only import dry-run.

## 16. GitHub Repository Integration (2026-10-01)

The GitHub clone retained its existing legacy-runtime `env.sh`
`RUNTIME_IMAGE_TAG_OVERRIDE` normalization, import consistency check, and
portable-config checksums. Normalization and the legacy consistency check apply
when no Compose runtime rebuild is required; the Compose build graph validates
the separate portable base and target runtime image. Checksums are calculated
after normalization and cover every portable config and context file.

The GitHub repository's `test_real_migration_fixes.py` remains, with four
empty Compose fixtures changed to valid build-free services for the new Compose
parser. The merged suite passed 370/370 tests. A new SO101 bundle under
`/tmp/docker-migration-github-sync-check-20261001` selected the portable base,
included the custom Dockerfile and helpers with checksums, retained `core.py`,
and passed bundle verify 22/22 plus import dry-run preflight. No Git commit or
push was performed.
