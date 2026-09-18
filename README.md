# docker-migration-tool

Japanese version: [README_ja.md](README_ja.md)

Move a Docker-based ROS 2 development environment from one Linux machine to
another — the image, the workspace, the git state, the package manifests and the
host-specific configuration — while keeping known credential material out of the
bundle.

## Overview

`docker-migration-tool` inspects a *running* development container, proves which
image is safe to ship, packages everything reproducible into a self-describing
bundle directory, and restores that bundle on a second machine. Anything that is
host-specific (UID/GID, `DISPLAY`, device group ids, X11 cookie, generated
compose files) is regenerated on the target rather than copied, and anything
secret is deliberately left behind.

It is a single Python package with a `docker-migration` CLI and five
subcommands: `inspect`, `export`, `import`, `verify`, `bundle-info`.

```
source machine                     bundle directory                target machine
──────────────                     ────────────────                ──────────────
running container   ──inspect──▶   MANIFEST.json                   docker load
clean parent image  ──export───▶   docker/image/base-image.tar  ──▶ workspace extract
workspace src                      workspace/src.tar.zst        ──▶ config regenerate
git + package state                git/, packages/              ──▶ dependency install
host + hardware facts              host/, hardware/             ──▶ compared, not copied
```

## Quickstart

New to the tool? This is the whole migration, start to finish. "Machine A" is
the machine you are moving *from* (where the container runs today) and
"machine B" is the machine you are moving *to*. Everything up to step 4 happens
on A; everything from step 5 happens on B.

Replace `my-ros-container` with your own container name and
`~/ros/my_workspace` with wherever you want the workspace to live on B.

### 0. Install it on both machines

```bash
git clone <your-remote-url> docker-migration-tool
cd docker-migration-tool
pip install -e .

docker-migration --version        # confirms the CLI is on your PATH
```

You also need `docker`, the `docker compose` plugin, `zstd` and `git` on A, and
`docker` + `zstd` on B. On B, keep at least 60 GB free: the bundle and the
loaded image both have to fit.

### 1. Find the container name (machine A)

The container must be **running**, because the tool reads its live
configuration:

```bash
docker ps --format '{{.Names}}\t{{.Image}}'
```

Pick the name from the first column.

### 2. Look before you leap: `inspect` (machine A)

```bash
docker-migration inspect --container my-ros-container
```

This only reads. It writes nothing and changes no Docker state. Read the last
line of the output:

- `Clean parent image proven - export is possible` → you are good to continue.
- `Clean parent image NOT proven - cannot export` → stop here. The tool could
  not prove which image is safe to ship, and it will refuse to export. The
  output lists the candidates it rejected and why (usually: the container runs
  from a `docker commit` snapshot whose base image is no longer on the machine —
  pull or rebuild that base image and try again).

Add `--output inspection.json` if you want the full report as a file to read
later.

### 3. Rehearse the export: `export --dry-run` (machine A)

```bash
docker-migration export --container my-ros-container --dry-run
```

A dry run writes nothing, but it really does run three of the four security
gates, so this is where problems surface. Check that you see
`config_metadata_scan: passed` and `final_filesystem_scan: passed`. The line
`layer_scan: skipped_dry_run` is expected — that gate needs a real
`docker save`, so only step 4 can run it.

It also prints which workspace files would be archived and which large files
would be skipped. Skim that list: if something you need is missing, fix it now
rather than after the transfer.

### 4. Create the bundle: `export` (machine A)

```bash
docker-migration export \
  --container my-ros-container \
  --output ~/migration-bundles
```

This is the slow step — it exports the image with `docker save` and compresses
the workspace, so expect minutes to tens of minutes and tens of GB. When it
finishes you have one self-contained directory:

```bash
ls ~/migration-bundles
# migration_bundle_my_workspace_20250101_120000

docker-migration bundle-info \
  ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
```

If the export stops with `EXPORT BLOCKED: …`, that is a security gate doing its
job — nothing was written. Read the reason, remove the credential material it
names from the *image* (not just from the running container), rebuild, and
retry.

### 5. Copy the bundle to machine B

Any method that preserves the directory works. `rsync` is convenient because it
can be re-run if the link drops:

```bash
rsync -a --info=progress2 \
  ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 \
  target-host:~/migration-bundles/
```

### 6. Check what arrived: `verify` (machine B)

```bash
cd ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
docker-migration verify .
```

This re-checks the bundle structure, the manifest, the recorded security verdict
and every checksum, so it catches a truncated or corrupted transfer before you
act on it. A failed check means a non-zero exit code — copy again.

### 7. Rehearse the import: `import --dry-run` (machine B)

```bash
docker-migration import . --dry-run
```

Still no changes. It runs the target-machine preflight (Docker, disk space, GPU
if the bundle needs one) and then tells you exactly where it *would* restore the
workspace, which image it would load, which steps need `sudo`, and what will be
left for you to do by hand.

### 8. Restore: `import` (machine B)

```bash
docker-migration import . \
  --workspace ~/ros/my_workspace \
  --ros-domain-id 2
```

This loads the image, extracts the workspace, restores the portable Docker
config, regenerates the host-specific files for *this* machine, starts the
container and installs the workspace dependencies inside it. It will ask before
anything that needs `sudo` (the udev rules); add `--non-interactive` to skip the
prompts and have those steps reported as manual work instead.

`--workspace` is optional. Without it the workspace goes to
`$DOCKER_MIGRATION_WORKSPACE_ROOT/<workspace name>` if that variable is set,
otherwise to `~/docker_workspaces/<workspace name>`. Machine A's paths are never
reused on B.

### 9. Confirm it works, then finish by hand (machine B)

```bash
docker-migration verify ~/ros/my_workspace --container my-ros-container
less configuration/SECRETS_REQUIRED.md
```

The first command checks Docker access, the workspace layout, the config, the
running container, GPU, ROS and model weights. The second is your remaining
to-do list: your own credentials for each service, your own git access for the
recorded remotes, application-specific secret files and your network setup. No
credential travels in the bundle, so this step is never optional.

### The short version

```bash
# machine A
docker-migration inspect --container my-ros-container
docker-migration export  --container my-ros-container --dry-run
docker-migration export  --container my-ros-container --output ~/migration-bundles
# copy the bundle directory to machine B, then on machine B
docker-migration verify .
docker-migration import . --dry-run
docker-migration import . --workspace ~/ros/my_workspace --ros-domain-id 2
docker-migration verify ~/ros/my_workspace --container my-ros-container
```

## Why This Tool Exists

Copying a robotics development environment by hand is slow and unsafe:

- **`docker commit` snapshots leak credentials.** A long-lived development
  container usually has API tokens, SSH keys and cloud credentials somewhere
  under the user's home directory. Once they are in an image layer, deleting the
  files and committing again does **not** remove them: `docker save` still ships
  the lower layer that contains them. So this tool never exports a snapshot — it
  exports the clean, Dockerfile-derived parent image and rebuilds the rest from
  manifests.
- **"The clean parent" cannot be guessed from tag names.** A plausible tag, an
  `env.sh` variable or `docker history` output is a *hint*, not proof. The tool
  requires the candidate's ordered `RootFS.Layers` to be an exact prefix of the
  runtime image's layer chain before it will export it.
- **Half of a working environment is host-specific.** UID/GID, device group ids,
  X11 authority, generated `.env` and compose overrides must be *regenerated* on
  the new machine, not copied. Copying them produces an environment that starts
  and then fails in subtle ways.
- **A migration needs an audit trail.** Every bundle records what was exported,
  what was excluded, which security gates ran, and what the operator must supply
  by hand.

## Architecture

```
src/docker_migration_tool/
├── cli.py                 # argparse CLI: inspect / export / import / verify / bundle-info
├── model.py               # dataclasses: ContainerInfo, ImageInfo, BundleManifest, ...
├── inspect/               # read-only discovery
│   ├── container.py       #   docker inspect -> mounts, env, compose labels, workspace
│   ├── image.py           #   runtime image, snapshot detection, clean-parent proof
│   ├── host.py            #   OS, kernel, CPU/RAM, Docker, GPU, UID/GID, DISPLAY
│   ├── packages.py        #   apt manual list + versions, pip freeze, ROS distro
│   └── workspace.py       #   src tree, git repos, large files, exclusion policy
├── security/              # the gates
│   ├── scanner.py         #   credential *paths* (final filesystem)
│   ├── layers.py          #   credential *paths* in every saved layer
│   └── image_config.py    #   credential key names/values in config + build history
├── export/bundle.py       # bundle assembly, manifest, generated bundle README
├── importers/
│   ├── preflight.py       #   target-machine checks + bundle security verdict gate
│   └── restore.py         #   image load, workspace, config, udev, X11, dependencies
├── verify/checks.py       # bundle integrity and restored-workspace verification
└── utils/                 # docker/compose wrappers, safe archive handling, logging
```

Host-side subprocesses are invoked using argument lists, and `shell=True` is not
used; the Docker helpers wrap `docker` / `docker compose` with timeouts. Some
checks do run a shell *inside* a container (`docker exec sh -c …`), which is a
deliberate, separate thing: the command is built by this tool, and the shell is
the container's, not the host's.

## What Gets Migrated

Written into the bundle:

- **The clean parent image** (`docker/image/base-image.tar`), proven by layer
  prefix and scanned for secrets.
- **The workspace source tree** (`workspace/src.tar.zst`), taken from the
  authoritative `src` bind mount, with model weights and other large files
  included and checksummed.
- **Git state for every repository and submodule** under `src`: remote URL,
  branch, HEAD, upstream, ahead/behind counts, dirty flag, modified and
  untracked file lists.
- **Package manifests**: manually-installed apt packages, apt versions, `pip
  freeze`, ROS distro and Python version, plus a human-readable
  `INSTALLED_DEPENDENCIES.md`.
- **Portable Docker configuration**: `Dockerfile`, `docker-compose.yml`,
  `env.sh`, `common.sh`, `config.sh`, `.dockerignore`, udev rules and the
  X11-authority helper scripts.
- **Host and hardware facts** (`host/host_info.json`, `hardware/devices.json`,
  `hardware/network.json`) — recorded so the target can be *compared* with the
  source, not so values can be copied.
- **A verification checklist** (`verification/checks.json`) and a
  `configuration/SECRETS_REQUIRED.md` listing what the operator must supply.

## What Does Not Get Migrated

- **The runtime snapshot image.** Never exported, by design.
- **Any credential**: SSH private keys, API tokens, cloud credentials, Docker
  registry logins, Wi-Fi/NetworkManager secrets, browser or CLI auth files.
- **The X11 cookie** — regenerated on the target.
- **Generated host-specific files**: `.env`, `docker-compose.override.yml`,
  `compose.generated.yml`, `.docker.xauth` and similar.
- **Build products**: `build/`, `install/`, `log/`, `__pycache__/`, `core.*`
  dumps and `*.jsonl` logs are excluded from the workspace archive.
- **UID/GID, device group ids, `DISPLAY`, device paths** — detected on the target
  and regenerated by `config.sh`.
- **Camera calibration.** Extrinsics are physical to the source setup and must
  be redone.

## Security Model

Three ideas, applied everywhere:

1. **Nothing sensitive is retained.** The path-based scanners check *whether* a
   known credential path exists (and its size); they do not read file contents.
   The image config / build history scanner is different by necessity: to detect
   a baked-in token it pattern-matches the actual `ENV`/`ARG` values and the
   `CreatedBy` command strings **in memory**. What it keeps is deliberately
   narrow — source, key name, finding kind, and `matched: true` for a value
   match. Credential values and full history command strings are not written to
   logs, to `MANIFEST.json`, to any bundle file, or to any report.
   *Scope limit:* detection covers known credential paths and supported
   credential formats. Unknown, proprietary or obfuscated secret formats can be
   missed, so a passing scan is strong evidence, not a proof of absence.
2. **Unverified means unsafe.** A scan that could not run is an `error`, not a
   pass. An image config that cannot be parsed blocks the export. A bundle whose
   manifest lacks security metadata is refused on import as an unsafe legacy
   bundle.
3. **Proof beats naming.** The exported image is chosen by layer-chain
   comparison, and the workspace archive source is the real bind mount, not a
   path assembled from a name.

Environment variables whose *names* look credential-like
(`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*`,
`*PRIVATE*`, `AWS_*`, `OPENAI_*`, `ANTHROPIC_*`, `GITHUB_*`, `AZURE_*`,
`DOCKER_*`, `NPM_*`, `PYPI_*`) are shown and stored as `[REDACTED]`.

## Requirements

On both machines:

- **Python 3.10 or newer** (the code uses PEP 604 `X | Y` annotations). No
  third-party runtime dependencies.
- **Docker Engine** with the `docker compose` plugin, and a user who can reach
  the daemon. The tool checks that both are present and that the daemon answers;
  it does not enforce a minimum version.
- **`zstd`** on the command line, for the workspace archive.
- **`git`**, for reading workspace repository state (export side).
- **`sudo`**, only for installing udev rules during import (optional and
  prompted).
- **NVIDIA driver + `nvidia-container-toolkit`**, only if the bundle needs a GPU
  (`nvidia-smi` and `nvidia-container-cli` are checked during preflight).
- Free disk space on the target: preflight requires **60 GB** (bundle plus the
  loaded image).

## Installation

### Prerequisites (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git zstd
```

On **Ubuntu 24.04**, if virtual environment creation fails with a message like
`ensurepip is not available`, install the version-specific package:

```bash
sudo apt install -y python3.12-venv
```

### Install docker-migration-tool

```bash
# Clone the repository
git clone <your-remote-url> docker-migration-tool
cd docker-migration-tool

# Remove any failed previous venv attempt
rm -rf .venv

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
python -m pip install --upgrade pip
python -m pip install -e .
```

### Using the tool after installation

The CLI is installed inside the virtual environment. **Every time you open a new
terminal**, activate the environment before using the tool:

```bash
cd ~/docker-migration-tool
source .venv/bin/activate
docker-migration --version
```

On Ubuntu 24.04, if you see `error: externally-managed-environment`, you are
running `pip` outside the virtual environment. Do **not** use
`--break-system-packages`; activate `.venv` and use `python -m pip` instead.

For development dependencies:

```bash
python -m pip install -e ".[dev]"
```

## CLI

```
docker-migration [--version] [--no-color] [-v|--verbose] <command> ...

inspect      --container/-c NAME  [--output/-o FILE]
export       --container/-c NAME  [--output/-o DIR] [--dry-run]
import       BUNDLE_PATH  [--workspace/-w PATH] [--ros-domain-id N]
                          [--dry-run] [--non-interactive]
verify       PATH  [--container/-c NAME]
bundle-info  BUNDLE_PATH
```

`--output` is required for a real `export` and optional for `export --dry-run`
(a dry run writes nothing). `verify` decides for itself whether `PATH` is a
bundle (it contains `MANIFEST.json`) or a restored workspace (it contains
`docker/` or `src/`).

## Inspect

Read-only. Nothing is written unless `--output` is given.

```bash
docker-migration inspect --container my-ros-container
docker-migration inspect --container my-ros-container --output inspection.json
```

It reports the container (mounts with per-mount classification, env var names,
compose labels), the runtime image and whether it is a snapshot, the clean
parent proof (including rejected candidates and why), the host, hardware and
network interfaces, workspace git repositories and their dirty state, large
files that would be included and large files excluded by policy, the package
manifests, and any credential paths detected inside the container.

The summary ends with either `Clean parent image proven - export is possible` or
`Clean parent image NOT proven - cannot export`.

## Export Dry Run

```bash
docker-migration export --container my-ros-container --dry-run
```

A dry run performs the real checks it can and says plainly which one it cannot:

- the clean-parent layer-prefix proof — **runs**;
- the image config / build history credential scan — **runs** (it only needs
  `docker image inspect` and `docker image history`) and **can block the run**;
- the final-filesystem credential-path scan — **runs**;
- the full image-layer secret scan — **skipped**, because a dry run never calls
  `docker save`.

It prints the three states separately (for example
`config_metadata_scan: passed`, `final_filesystem_scan: passed`,
`layer_scan: skipped_dry_run`) followed by
`Export safety is NOT fully verified in dry-run`. A blanket "passed all required
security checks" is only ever printed by a real export, after all three scans
pass.

It also lists what would be archived: the resolved `src` archive root, the
exclusion policy, the large files that would be included and the large files
excluded by policy.

## Export

```bash
docker-migration export \
  --container my-ros-container \
  --output ~/migration-bundles
```

Order of operations: validate the inspection → initialise the manifest → prove
the parent relationship → scan the image config and build history → scan the
final filesystem → create the bundle tree → export and scan the image → archive
the workspace → write git state, packages, Docker config, host info, hardware
inventory, `SECRETS_REQUIRED.md` and the verification checklist → write
`MANIFEST.json` and the bundle's own README.

If any gate fails, the export stops. When the layer scan rejects an image, the
`docker save` archive it produced is discarded rather than kept in the bundle.

## bundle-info

```bash
docker-migration bundle-info ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
```

Prints creation time, tool version, source host summary, workspace and container
names, the runtime image that was **not** exported, the clean base image and its
size, the security metadata (parent relationship, layer scan, config scan and
scanner versions) and the component list — without extracting anything.

## verify

```bash
# a bundle: structure, manifest, security metadata, checksums, image archive
docker-migration verify ~/migration-bundles/migration_bundle_my_workspace_20250101_120000

# a restored workspace: Docker access, layout, config, container, GPU, ROS, weights
docker-migration verify ~/docker_workspaces/my_workspace --container my-ros-container
```

Exit status is non-zero if any check fails.

## Import Dry Run

```bash
docker-migration import ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 --dry-run
```

Preflight runs for real — including the bundle security-verdict gate — and then
the tool reports where it *would* restore, which image it would load, that it
would extract the workspace and restore the Docker configuration, which steps
need `sudo`, what will be regenerated on this host, and which manual actions
will remain. Nothing is changed.

## Import

```bash
docker-migration import ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 \
  --workspace ~/ros/my_workspace \
  --ros-domain-id 2
```

Steps: preflight → determine the target workspace → `docker load` the clean
image → extract the workspace archive → restore the portable Docker config →
install udev rules (prompts for `sudo`, skippable) → set up X11 authority sync →
run `config.sh` to regenerate `.env` and `docker-compose.override.yml` →
reconcile `ROS_DOMAIN_ID` → `docker compose up -d` and run the workspace's
dependency installer inside the container → print the remaining manual actions.

Target workspace resolution, in order:

1. `--workspace/-w`
2. `$DOCKER_MIGRATION_WORKSPACE_ROOT/<workspace name>`
3. `~/docker_workspaces/<workspace name>`

No path from the source machine is ever reused as a target path. Use
`--non-interactive` for unattended runs (prompts are skipped and the
corresponding actions are reported as manual follow-ups instead).

### `--workspace` semantics

`--workspace` specifies the **filesystem path** where the workspace is restored.
It does not rename the workspace's logical identity: the `workspace_name` from
the source manifest is preserved in `MANIFEST.json` for provenance tracking.
Container names and compose project names are derived from the original
`workspace_name`, not from the target path's basename.

If you need to run multiple copies of the same workspace on one machine with
different identities, you would need to edit `env.sh` / `docker-compose.yml`
post-import to change `CONTAINER_NAME` / `COMPOSE_PROJECT_NAME`.

## Migration Workflow

```
on the source machine                on the target machine
─────────────────────                ─────────────────────
1. inspect   (read-only)
2. export --dry-run  (gates 1-3)
3. export            (gates 1-4)
4. bundle-info       (sanity)
   ── copy the bundle directory ──▶  5. bundle-info
                                     6. verify <bundle>
                                     7. import --dry-run
                                     8. import
                                     9. verify <workspace> -c <container>
                                    10. work through SECRETS_REQUIRED.md
```

## Bundle Layout

```
migration_bundle_<workspace>_<timestamp>/
├── MANIFEST.json                     # metadata, checksums, security verdict
├── README.md                         # generated, human-readable instructions
├── docker/
│   ├── image/
│   │   ├── base-image.tar            # the clean parent image
│   │   └── IMAGE_INFO.json
│   └── config/
│       ├── Dockerfile
│       ├── docker-compose.yml
│       ├── env.sh
│       ├── common.sh
│       ├── config.sh                 # regenerates .env and the compose override
│       ├── .dockerignore
│       ├── udev/
│       │   └── 99-robotics-docker.rules
│       ├── install_host_udev_rules.sh
│       ├── install_user_xauthority_sync.sh
│       └── xauthority/
├── workspace/
│   ├── src.tar.zst                   # the workspace src tree
│   ├── EXCLUDED.txt                  # exclusion policy, as applied
│   ├── LARGE_FILES.json              # included large files + checksums
│   └── EXCLUDED_LARGE_FILES.json     # large files skipped, with the pattern
├── git/
│   └── repos.json                    # per-repo and per-submodule state
├── packages/
│   ├── apt_manual.txt
│   ├── apt_versions.txt
│   ├── pip_freeze.txt
│   ├── packages_meta.json
│   └── INSTALLED_DEPENDENCIES.md
├── host/
│   └── host_info.json
├── hardware/
│   ├── devices.json
│   └── network.json
└── configuration/
    ├── SECRETS_REQUIRED.md
    ├── detected_secrets.json         # paths and kinds only, never contents
    └── GENERATED_FILES_NOTE.txt
```

## Workspace Handling

The archive source is the **authoritative `src` bind mount** reported by
`docker inspect`, never a path guessed from the workspace name, and never the
workspace root (portable Docker configuration is collected separately, so
archiving the root would duplicate it and risk pulling in generated files).

A workspace mount is recognised by its shape — a bind mount whose path is a
directory named `src`, outside system prefixes — so your workspace directory can
be called anything.

The exclusion policy has a **single definition** in `inspect/workspace.py`
(`**/__pycache__`, `**/build`, `**/install`, `**/log`, `core.*`, `*.jsonl`, plus
generated files such as `.env`, `docker-compose.override.yml` and X11 authority
files). The archive, the large-file discovery, the checksums and the dry-run
report all read it from that one place, so an excluded file can never be
reported as an included large file.

Large files (>10 MB) that survive the policy — model weights in particular — are
archived and listed with checksums in `workspace/LARGE_FILES.json`; those that
are excluded are listed with the pattern that excluded them.

## Git State Handling

`git/repos.json` records, for every repository and submodule under `src`: path,
remote URL (byte-for-byte, never re-encoded), branch, short HEAD, upstream,
ahead/behind counts, dirty flag, modified files and untracked files. The export
warns when repositories are dirty or have untracked files, so you know what the
bundle is carrying that no remote has.

Git credentials are not collected: on the target you authenticate to whatever
hosting service those remotes point at with your own key or token.

## Package Restoration

The bundle carries manifests, not installed trees: manually-installed apt
packages, exact apt versions, `pip freeze`, the ROS distro and Python version,
and a readable `INSTALLED_DEPENDENCIES.md`.

On import, after the container starts, the workspace's own
`_container_setup/install_workspace_dependencies.sh` is run **inside** the
container (30-minute timeout) to install dependencies and build the workspace.
Its absolute path is not hardcoded: it is taken from the manifest's recorded
container-side workspace path, then looked for under the container user's own
`$HOME`. If no installer is found, the step fails loudly and is reported as a
manual action.

## Host / Hardware Handling

Host and hardware data is **diagnostic**, never restored verbatim:

- `host/host_info.json`: OS, kernel, architecture, CPU, RAM, Docker and Compose
  versions, GPU model and driver, UID/GID and group list, free disk, `DISPLAY`.
- `hardware/devices.json`: stable `/dev/*/by-id` and `by-path` names for cameras
  and serial devices, USB device list, DRI and sound devices, and the `dri`,
  `audio` and `render` group ids.
- `hardware/network.json`: per-interface *intents* — name, type, address,
  subnet, gateway, connection name and purpose. No credential of any kind.

On the target, UID/GID, device group ids and `DISPLAY` are detected locally and
written into the regenerated `.env` by `config.sh`. Device paths are verified,
not assumed, and calibration is a manual step.

## Secrets Handling

- The credential-path scanner knows the usual locations (SSH private keys and
  config, Docker registry config, cloud credential directories, AI CLI auth
  files) as **user-agnostic globs** such as `/home/*/.ssh/id_*` — no account
  name is ever baked in.
- Those checks test for existence and size only (`[ -e … ] && stat -c %s`), so
  file contents are not read. Findings are recorded as path + kind (+ size) in
  `configuration/detected_secrets.json`.
- The image config / build history scanner does pattern-match real values in
  memory, because that is the only way to see a token baked into `ENV`, `ARG` or
  a `RUN` command. It records the source, the key name and the finding kind —
  never the value itself and never the full history command.
- Detection is limited to known credential paths and supported credential
  formats (for example `sk-…`, `sk-ant-…`, `ghp_…`, `AKIA…`, `Bearer …`, JWTs,
  PEM private-key headers, `scheme://user:pass@host`). A custom or obfuscated
  secret format can pass unnoticed; treat a clean scan as a strong check, not a
  guarantee.
- `configuration/SECRETS_REQUIRED.md` tells the importing operator what to
  supply: their own service credentials, their own git access for the recorded
  remotes, any application secret files, the regenerated X11 cookie and their own
  network configuration.
- Credential-like environment variable names are redacted in all output.

## Security Gates

Four gates, all of which must pass before a bundle exists:

| # | Gate | Needs `docker save`? | What blocks it |
|---|------|----------------------|----------------|
| 1 | Clean parent proof | no | The candidate's `RootFS.Layers` is not an exact prefix of (or identical to) the runtime image's chain → `EXPORT BLOCKED: Unable to prove clean parent image relationship` |
| 2 | Image config + build history credential scan | no | A credential-like key name or a credential-shaped value in `Config.Env`, `ContainerConfig.Env`, `Cmd`, `Entrypoint`, `Labels` or any `history` `CreatedBy` command; also a config that cannot be read |
| 3 | Final-filesystem credential path scan | no | A known credential path present in the image's final filesystem |
| 4 | Full image-layer secret scan | yes | A credential-like path in **any** layer of the saved archive — a later whiteout deletion does not help, because the lower layer still ships |

Gate 2 matters because gates 3 and 4 match on *paths*: a secret baked in with
`ENV OPENAI_API_KEY=...`, `ARG GITHUB_TOKEN=...` or
`RUN curl -H "Authorization: Bearer ..."` has no path at all. Key names are
matched per name *component*, so `--keyring=`, `KEYSTORE` and `XAUTHORITY` do not
block a clean export, and values are matched with format-limited patterns
(`sk-…`, `sk-ant-…`, `ghp_…`, `AKIA…`, `Bearer …`, JWTs, PEM private-key
headers, `scheme://user:pass@host`, nested `TOKEN=`/`API_KEY=` assignments)
rather than substrings, so ordinary package names and version pins are not
findings. A finding records `source` / `key` / `kind` / `matched: true` — never
a value.

On the import side the gate is symmetric: preflight refuses the bundle unless
`parent_relationship_verified` is true and both `layer_secret_scan_result` and
`image_config_scan_result` are `passed`. A bundle with no security metadata is
refused as an unsafe legacy bundle rather than trusted.

## Example Workflow

```bash
# ── source machine ────────────────────────────────────────────────────────────
docker-migration inspect --container my-ros-container --output inspection.json
docker-migration export  --container my-ros-container --dry-run
docker-migration export  --container my-ros-container --output ~/migration-bundles
docker-migration bundle-info ~/migration-bundles/migration_bundle_my_workspace_20250101_120000

# ── copy the bundle (any method that preserves the directory) ────────────────
rsync -a --info=progress2 \
  ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 \
  target-host:~/migration-bundles/

# ── target machine ───────────────────────────────────────────────────────────
cd ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
docker-migration verify .
docker-migration import . --dry-run
docker-migration import . --workspace ~/ros/my_workspace --ros-domain-id 2
docker-migration verify ~/ros/my_workspace --container my-ros-container
less configuration/SECRETS_REQUIRED.md
```

## Limitations

- **Linux hosts only**, and both machines must share an architecture: the image
  is transferred as-is, not rebuilt.
- **The bundle is large**: a clean ROS image plus a workspace with model weights
  is commonly in the tens of GB, and preflight asks for 60 GB free.
- **No incremental or resumable transfer.** Copying the bundle is your job.
- **Workspaces must follow the `<workspace>/src` convention**, with a bind mount
  into the container, and the dependency installer (if you want that step) must
  live at `src/_container_setup/install_workspace_dependencies.sh`.
- **Dirty git state is recorded and shipped, not resolved.** Uncommitted work
  travels inside the archive; there is no merge logic.
- **Robot networking, device permissions beyond udev, and camera calibration are
  manual**, by design.
- **Credential material is deliberately left behind, and the gates are
  best-effort.** Expect to re-authenticate every service on the new machine. The
  scanners cover known credential paths and supported credential formats; an
  unknown or deliberately obfuscated secret format can escape them, so review
  what you are about to hand over rather than relying on a green run alone.
- **A dry run is not a safety certificate**: gate 4 cannot run without
  `docker save`.

## Development

```bash
pip install -e ".[dev]"
```

Layout conventions: production code lives under `src/docker_migration_tool/`,
tests under `tests/`. Host-side subprocesses are invoked using argument lists and
`shell=True` is not used (container-side commands may legitimately be
`sh -c`/`bash -c` strings that this tool composes), all Docker calls go through
`utils/docker.py` with timeouts, and archive extraction goes through
`utils/filesystem.py`, which rejects path traversal, absolute paths, symlink
escapes and device nodes.

Two rules worth knowing before changing code:

1. The workspace exclusion policy has exactly one definition
   (`inspect/workspace.py`); every consumer must read it from there.
2. Security scanners must keep recording *existence only*. If you add a
   detector, add it with a test that proves it blocks the export, and never log
   or store the matched value.

## Tests

```bash
python -m pytest                       # 308 tests
python -m pytest --collect-only -q     # collection only
python -m pytest tests/test_security.py
```

The suite is pure unit tests with mocked Docker calls — no daemon, no container
and no network is required, and it runs in well under a second. Coverage
includes the layer-prefix proof, all four security gates, the config/history
credential scanner (89 tests), the workspace exclusion policy, archive safety,
manifest security metadata, logging redaction, and a publication-safety module
that fails if a machine-specific path or identifier is reintroduced into
production code.

## Safety Guarantees

What follows is what the code enforces. It is not a claim that every possible
secret is caught: the gates work on known credential paths and supported
credential formats.

- A snapshot image is never exported.
- An image is exported only after its layer chain is proven to be a prefix of
  the runtime image's chain.
- An export is blocked by a credential-like path in any layer, a credential-like
  key or value in the image config or build history, or a credential path in the
  final filesystem.
- A rejected `docker save` archive is discarded, not shipped.
- The path-based scanners do not read file contents; they record path, kind and
  size. The config/history scanner pattern-matches values in memory but persists
  only source, key name, kind and `matched: true` — no credential value and no
  full history command reaches a log, the manifest, a bundle file or a report.
- A bundle without a complete, passing security verdict is refused on import.
- `inspect` and `--dry-run` never modify Docker state or write into your
  workspace.
- No path, UID, GID, device id or hostname from the source machine is reused as
  a target value; the target's own values are detected at import time.

## License

MIT — see [LICENSE](LICENSE).
