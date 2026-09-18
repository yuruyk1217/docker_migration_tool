"""Publication safety tests.

These tests are the regression net for the repository publication audit: they
fail if a developer-specific identifier or a hardcoded user home directory
re-enters the published parts of the repository (production code, README,
packaging metadata).

The forbidden tokens are assembled from fragments on purpose - writing them as
literals here would put the very strings this file exists to keep out back into
the repository.
"""

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "docker_migration_tool"

# Real developer account / machine / workspace / image identifiers that must not
# appear in published code, docs or packaging metadata.
FORBIDDEN_TOKENS = [
    "robotics" + "-team",
    "robotics" + "_team",
    "alien" + "ware",
    "area" + "-51",
    "omori" + "_humble",
    "snapshot-" + "20260917",
]

# Paths that are checked. Development reports (docker_migration_tool_v1_*.md)
# are deliberately NOT checked: they are internal records of a real migration
# and are excluded from publication by .gitignore instead of being rewritten.
PUBLISHED_TEXT_FILES = sorted(SRC_ROOT.rglob("*.py")) + [
    REPO_ROOT / "README.md",
    REPO_ROOT / "README_ja.md",
    REPO_ROOT / "pyproject.toml",
]

# Concrete home directories that are allowed in production code: only generic
# pattern/documentation placeholders, never a real account name.
ALLOWED_HOME_SEGMENTS = {"*", "u", "user", "dev_user", "$USER", "<user>"}

_HOME_PATH_RE = re.compile(r"/home/([A-Za-z0-9_.$<>*-]+)/")


def _relative(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


@pytest.mark.parametrize("path", PUBLISHED_TEXT_FILES, ids=_relative)
def test_no_developer_identifiers(path: Path) -> None:
    """No published file names the developer's account, host or workspace."""
    text = path.read_text(encoding="utf-8", errors="replace").lower()

    hits = [token for token in FORBIDDEN_TOKENS if token in text]

    assert not hits, (
        f"{_relative(path)} contains developer-specific identifier(s) "
        f"{hits}; generalize before publishing"
    )


@pytest.mark.parametrize("path", sorted(SRC_ROOT.rglob("*.py")), ids=_relative)
def test_no_hardcoded_user_home(path: Path) -> None:
    """Production code never hardcodes a specific user's home directory.

    A fixed ``/home/<someone>/...`` path is the single most portability-breaking
    thing this tool could contain: it silently targets the exporting developer's
    machine on every other machine. Glob patterns (``/home/*/.ssh/*``, used by
    the secret scanner) and neutral doc placeholders are fine.
    """
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for segment in _HOME_PATH_RE.findall(line):
            assert segment in ALLOWED_HOME_SEGMENTS, (
                f"{_relative(path)}:{lineno} hardcodes /home/{segment}/; "
                "derive the path at runtime (Path.home(), $HOME, manifest data) "
                "or use a generic placeholder"
            )


def test_packaging_metadata_has_no_guessed_remote() -> None:
    """pyproject.toml must not advertise a repository URL that does not exist."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith(("Homepage", "Repository", "Documentation")), (
            f"pyproject.toml declares a project URL ({stripped!r}); set it only "
            "once a real remote exists"
        )
