"""Tests for the image config metadata / build history credential scan.

A credential baked in with `ENV OPENAI_API_KEY=...` travels with `docker save`
even when every layer path is clean, so this is a separate export gate.

No real credential appears in this file. Every "token" below is synthetic
padding in the right *shape* (``sk-`` + filler, ``AKIA`` + 16 uppercase, ...)
so that the format detectors can be exercised without handling real material.
Assertions match on meaning (source/key/kind, per-check state) rather than on
exact log sentences.
"""

import json
from dataclasses import asdict

import pytest

from docker_migration_tool.export.bundle import BundleCreator, ExportBlockedError
from docker_migration_tool.importers.preflight import PreflightChecker
from docker_migration_tool.model import ImageConfigScanResult
from docker_migration_tool.security.image_config import (
    CONFIG_SCANNER_VERSION,
    ENV_KEY_ALLOWLIST,
    SECRET_ENV_KEY_PREFIXES,
    SECRET_ENV_KEY_WORDS,
    is_allowlisted_secret_like_key,
    key_name_pattern,
    matched_secret_env_key,
    scan_image_config,
    scan_image_config_data,
    value_looks_like_credential,
)
from docker_migration_tool.utils.docker import DockerError
from docker_migration_tool.utils.logging import (
    SECRET_PATTERNS,
    SECRET_PREFIXES,
    redact_value,
)

from tests.test_security_metadata import (
    PASSING_METADATA,
    make_inspection,
    patch_config_scan,
    write_bundle,
)


# Synthetic values in the right shape. None of these is a real credential.
DUMMY_OPENAI_KEY = "sk-" + "A" * 32
DUMMY_ANTHROPIC_KEY = "sk-ant-api03-" + "B" * 32
DUMMY_GITHUB_TOKEN = "ghp_" + "C" * 36
DUMMY_AWS_KEY_ID = "AKIA" + "D" * 16
DUMMY_BEARER = "Authorization: Bearer " + "E" * 40
DUMMY_JWT = "eyJ" + "F" * 20 + "." + "G" * 20 + "." + "H" * 20

# A realistic, credential-free clean parent image config
CLEAN_CONFIG = {
    "Config": {
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LD_LIBRARY_PATH=/usr/local/cuda/lib64",
            "CUDA_VERSION=12.8.1",
            "NV_LIBNCCL_PACKAGE=libnccl2=2.25.1-1+cuda12.8",
            "DEBIAN_FRONTEND=noninteractive",
            "LANG=en_US.UTF-8",
            "ROS_DISTRO=humble",
            "ROS_WORKSPACE=/home/dev_user/colcon_ws",
            "ROS_DOMAIN_ID=0",
            "ROBOTICS_INSTALL_OPENCV=1",
        ],
        "Cmd": ["/bin/bash"],
        "Entrypoint": ["/ros_entrypoint.sh"],
        "Labels": {"maintainer": "dev_user", "org.opencontainers.version": "1"},
    },
    "RootFS": {"Layers": []},
}

CLEAN_HISTORY = [
    {"CreatedBy": "/bin/sh -c #(nop) ENV NV_LIBNCCL_PACKAGE=libnccl2=2.25.1-1+cuda12.8"},
    {"CreatedBy": "/bin/sh -c apt-get update && apt-get install -y curl gnupg"},
    {"CreatedBy": "/bin/sh -c curl -sSL https://example.invalid/ros.key | "
                  "gpg --dearmor -o /usr/share/keyrings/ros-archive-keyring.gpg"},
    {"CreatedBy": "/bin/sh -c echo 'deb [signed-by=/usr/share/keyrings/"
                  "ros-archive-keyring.gpg] http://packages.example.invalid/ros2 "
                  "jammy main' > /etc/apt/sources.list.d/ros2.list"},
    {"CreatedBy": "/bin/sh -c #(nop) ENV ROS_DISTRO=humble"},
    {"CreatedBy": "/bin/sh -c #(nop) CMD [\"/bin/bash\"]"},
]


def captured(capsys) -> str:
    """All operator-visible output: blocking findings go to stderr."""
    captured_output = capsys.readouterr()
    return captured_output.out + captured_output.err


def config_with_env(*entries: str) -> dict:
    """Clean config plus the given extra Config.Env entries."""
    data = json.loads(json.dumps(CLEAN_CONFIG))
    data["Config"]["Env"].extend(entries)
    return data


class TestSecretKeyVocabulary:
    """One shared vocabulary; word-scoped matching."""

    def test_required_key_words_are_present(self):
        for word in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"):
            assert word in SECRET_ENV_KEY_WORDS

    def test_required_key_prefixes_are_present(self):
        for prefix in ("AWS_", "OPENAI_", "ANTHROPIC_", "GITHUB_",
                       "AZURE_", "DOCKER_"):
            assert prefix in SECRET_ENV_KEY_PREFIXES

    def test_vocabulary_is_shared_with_value_redaction(self):
        """Single source of truth: utils.logging owns the words."""
        assert SECRET_ENV_KEY_WORDS == tuple(SECRET_PATTERNS)
        assert SECRET_ENV_KEY_PREFIXES == tuple(SECRET_PREFIXES)

    @pytest.mark.parametrize("key", [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "AZURE_CLIENT_SECRET",
        "DOCKER_PASSWORD",
        "MY_APP_PASSWORD",
        "SERVICE_CREDENTIALS",
        "REFRESH_TOKENS",
    ])
    def test_credential_keys_match(self, key):
        matched, pattern = matched_secret_env_key(key)
        assert matched is True
        assert pattern

    @pytest.mark.parametrize("key", [
        "PATH",
        "LD_LIBRARY_PATH",
        "CUDA_VERSION",
        "NV_LIBNCCL_PACKAGE",
        "DEBIAN_FRONTEND",
        "LANG",
        "ROS_DISTRO",
        "ROS_WORKSPACE",
        "ROBOTICS_INSTALL_OPENCV",
        "NVIDIA_DRIVER_CAPABILITIES",
    ])
    def test_benign_keys_do_not_match(self, key):
        assert matched_secret_env_key(key) == (False, None)

    @pytest.mark.parametrize("key", ["KEYRING", "ROS_SECURITY_KEYSTORE",
                                     "MONKEYS", "KEYBOARD_LAYOUT"])
    def test_matching_is_word_scoped_not_substring(self, key):
        """`*KEY*` means a name component, so --keyring= does not block export."""
        assert matched_secret_env_key(key) == (False, None)

    def test_allowlisted_keys_are_not_findings_but_are_reported(self):
        assert "GPG_KEY" in ENV_KEY_ALLOWLIST
        assert matched_secret_env_key("GPG_KEY") == (False, None)
        # ... and the operator still gets told the name matched
        assert is_allowlisted_secret_like_key("GPG_KEY") is True
        assert key_name_pattern("GPG_KEY") == "*KEY*"

    def test_allowlist_does_not_cover_real_docker_secrets(self):
        assert "DOCKER_PASSWORD" not in ENV_KEY_ALLOWLIST
        assert matched_secret_env_key("DOCKER_PASSWORD")[0] is True

    def test_redaction_stays_greedier_than_the_export_gate(self):
        """Intentional: over-redacting a report is safe, over-blocking is not."""
        assert redact_value("KEYRING", "/usr/share/keyrings") == "[REDACTED]"
        assert matched_secret_env_key("KEYRING") == (False, None)


class TestCredentialValueDetectors:
    """Format-limited regexes, never substring matching."""

    @pytest.mark.parametrize("value", [
        DUMMY_OPENAI_KEY,
        DUMMY_ANTHROPIC_KEY,
        DUMMY_GITHUB_TOKEN,
        DUMMY_AWS_KEY_ID,
        DUMMY_BEARER,
        DUMMY_JWT,
        "github_pat_" + "I" * 32,
        "xoxb-" + "1" * 16,
        "pypi-" + "J" * 40,
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "https://user:hunter2secret@git.example.invalid/repo.git",
        "MY_APP_CONFIG=OPENAI_API_KEY=" + "K" * 24,
        "--build-arg ACCESS_TOKEN=" + "L" * 20,
    ])
    def test_credential_material_is_detected(self, value):
        assert value_looks_like_credential(value) is True

    @pytest.mark.parametrize("value", [
        "sk",
        "sklearn",
        "disk-usage",
        "task-manager-2",
        "/usr/local/cuda/lib64",
        "libnccl2=2.25.1-1+cuda12.8",
        "noninteractive",
        "humble",
        "en_US.UTF-8",
        "0",
        "1234567890abcdef1234567890abcdef12345678",   # a git sha
        "/usr/share/keyrings/ros-archive-keyring.gpg",
    ])
    def test_benign_values_are_not_flagged(self, value):
        assert value_looks_like_credential(value) is False

    @pytest.mark.parametrize("value", ["$TOKEN", "${GITHUB_TOKEN}", "$(cat x)"])
    def test_placeholders_are_not_baked_in_material(self, value):
        assert value_looks_like_credential(value) is False


class TestScanConfigEnv:
    """Config.Env is the primary surface."""

    def test_clean_config_passes(self):
        result = scan_image_config_data(CLEAN_CONFIG, CLEAN_HISTORY)

        assert result.performed is True
        assert result.result == "passed"
        assert result.passed is True
        assert result.findings == []
        assert result.scanner_version == CONFIG_SCANNER_VERSION
        assert result.env_vars_scanned == 10
        assert result.labels_scanned == 2
        assert result.history_entries_scanned == len(CLEAN_HISTORY)

    def test_secret_env_key_fails_the_scan(self):
        result = scan_image_config_data(
            config_with_env(f"OPENAI_API_KEY={DUMMY_OPENAI_KEY}"), CLEAN_HISTORY
        )

        assert result.result == "failed"
        assert result.passed is False
        finding = result.findings[0]
        assert finding.source == "image_config_env"
        assert finding.key == "OPENAI_API_KEY"
        assert finding.kind == "credential_environment"
        assert finding.matched_pattern

    def test_finding_never_carries_the_value(self):
        result = scan_image_config_data(
            config_with_env(f"GITHUB_TOKEN={DUMMY_GITHUB_TOKEN}"), []
        )

        serialized = json.dumps([asdict(f) for f in result.findings], default=str)
        assert DUMMY_GITHUB_TOKEN not in serialized
        assert "value" not in asdict(result.findings[0])

    def test_value_side_detection_records_matched_and_kind_only(self):
        """An innocuous key whose value carries credential material."""
        result = scan_image_config_data(
            config_with_env(f"MY_APP_CONFIG=OPENAI_API_KEY={DUMMY_OPENAI_KEY}"), []
        )

        assert result.result == "failed"
        finding = result.findings[0]
        assert finding.source == "image_config_env"
        assert finding.key == "MY_APP_CONFIG"
        assert finding.kind == "possible_credential_value"
        assert finding.matched is True
        # The detector that fired is not recorded either
        assert finding.matched_pattern is None
        assert DUMMY_OPENAI_KEY not in json.dumps(asdict(finding), default=str)

    def test_allowlisted_key_is_reported_not_blocked(self):
        result = scan_image_config_data(
            config_with_env("GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568"), []
        )

        assert result.result == "passed"
        assert result.allowlisted_keys == ["GPG_KEY"]

    def test_allowlist_cannot_hide_credential_material(self):
        result = scan_image_config_data(
            config_with_env(f"DOCKER_HOST={DUMMY_BEARER}"), []
        )

        assert result.result == "failed"
        assert result.findings[0].kind == "possible_credential_value"

    def test_container_config_env_is_scanned_when_present(self):
        data = json.loads(json.dumps(CLEAN_CONFIG))
        data["ContainerConfig"] = {
            "Env": ["PATH=/usr/bin", f"AWS_SESSION_TOKEN={DUMMY_AWS_KEY_ID}"]
        }

        result = scan_image_config_data(data, [])

        assert result.container_config_present is True
        sources = {f.source for f in result.findings}
        assert "image_container_config_env" in sources
        assert result.env_vars_scanned == 12

    def test_missing_container_config_is_not_an_error(self):
        result = scan_image_config_data(CLEAN_CONFIG, [])
        assert result.container_config_present is False
        assert result.result == "passed"

    def test_env_entry_without_a_value_is_handled(self):
        result = scan_image_config_data(config_with_env("GITHUB_TOKEN"), [])
        assert result.result == "failed"
        assert result.findings[0].key == "GITHUB_TOKEN"


class TestScanCmdEntrypointAndLabels:
    """Secondary surfaces still block the export."""

    def test_entrypoint_credential_is_detected(self):
        data = json.loads(json.dumps(CLEAN_CONFIG))
        data["Config"]["Entrypoint"] = [
            "/bin/sh", "-c", f"curl -H '{DUMMY_BEARER}' https://example.invalid"
        ]

        result = scan_image_config_data(data, [])

        assert result.result == "failed"
        assert result.findings[0].source == "image_config_entrypoint"
        assert DUMMY_BEARER not in json.dumps(
            [asdict(f) for f in result.findings], default=str
        )

    def test_cmd_assignment_key_is_detected(self):
        data = json.loads(json.dumps(CLEAN_CONFIG))
        data["Config"]["Cmd"] = ["/bin/sh", "-c", "GITHUB_TOKEN=abc123 run.sh"]

        result = scan_image_config_data(data, [])

        assert result.result == "failed"
        assert result.findings[0].source == "image_config_cmd"
        assert result.findings[0].key == "GITHUB_TOKEN"

    def test_label_key_and_value_are_scanned(self):
        data = json.loads(json.dumps(CLEAN_CONFIG))
        data["Config"]["Labels"] = {
            "maintainer": "dev_user",
            "com.example.api_key": "redacted-by-owner",
            "com.example.note": DUMMY_ANTHROPIC_KEY,
        }

        result = scan_image_config_data(data, [])

        assert result.result == "failed"
        kinds = {(f.key, f.kind) for f in result.findings}
        assert ("com.example.api_key", "credential_label") in kinds
        assert ("com.example.note", "possible_credential_value") in kinds
        assert result.labels_scanned == 3


class TestScanHistory:
    """docker image history --no-trunc CreatedBy commands."""

    def test_realistic_build_history_passes(self):
        """apt keyrings and package pins must not be false positives."""
        result = scan_image_config_data(CLEAN_CONFIG, CLEAN_HISTORY)
        assert result.result == "passed"
        assert result.history_entries_scanned == len(CLEAN_HISTORY)

    def test_env_assignment_in_history_is_detected_by_key(self):
        history = CLEAN_HISTORY + [
            {"CreatedBy": f"/bin/sh -c #(nop) ENV OPENAI_API_KEY={DUMMY_OPENAI_KEY}"}
        ]

        result = scan_image_config_data(CLEAN_CONFIG, history)

        assert result.result == "failed"
        finding = result.findings[0]
        assert finding.source == "image_history_created_by"
        assert finding.key == "OPENAI_API_KEY"
        assert finding.kind == "credential_environment"
        assert finding.location == f"history[{len(history) - 1}]"

    def test_build_arg_in_history_is_detected(self):
        history = [{"CreatedBy": "/bin/sh -c #(nop) ARG GITHUB_TOKEN"},
                   {"CreatedBy": f"/bin/sh -c git clone https://x:{DUMMY_GITHUB_TOKEN}"
                                 "@git.example.invalid/repo.git"}]

        result = scan_image_config_data(CLEAN_CONFIG, history)

        assert result.result == "failed"
        assert any(f.kind == "possible_credential_value" for f in result.findings)

    def test_history_command_text_is_never_recorded(self):
        history = [{"CreatedBy": f"/bin/sh -c curl -H '{DUMMY_BEARER}' url"}]

        result = scan_image_config_data(CLEAN_CONFIG, history)

        serialized = json.dumps([asdict(f) for f in result.findings], default=str)
        assert DUMMY_BEARER not in serialized
        assert "curl" not in serialized

    def test_missing_history_is_handled(self):
        result = scan_image_config_data(CLEAN_CONFIG, None)
        assert result.history_entries_scanned == 0
        assert result.result == "passed"


class TestScanImageConfigDockerErrors:
    """An unscanned config is never treated as safe."""

    def test_unreadable_config_is_an_error_not_a_pass(self, monkeypatch):
        from docker_migration_tool.security import image_config as module

        def boom(image):
            raise DockerError("no such image")

        monkeypatch.setattr(module, "inspect_image_json", boom)

        result = scan_image_config("dummy/image:tag")

        assert result.performed is True
        assert result.result == "error"
        assert result.passed is False

    def test_unreadable_history_is_an_error_not_a_pass(self, monkeypatch):
        from docker_migration_tool.security import image_config as module

        monkeypatch.setattr(module, "inspect_image_json",
                            lambda image: CLEAN_CONFIG)

        def boom(image):
            raise DockerError("history unavailable")

        monkeypatch.setattr(module, "get_image_history", boom)

        result = scan_image_config("dummy/image:tag")

        assert result.result == "error"
        assert result.passed is False


class TestExportGate:
    """Gate 2: the export refuses a credential-bearing image config."""

    @staticmethod
    def _dry_run(tmp_path, monkeypatch, config_result):
        from docker_migration_tool.export import bundle as bundle_module

        def fail_docker_save(image, output_path, progress=False):
            raise AssertionError("docker save must not run during a dry run")

        monkeypatch.setattr(bundle_module, "docker_save", fail_docker_save)
        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda i: [])
        patch_config_scan(monkeypatch, config_result)

        creator = BundleCreator(make_inspection(), tmp_path / "bundle",
                                dry_run=True)
        return creator

    def test_secret_env_blocks_the_export(self, tmp_path, monkeypatch, capsys):
        failing = scan_image_config_data(
            config_with_env(f"OPENAI_API_KEY={DUMMY_OPENAI_KEY}"), CLEAN_HISTORY
        )
        creator = self._dry_run(tmp_path, monkeypatch, failing)

        with pytest.raises(ExportBlockedError):
            creator.create()

        output = captured(capsys)
        assert "image_config_env" in output
        assert "OPENAI_API_KEY" in output
        assert "credential_environment" in output
        # The value is never displayed
        assert DUMMY_OPENAI_KEY not in output
        assert not (tmp_path / "bundle").exists()

    def test_blocked_export_records_the_failed_verdict(self, tmp_path,
                                                      monkeypatch):
        failing = scan_image_config_data(
            config_with_env(f"AWS_SECRET_ACCESS_KEY={DUMMY_AWS_KEY_ID}"), []
        )
        creator = self._dry_run(tmp_path, monkeypatch, failing)

        with pytest.raises(ExportBlockedError):
            creator.create()

        assert creator.manifest.image_config_scan is True
        assert creator.manifest.image_config_scan_result == "failed"
        assert creator.security_status.config_metadata_scan == "failed"
        assert creator.security_status.all_required_checks_passed is False

    def test_unreadable_config_blocks_the_export(self, tmp_path, monkeypatch):
        error = ImageConfigScanResult(
            performed=True, result="error",
            scanner_version=CONFIG_SCANNER_VERSION,
            message="image config could not be read: no such image",
        )
        creator = self._dry_run(tmp_path, monkeypatch, error)

        with pytest.raises(ExportBlockedError, match="never treated as safe"):
            creator.create()

        assert creator.security_status.config_metadata_scan == "error"

    def test_value_side_finding_blocks_without_showing_the_value(
        self, tmp_path, monkeypatch, capsys,
    ):
        failing = scan_image_config_data(
            config_with_env(f"MY_APP_CONFIG=ACCESS_TOKEN={DUMMY_GITHUB_TOKEN}"), []
        )
        creator = self._dry_run(tmp_path, monkeypatch, failing)

        with pytest.raises(ExportBlockedError):
            creator.create()

        output = captured(capsys)
        assert "possible_credential_value" in output
        assert "matched: true" in output.lower()
        assert DUMMY_GITHUB_TOKEN not in output

    def test_clean_config_lets_the_dry_run_continue(self, tmp_path, monkeypatch,
                                                   capsys):
        passing = scan_image_config_data(CLEAN_CONFIG, CLEAN_HISTORY)
        creator = self._dry_run(tmp_path, monkeypatch, passing)
        creator.create()

        output = capsys.readouterr().out
        lower = output.lower()
        assert creator.security_status.config_metadata_scan == "passed"
        assert creator.manifest.image_config_scan_result == "passed"
        # The scan really ran in the dry run (it needs no docker save)
        assert "config_metadata_scan:  passed" in output
        assert "config" in lower and "history" in lower
        # ... while the layer scan is still reported as skipped
        assert creator.security_status.layer_scan == "skipped_dry_run"

    def test_real_export_records_the_verdict_in_the_bundle(self, tmp_path,
                                                          monkeypatch):
        from docker_migration_tool.export import bundle as bundle_module
        from tests.test_layer_scan import CLEAN_LAYER, build_oci_save_archive

        monkeypatch.setattr(bundle_module, "docker_save",
                            lambda image, path, progress=False:
                            build_oci_save_archive(path, [CLEAN_LAYER]))
        monkeypatch.setattr(bundle_module, "scan_image_for_secrets", lambda i: [])
        patch_config_scan(monkeypatch, scan_image_config_data(CLEAN_CONFIG,
                                                             CLEAN_HISTORY))

        creator = BundleCreator(make_inspection(), tmp_path / "bundle")
        creator._initialize_manifest()
        creator._scan_image_config_metadata()
        creator._security_scan_image()
        creator._create_bundle_structure()
        creator._export_image()

        info = json.loads(
            (tmp_path / "bundle" / "docker" / "image" / "IMAGE_INFO.json").read_text()
        )
        assert info["image_config_scan"] is True
        assert info["image_config_scan_result"] == "passed"
        assert info["config_scanner_version"] == CONFIG_SCANNER_VERSION
        assert info["config_env_vars_scanned"] == 10
        assert info["layer_secret_scan_result"] == "passed"
        assert creator.security_status.all_required_checks_passed is True


class TestImportGate:
    """Import refuses bundles whose image config was not proven clean."""

    def test_passing_metadata_is_accepted(self, tmp_path):
        checker = PreflightChecker(write_bundle(tmp_path, dict(PASSING_METADATA)))
        checker._check_bundle_security_metadata()

        assert checker.errors == []
        assert "image_config_scan" in {c.name for c in checker.checks}

    def test_missing_config_scan_result_is_refused(self, tmp_path):
        manifest = dict(PASSING_METADATA)
        del manifest["image_config_scan_result"]
        del manifest["image_config_scan"]

        checker = PreflightChecker(write_bundle(tmp_path, manifest))
        checker._check_bundle_security_metadata()

        assert any("image_config_scan_result" in e for e in checker.errors)

    def test_failed_config_scan_is_refused(self, tmp_path):
        manifest = dict(PASSING_METADATA)
        manifest["image_config_scan_result"] = "failed"

        checker = PreflightChecker(write_bundle(tmp_path, manifest))
        checker._check_bundle_security_metadata()

        assert any("image_config_scan_result" in e for e in checker.errors)

    def test_error_config_scan_is_refused(self, tmp_path):
        manifest = dict(PASSING_METADATA)
        manifest["image_config_scan_result"] = "error"

        checker = PreflightChecker(write_bundle(tmp_path, manifest))
        checker._check_bundle_security_metadata()

        assert any("image_config_scan_result" in e for e in checker.errors)

    def test_image_info_json_is_used_as_fallback(self, tmp_path):
        bundle = write_bundle(tmp_path, {"schema_version": "1.0.0"},
                              image_info=dict(PASSING_METADATA))
        checker = PreflightChecker(bundle)
        checker._check_bundle_security_metadata()

        assert checker.errors == []

    def test_existing_gates_still_apply(self, tmp_path):
        """The new check does not replace the parent proof or the layer scan."""
        manifest = dict(PASSING_METADATA)
        manifest["parent_relationship_verified"] = False
        manifest["layer_secret_scan_result"] = "failed"

        checker = PreflightChecker(write_bundle(tmp_path, manifest))
        checker._check_bundle_security_metadata()

        assert any("parent_relationship_verified" in e for e in checker.errors)
        assert any("layer_secret_scan_result" in e for e in checker.errors)
