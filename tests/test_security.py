"""Tests for security module."""

import pytest

from docker_migration_tool.security.scanner import (
    is_secret_path,
    is_generated_config,
    is_nvidia_runtime_file,
)


class TestSecretPathDetection:
    """Tests for secret path detection."""

    def test_codex_auth_detected(self):
        """Test .codex/auth.json is detected as secret."""
        is_secret, kind = is_secret_path("/home/user/.codex/auth.json")
        assert is_secret is True
        assert kind == "codex_credential"

    def test_claude_json_detected(self):
        """Test .claude.json is detected as secret."""
        is_secret, kind = is_secret_path("/home/user/.claude.json")
        assert is_secret is True
        assert kind == "claude_credential"

    def test_claude_sessions_detected(self):
        """Test .claude/sessions is detected as secret."""
        is_secret, kind = is_secret_path("/home/user/.claude/sessions/abc.key")
        assert is_secret is True
        assert kind == "claude_credential"

    def test_claude_bedrock_detected(self):
        """Test claude-bedrock/env is detected as secret."""
        is_secret, kind = is_secret_path("/home/user/.config/claude-bedrock/env")
        assert is_secret is True
        assert kind == "claude_credential"

    def test_ssh_private_key_detected(self):
        """Test SSH private keys are detected."""
        paths = [
            "/home/user/.ssh/id_rsa",
            "/home/user/.ssh/id_ed25519",
            "/home/user/.ssh/id_ecdsa",
        ]
        for path in paths:
            is_secret, kind = is_secret_path(path)
            assert is_secret is True, f"Expected {path} to be detected as secret"
            assert kind == "ssh_key"

    def test_docker_config_detected(self):
        """Test Docker config.json is detected."""
        is_secret, kind = is_secret_path("/home/user/.docker/config.json")
        assert is_secret is True
        assert kind == "docker_credential"

    def test_aws_credentials_detected(self):
        """Test AWS credentials are detected."""
        is_secret, kind = is_secret_path("/home/user/.aws/credentials")
        assert is_secret is True
        assert kind == "aws_credential"

    def test_bash_history_detected(self):
        """Test bash history is detected as secret."""
        is_secret, kind = is_secret_path("/home/user/.bash_history")
        assert is_secret is True
        assert kind == "shell_history"

    def test_xauthority_detected(self):
        """Test Xauthority files are detected."""
        paths = [
            "/home/user/.Xauthority",
            "/home/user/.docker/robotics-xauthority",
            "/tmp/.docker.xauth",
        ]
        for path in paths:
            is_secret, kind = is_secret_path(path)
            assert is_secret is True, f"Expected {path} to be detected as secret"
            assert kind == "x11_cookie"

    def test_credential_filename_patterns(self):
        """Test credential-like filenames are detected."""
        paths = [
            "/some/path/auth.json",
            "/some/path/secrets.yaml",
            "/some/path/secrets.yml",
            "/some/path/credentials.json",
        ]
        for path in paths:
            is_secret, kind = is_secret_path(path)
            assert is_secret is True, f"Expected {path} to be detected as secret"
            assert kind == "credential_file"

    def test_normal_file_not_detected(self):
        """Test normal files are not detected as secrets."""
        paths = [
            "/home/user/code/main.py",
            "/home/user/documents/readme.md",
            "/opt/ros/humble/setup.bash",
            "/usr/local/bin/python3",
        ]
        for path in paths:
            is_secret, kind = is_secret_path(path)
            assert is_secret is False, f"Expected {path} to NOT be detected as secret"

    def test_root_paths_detected(self):
        """Test root user secret paths are detected."""
        paths = [
            "/root/.codex/auth.json",
            "/root/.claude.json",
            "/root/.ssh/id_rsa",
        ]
        for path in paths:
            is_secret, kind = is_secret_path(path)
            assert is_secret is True, f"Expected {path} to be detected as secret"


class TestGeneratedConfigDetection:
    """Tests for generated config file detection."""

    def test_env_file_detected(self):
        """Test .env is detected as generated."""
        assert is_generated_config(".env") is True
        assert is_generated_config("/some/path/.env") is True

    def test_override_file_detected(self):
        """Test docker-compose.override.yml is detected."""
        assert is_generated_config("docker-compose.override.yml") is True

    def test_xauth_file_detected(self):
        """Test .docker.xauth is detected."""
        assert is_generated_config(".docker.xauth") is True
        assert is_generated_config("robotics-xauthority") is True

    def test_portable_files_not_detected(self):
        """Test portable files are not detected as generated."""
        files = [
            "Dockerfile",
            "docker-compose.yml",
            "env.sh",
            "common.sh",
        ]
        for f in files:
            assert is_generated_config(f) is False, f"Expected {f} to NOT be generated"


class TestNvidiaRuntimeFileDetection:
    """Tests for NVIDIA runtime file detection."""

    def test_nvidia_lib_detected(self):
        """Test NVIDIA library files are detected."""
        paths = [
            "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
            "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
            "/usr/lib/x86_64-linux-gnu/libnvidia-ptxjitcompiler.so.1",
        ]
        for path in paths:
            assert is_nvidia_runtime_file(path) is True, f"Expected {path} to be NVIDIA runtime"

    def test_nvidia_bin_detected(self):
        """Test NVIDIA binary files are detected."""
        paths = [
            "/usr/bin/nvidia-smi",
            "/usr/bin/nvidia-debugdump",
        ]
        for path in paths:
            assert is_nvidia_runtime_file(path) is True, f"Expected {path} to be NVIDIA runtime"

    def test_nvidia_firmware_detected(self):
        """Test NVIDIA firmware is detected."""
        assert is_nvidia_runtime_file("/usr/lib/firmware/nvidia/595.84/gsp.bin") is True

    def test_nvidia_config_detected(self):
        """Test NVIDIA config files are detected."""
        paths = [
            "/etc/nvidia/nvidia-application-profiles-rc",
            "/etc/OpenCL/vendors/nvidia.icd",
            "/etc/vulkan/icd.d/nvidia_icd.json",
        ]
        for path in paths:
            assert is_nvidia_runtime_file(path) is True, f"Expected {path} to be NVIDIA runtime"

    def test_non_nvidia_files_not_detected(self):
        """Test non-NVIDIA files are not detected."""
        paths = [
            "/usr/lib/libstdc++.so",
            "/opt/ros/humble/setup.bash",
            "/home/user/code/main.py",
        ]
        for path in paths:
            assert is_nvidia_runtime_file(path) is False, f"Expected {path} to NOT be NVIDIA"
