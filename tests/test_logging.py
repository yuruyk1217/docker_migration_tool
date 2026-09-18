"""Tests for logging utilities."""

import pytest

from docker_migration_tool.utils.logging import (
    redact_value,
    safe_env_dict,
)


class TestCredentialRedaction:
    """Tests for credential value redaction."""

    def test_api_key_redacted(self):
        """Test that API_KEY values are redacted."""
        assert redact_value("API_KEY", "secret123") == "[REDACTED]"
        assert redact_value("OPENAI_API_KEY", "sk-xxx") == "[REDACTED]"
        assert redact_value("my_api_key", "token") == "[REDACTED]"

    def test_token_redacted(self):
        """Test that TOKEN values are redacted."""
        assert redact_value("AUTH_TOKEN", "abc123") == "[REDACTED]"
        assert redact_value("GITHUB_TOKEN", "ghp_xxx") == "[REDACTED]"
        assert redact_value("access_token", "xyz") == "[REDACTED]"

    def test_secret_redacted(self):
        """Test that SECRET values are redacted."""
        assert redact_value("CLIENT_SECRET", "secret") == "[REDACTED]"
        assert redact_value("AWS_SECRET_ACCESS_KEY", "xxx") == "[REDACTED]"

    def test_password_redacted(self):
        """Test that PASSWORD values are redacted."""
        assert redact_value("PASSWORD", "hunter2") == "[REDACTED]"
        assert redact_value("DB_PASSWORD", "pass123") == "[REDACTED]"
        assert redact_value("user_password", "xxx") == "[REDACTED]"

    def test_credential_redacted(self):
        """Test that CREDENTIAL values are redacted."""
        assert redact_value("CREDENTIAL", "xxx") == "[REDACTED]"
        assert redact_value("AWS_CREDENTIAL", "xxx") == "[REDACTED]"

    def test_aws_prefix_redacted(self):
        """Test that AWS_* values are redacted."""
        assert redact_value("AWS_ACCESS_KEY_ID", "AKIA...") == "[REDACTED]"
        assert redact_value("AWS_SESSION_TOKEN", "xxx") == "[REDACTED]"

    def test_openai_prefix_redacted(self):
        """Test that OPENAI_* values are redacted."""
        assert redact_value("OPENAI_ORG", "org-xxx") == "[REDACTED]"

    def test_anthropic_prefix_redacted(self):
        """Test that ANTHROPIC_* values are redacted."""
        assert redact_value("ANTHROPIC_API_KEY", "sk-ant-xxx") == "[REDACTED]"

    def test_normal_values_not_redacted(self):
        """Test that normal values are not redacted."""
        assert redact_value("PATH", "/usr/bin") == "/usr/bin"
        assert redact_value("HOME", "/home/user") == "/home/user"
        assert redact_value("ROS_DISTRO", "humble") == "humble"
        assert redact_value("DISPLAY", ":1") == ":1"
        assert redact_value("USER", "robotics") == "robotics"
        assert redact_value("WORKSPACE_NAME", "my_ws") == "my_ws"

    def test_case_insensitive(self):
        """Test that redaction is case insensitive."""
        assert redact_value("api_key", "xxx") == "[REDACTED]"
        assert redact_value("Api_Key", "xxx") == "[REDACTED]"
        assert redact_value("API_KEY", "xxx") == "[REDACTED]"


class TestSafeEnvDict:
    """Tests for safe environment dict creation."""

    def test_mixed_env_redaction(self):
        """Test redaction of mixed environment variables."""
        env = {
            "PATH": "/usr/bin",
            "API_KEY": "secret123",
            "HOME": "/home/user",
            "AWS_SECRET_ACCESS_KEY": "xxx",
            "ROS_DISTRO": "humble",
            "PASSWORD": "hunter2",
        }

        safe = safe_env_dict(env)

        assert safe["PATH"] == "/usr/bin"
        assert safe["API_KEY"] == "[REDACTED]"
        assert safe["HOME"] == "/home/user"
        assert safe["AWS_SECRET_ACCESS_KEY"] == "[REDACTED]"
        assert safe["ROS_DISTRO"] == "humble"
        assert safe["PASSWORD"] == "[REDACTED]"

    def test_empty_dict(self):
        """Test with empty dict."""
        assert safe_env_dict({}) == {}

    def test_all_safe(self):
        """Test with all safe values."""
        env = {
            "PATH": "/usr/bin",
            "HOME": "/home/user",
            "USER": "robotics",
        }
        safe = safe_env_dict(env)
        assert safe == env

    def test_all_secrets(self):
        """Test with all secrets."""
        env = {
            "API_KEY": "xxx",
            "PASSWORD": "yyy",
            "TOKEN": "zzz",
        }
        safe = safe_env_dict(env)
        assert all(v == "[REDACTED]" for v in safe.values())
