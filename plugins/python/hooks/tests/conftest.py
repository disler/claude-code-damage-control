"""Pytest fixtures for damage-control hook tests."""

import os
import pytest
from pathlib import Path


@pytest.fixture
def tmp_log_dir(tmp_path, monkeypatch):
    """Isolated log directory for tests.

    Creates a temporary log directory for isolation. On Windows,
    os.path.expanduser("~") doesn't respect HOME env var, so we
    monkey-patch os.path.expanduser directly.

    Args:
        tmp_path: pytest's built-in temporary directory fixture
        monkeypatch: pytest's monkeypatch fixture for env vars

    Returns:
        Path object to the temporary log directory
    """
    import os.path as path_module

    # Create the log directory structure
    log_dir = tmp_path / ".claude" / "logs" / "damage-control"
    log_dir.mkdir(parents=True)

    # Monkey-patch os.path.expanduser to return our tmp_path for "~"
    original_expanduser = path_module.expanduser
    def mock_expanduser(path_str):
        if path_str.startswith("~"):
            return path_str.replace("~", str(tmp_path), 1)
        return original_expanduser(path_str)

    monkeypatch.setattr(path_module, "expanduser", mock_expanduser)

    return log_dir


@pytest.fixture
def sample_commands():
    """Common command strings for testing.

    Returns:
        Dict of command categories with example commands
    """
    return {
        "simple": [
            "ls -la",
            "echo hello",
            "git status",
        ],
        "wrapped_bash": [
            'bash -c "rm -rf /"',
            "sh -c 'git reset --hard'",
            'zsh -c "dangerous command"',
        ],
        "wrapped_python": [
            'python -c "import os; os.system(\'rm -rf /\')"',
            "python3 -c \"import subprocess; subprocess.run(['rm', '-rf', '/'])\"",
        ],
        "wrapped_env": [
            "env PATH=/usr/bin rm -rf /",
            "env DEBUG=1 VAR=val dangerous_command",
        ],
        "nested": [
            'bash -c "sh -c \'rm -rf /\'"',
            'python -c "import os; os.system(\'bash -c \\\"rm -rf /\\\"\')"',
        ],
        "git_safe": [
            "git checkout -b feature",
            "git checkout main",
            "git push --force-with-lease",
            "git reset --soft HEAD~1",
        ],
        "git_dangerous": [
            "git checkout -- .",
            "git checkout -f main",
            "git push --force",
            "git push -f",
            "git reset --hard HEAD~1",
            "git clean -fd",
        ],
    }


@pytest.fixture
def sample_secrets():
    """Sample secret patterns for redaction testing.

    Returns:
        Dict of secret types with example values
    """
    return {
        "api_keys": [
            "curl -H 'apikey=sk_live_1234567890abcdef' https://api.example.com",
            "export api_key=ghp_1234567890abcdefghijklmnopqrstuv",
        ],
        "passwords": [
            "mysql -u root -pMySecretPassword123",
            "curl -u user:password=secret123 https://example.com",
        ],
        "aws_keys": [
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE",
        ],
        "tokens": [
            "export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuv",
            "docker login -p dckr_pat_1234567890abcdefghij",
        ],
    }
