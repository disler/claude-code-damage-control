"""Pytest fixtures for path-normalization hook tests."""

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest


HOOK_DIR = Path(__file__).parent.parent
HOOK_PATH = HOOK_DIR / "path-normalization-hook.py"


@dataclass
class HookResult:
    """Result from running the path normalization hook."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def allowed(self) -> bool:
        """Check if the operation was allowed (exit 0)."""
        return self.exit_code == 0

    @property
    def blocked(self) -> bool:
        """Check if the operation was blocked (exit 2)."""
        return self.exit_code == 2


@pytest.fixture
def run_hook():
    """Fixture that returns a function to run the hook with given inputs.

    Returns:
        Function that accepts tool_name, file_path, and optional env overrides.
    """

    def _run_hook(
        tool_name: str,
        file_path: str,
        env: Optional[dict] = None,
    ) -> HookResult:
        """Run the path normalization hook.

        Args:
            tool_name: The Claude tool name (Edit, Write, Read, etc.)
            file_path: The file path to validate
            env: Optional environment variable overrides

        Returns:
            HookResult with exit_code, stdout, and stderr
        """
        input_data = {
            "tool_name": tool_name,
            "tool_input": {"file_path": file_path},
        }

        # Build environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        # On Windows, hide console windows to avoid focus-stealing
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            ["uv", "run", str(HOOK_PATH)],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=10,
            env=run_env,
            **kwargs,
        )

        return HookResult(
            exit_code=result.returncode,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
        )

    return _run_hook


@pytest.fixture
def mock_project_dir(tmp_path, monkeypatch):
    """Create a mock project directory and set CLAUDE_PROJECT_DIR.

    Args:
        tmp_path: pytest's built-in temporary directory fixture
        monkeypatch: pytest's monkeypatch fixture

    Returns:
        Path to the mock project directory
    """
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project_dir))
    return project_dir


@pytest.fixture
def mock_home_dir(tmp_path):
    """Create environment dict with mocked home directory.

    Args:
        tmp_path: pytest's built-in temporary directory fixture

    Returns:
        Dict with USERPROFILE set to temp path
    """
    home_dir = tmp_path / "home" / "TestUser"
    home_dir.mkdir(parents=True)
    return {"USERPROFILE": str(home_dir)}


@pytest.fixture
def run_hook_raw():
    """Fixture for running hook with arbitrary JSON input (for malformed input testing).

    Unlike run_hook, this allows testing with malformed tool_input structures,
    wrong types, or completely invalid JSON.

    Returns:
        Function that accepts a dict (or raw string) to send to the hook.
    """

    def _run_hook_raw(
        input_data: dict | str,
        env: Optional[dict] = None,
    ) -> HookResult:
        """Run the hook with raw input data.

        Args:
            input_data: Dict to JSON-encode, or raw string for invalid JSON testing
            env: Optional environment variable overrides

        Returns:
            HookResult with exit_code, stdout, and stderr
        """
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        # Allow raw strings for testing invalid JSON
        if isinstance(input_data, str):
            input_str = input_data
        else:
            input_str = json.dumps(input_data)

        result = subprocess.run(
            ["uv", "run", str(HOOK_PATH)],
            input=input_str,
            capture_output=True,
            text=True,
            timeout=10,
            env=run_env,
            **kwargs,
        )

        return HookResult(
            exit_code=result.returncode,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
        )

    return _run_hook_raw
