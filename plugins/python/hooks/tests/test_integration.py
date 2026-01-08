#!/usr/bin/env python
"""Test integration of git semantic analysis with check_command."""

import sys
import os
from pathlib import Path

import pytest

# Import the hook module
import importlib.util

HOOK_DIR = Path(__file__).parent.parent

def load_module(name: str, filename: str):
    """Load a module with dashes in its filename."""
    spec = importlib.util.spec_from_file_location(name, HOOK_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bash_tool = load_module("bash_tool", "bash-tool-damage-control.py")
check_command = bash_tool.check_command


@pytest.fixture
def minimal_config():
    """Minimal test configuration."""
    return {
        "bashToolPatterns": [],
        "zeroAccessPaths": [],
        "readOnlyPaths": [],
        "noDeletePaths": []
    }


class TestGitSemanticIntegration:
    """Integration tests for git semantic analysis with check_command."""

    @pytest.mark.parametrize("command,expected_blocked,description", [
        # Git semantic analysis should catch these
        ('git checkout -- .', True, 'Git semantic: checkout with --'),
        ('git push --force', True, 'Git semantic: force push'),
        ('git reset --hard', True, 'Git semantic: hard reset'),
        ('git clean -fd', True, 'Git semantic: clean with flags'),
        # These should pass
        ('git checkout -b feature', False, 'Git semantic: safe checkout -b'),
        ('git push --force-with-lease', False, 'Git semantic: safe force with lease'),
        ('git status', False, 'Git semantic: safe status'),
        # Shell unwrapping + git semantic
        ('bash -c "git push --force"', True, 'Unwrapped git force push'),
        ('sh -c "git reset --hard"', True, 'Unwrapped git hard reset'),
    ])
    def test_git_semantic_integration(self, minimal_config, command, expected_blocked, description):
        """Test that git semantic analysis integrates with check_command."""
        is_blocked, should_ask, reason, pattern, unwrapped, semantic = check_command(
            command, minimal_config
        )
        assert is_blocked == expected_blocked, f"{description}: expected {expected_blocked}, got {is_blocked}"
