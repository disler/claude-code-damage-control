#!/usr/bin/env python
"""Test git semantic analysis implementation."""

import sys
import os
from pathlib import Path

import pytest

# Import with dash converted to underscore won't work, need to use importlib
import importlib.util

HOOK_DIR = Path(__file__).parent.parent

def load_module(name: str, filename: str):
    """Load a module with dashes in its filename."""
    spec = importlib.util.spec_from_file_location(name, HOOK_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bash_tool = load_module("bash_tool", "bash-tool-damage-control.py")
analyze_git_command = bash_tool.analyze_git_command


class TestGitSemanticAnalysis:
    """Tests for git semantic analysis."""

    @pytest.mark.parametrize("command,expected_dangerous,description", [
        ('git checkout -b feature', False, 'Creating branch should be safe'),
        ('git checkout -- .', True, 'Discarding changes should be dangerous'),
        ('git push --force-with-lease', False, 'Force with lease should be safe'),
        ('git push --force', True, 'Force push should be dangerous'),
        ('git push -f', True, 'Force push short flag should be dangerous'),
        ('git push -fu origin main', True, 'Combined short flags with -f should be dangerous'),
        ('git reset --soft HEAD~1', False, 'Soft reset should be safe'),
        ('git reset --hard HEAD~1', True, 'Hard reset should be dangerous'),
        ('git clean -f', True, 'Clean with -f should be dangerous'),
        ('git clean -fd', True, 'Clean with combined flags should be dangerous'),
        ('git status', False, 'Status should be safe'),
        ('git checkout -b new-feature -- .', False, 'Creating branch makes it safe despite --'),
        ('ls -la', False, 'Non-git command should be safe'),
        ('git', False, 'Git with no subcommand should be safe'),
        ('git my-alias', False, 'Unknown subcommand should be safe'),
        ('git checkout -f branch', True, 'Checkout with -f should be dangerous'),
        ('git checkout -fb new-branch', True, 'Checkout with -fb should be dangerous (contains -f)'),
    ])
    def test_git_semantic_analysis(self, command, expected_dangerous, description):
        """Test git semantic analysis detects dangerous commands correctly."""
        is_dangerous, reason = analyze_git_command(command)
        assert is_dangerous == expected_dangerous, f"{description}: expected {expected_dangerous}, got {is_dangerous}"
