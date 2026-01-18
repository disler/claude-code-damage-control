"""Tests for context-aware damage control hooks.

Tests context detection and relaxed check behavior for:
- Documentation context (markdown files)
- Commit message context (git commit commands)
"""

import sys
import os
import importlib.util
from pathlib import Path

import pytest

# Add parent directory to path for imports
HOOK_DIR = Path(__file__).parent.parent

def load_module(name: str, filename: str):
    """Load a module with dashes in its filename."""
    spec = importlib.util.spec_from_file_location(name, HOOK_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Load modules with dashes in names
bash_tool = load_module("bash_tool", "bash-tool-damage-control.py")
edit_tool = load_module("edit_tool", "edit-tool-damage-control.py")
write_tool = load_module("write_tool", "write-tool-damage-control.py")

# Import functions
bash_detect_context = bash_tool.detect_context
check_command = bash_tool.check_command
edit_detect_context = edit_tool.detect_context
edit_check_path = edit_tool.check_path
write_detect_context = write_tool.detect_context
write_check_path = write_tool.check_path


# ============================================================================
# CONFIG FIXTURES
# ============================================================================

@pytest.fixture
def config_with_contexts_enabled():
    """Config with both contexts enabled."""
    return {
        "bashToolPatterns": [
            {"pattern": r"\brm\s+.*-[rRf]", "reason": "rm with dangerous flags"},
            {"pattern": r"\bgit\s+push\s+--force\b", "reason": "git push --force"},
        ],
        "zeroAccessPaths": ["~/.ssh/", ".env"],
        "readOnlyPaths": ["/etc/"],
        "noDeletePaths": ["README.md"],
        "contexts": {
            "documentation": {
                "enabled": True,
                "detection": {
                    "file_extensions": [".md", ".markdown", ".mdx", ".rst", ".adoc", ".txt"]
                },
                "relaxed_checks": ["bashToolPatterns"],
                "enforced_checks": ["zeroAccessPaths", "readOnlyPaths", "noDeletePaths"],
            },
            "commit_message": {
                "enabled": True,
                "detection": {
                    "command_patterns": [
                        r"git\s+commit.*-m",
                        r"git\s+commit.*<<\s*EOF",
                    ]
                },
                "relaxed_checks": ["bashToolPatterns"],
                "enforced_checks": ["zeroAccessPaths", "readOnlyPaths", "noDeletePaths", "semantic_git"],
            },
        },
    }


@pytest.fixture
def config_with_contexts_disabled():
    """Config with contexts disabled."""
    return {
        "bashToolPatterns": [
            {"pattern": r"\brm\s+.*-[rRf]", "reason": "rm with dangerous flags"},
        ],
        "zeroAccessPaths": ["~/.ssh/"],
        "readOnlyPaths": ["/etc/"],
        "noDeletePaths": [],
        "contexts": {
            "documentation": {
                "enabled": False,
                "detection": {"file_extensions": [".md"]},
                "relaxed_checks": ["bashToolPatterns"],
            },
            "commit_message": {
                "enabled": False,
                "detection": {"command_patterns": [r"git\s+commit.*-m"]},
                "relaxed_checks": ["bashToolPatterns"],
            },
        },
    }


@pytest.fixture
def config_without_contexts():
    """Config without contexts section (backward compatibility)."""
    return {
        "bashToolPatterns": [
            {"pattern": r"\brm\s+.*-[rRf]", "reason": "rm with dangerous flags"},
        ],
        "zeroAccessPaths": ["~/.ssh/", ".env"],
        "readOnlyPaths": ["/etc/"],
        "noDeletePaths": [],
    }


# ============================================================================
# DOCUMENTATION CONTEXT DETECTION TESTS
# ============================================================================

class TestDocumentationContextDetection:
    """Tests for documentation context detection."""

    @pytest.mark.parametrize("file_path,expected", [
        ("README.md", "documentation"),
        ("docs/guide.md", "documentation"),
        ("CHANGELOG.markdown", "documentation"),
        ("tutorial.mdx", "documentation"),
        ("manual.rst", "documentation"),
        ("guide.adoc", "documentation"),
        ("notes.txt", "documentation"),
        ("script.py", None),
        ("config.json", None),
        ("data.yaml", None),
        (".env.md", "documentation"),  # Extension takes precedence
    ])
    def test_edit_tool_context_detection(self, config_with_contexts_enabled, file_path, expected):
        """Edit tool correctly detects documentation context by file extension."""
        context = edit_detect_context(
            "Edit",
            {"file_path": file_path},
            config_with_contexts_enabled
        )
        assert context == expected

    @pytest.mark.parametrize("file_path,expected", [
        ("README.md", "documentation"),
        ("script.py", None),
    ])
    def test_write_tool_context_detection(self, config_with_contexts_enabled, file_path, expected):
        """Write tool correctly detects documentation context by file extension."""
        context = write_detect_context(
            "Write",
            {"file_path": file_path},
            config_with_contexts_enabled
        )
        assert context == expected

    def test_context_disabled(self, config_with_contexts_disabled):
        """Context detection returns None when disabled."""
        context = edit_detect_context(
            "Edit",
            {"file_path": "README.md"},
            config_with_contexts_disabled
        )
        assert context is None

    def test_context_missing(self, config_without_contexts):
        """Context detection returns None when contexts section missing."""
        context = edit_detect_context(
            "Edit",
            {"file_path": "README.md"},
            config_without_contexts
        )
        assert context is None


# ============================================================================
# COMMIT MESSAGE CONTEXT DETECTION TESTS
# ============================================================================

class TestCommitMessageContextDetection:
    """Tests for commit message context detection."""

    @pytest.mark.parametrize("command,expected", [
        ('git commit -m "fix: something"', "commit_message"),
        ("git commit -m 'test commit'", "commit_message"),
        ('git commit --message="update docs"', "commit_message"),  # Contains -m in --message
        ("git commit << EOF\nmessage\nEOF", "commit_message"),
        ("git status", None),
        ("git push origin main", None),
        ("ls -la", None),
    ])
    def test_bash_tool_commit_context_detection(self, config_with_contexts_enabled, command, expected):
        """Bash tool correctly detects commit message context."""
        context = bash_detect_context(
            "Bash",
            {"command": command},
            config_with_contexts_enabled
        )
        assert context == expected

    def test_commit_context_disabled(self, config_with_contexts_disabled):
        """Commit context detection returns None when disabled."""
        context = bash_detect_context(
            "Bash",
            {"command": 'git commit -m "test"'},
            config_with_contexts_disabled
        )
        assert context is None


# ============================================================================
# RELAXED CHECKS IN DOCUMENTATION CONTEXT
# ============================================================================

class TestDocumentationContextRelaxedChecks:
    """Tests that bash patterns are relaxed in documentation context."""

    def test_edit_allows_with_context(self, config_with_contexts_enabled, tmp_log_dir):
        """Edit tool allows editing markdown even when it would normally block bash patterns."""
        # Note: Edit tool doesn't check bash patterns, only path protections
        # This tests that path protections are still enforced
        blocked, reason = edit_check_path(
            "README.md",
            config_with_contexts_enabled,
            context="documentation"
        )
        assert not blocked

    def test_edit_still_blocks_zero_access(self, config_with_contexts_enabled, tmp_log_dir):
        """Edit tool still blocks zero-access paths even in documentation context."""
        # Use .env which is a glob pattern in zero-access
        blocked, reason = edit_check_path(
            ".env",
            config_with_contexts_enabled,
            context="documentation"
        )
        assert blocked
        assert "zero-access" in reason

    def test_write_allows_with_context(self, config_with_contexts_enabled, tmp_log_dir):
        """Write tool allows writing to markdown files in documentation context."""
        blocked, reason = write_check_path(
            "docs/guide.md",
            config_with_contexts_enabled,
            context="documentation"
        )
        assert not blocked

    def test_write_still_blocks_zero_access(self, config_with_contexts_enabled, tmp_log_dir):
        """Write tool still blocks zero-access paths even in documentation context."""
        blocked, reason = write_check_path(
            ".env",
            config_with_contexts_enabled,
            context="documentation"
        )
        assert blocked
        assert "zero-access" in reason


# ============================================================================
# RELAXED CHECKS IN COMMIT MESSAGE CONTEXT
# ============================================================================

class TestCommitMessageContextRelaxedChecks:
    """Tests that bash patterns are relaxed in commit message context."""

    def test_commit_message_allows_dangerous_pattern_mention(self, config_with_contexts_enabled, tmp_log_dir):
        """Commit message can mention dangerous commands without blocking."""
        # When in commit_message context, bashToolPatterns should be relaxed
        command = 'git commit -m "fix: prevent git push --force issue"'
        blocked, ask, reason, pattern, unwrapped, semantic = check_command(
            command,
            config_with_contexts_enabled,
            context="commit_message"
        )
        # The pattern "git push --force" is in bashToolPatterns, but context relaxes it
        assert not blocked

    def test_commit_message_still_blocks_zero_access(self, config_with_contexts_enabled, tmp_log_dir):
        """Commit context still blocks zero-access path operations."""
        # This command touches ~/.ssh which is zero-access
        command = 'cat ~/.ssh/id_rsa && git commit -m "test"'
        blocked, ask, reason, pattern, unwrapped, semantic = check_command(
            command,
            config_with_contexts_enabled,
            context="commit_message"
        )
        assert blocked
        assert "zero-access" in reason


# ============================================================================
# NO CONTEXT - STANDARD BEHAVIOR
# ============================================================================

class TestNoContextStandardBehavior:
    """Tests that standard blocking works when no context is detected."""

    def test_bash_blocks_dangerous_pattern_without_context(self, config_with_contexts_enabled, tmp_log_dir):
        """Bash tool blocks dangerous patterns when not in a context."""
        command = "rm -rf /tmp/data"
        blocked, ask, reason, pattern, unwrapped, semantic = check_command(
            command,
            config_with_contexts_enabled,
            context=None
        )
        assert blocked or ask  # Either blocked or requires confirmation

    def test_edit_blocks_zero_access_without_context(self, config_with_contexts_enabled, tmp_log_dir):
        """Edit tool blocks zero-access paths when not in a context."""
        # Test with exact .env match (not .env.example which should be allowed)
        blocked, reason = edit_check_path(
            ".env",
            config_with_contexts_enabled,
            context=None
        )
        assert blocked
        assert "zero-access" in reason

    def test_write_blocks_zero_access_without_context(self, config_with_contexts_enabled, tmp_log_dir):
        """Write tool blocks zero-access paths when not in a context."""
        # Test with exact .env match (not .env.example which should be allowed)
        blocked, reason = write_check_path(
            ".env",
            config_with_contexts_enabled,
            context=None
        )
        assert blocked
        assert "zero-access" in reason


# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

class TestBackwardCompatibility:
    """Tests that hooks work without contexts configuration."""

    def test_bash_works_without_contexts(self, config_without_contexts, tmp_log_dir):
        """Bash tool functions normally without contexts in config."""
        command = "rm -rf /tmp/data"
        blocked, ask, reason, pattern, unwrapped, semantic = check_command(
            command,
            config_without_contexts,
            context=None
        )
        assert blocked or ask

    def test_edit_works_without_contexts(self, config_without_contexts, tmp_log_dir):
        """Edit tool functions normally without contexts in config."""
        blocked, reason = edit_check_path(
            ".env",
            config_without_contexts,
            context=None
        )
        assert blocked

    def test_write_works_without_contexts(self, config_without_contexts, tmp_log_dir):
        """Write tool functions normally without contexts in config."""
        blocked, reason = write_check_path(
            ".env",
            config_without_contexts,
            context=None
        )
        assert blocked
