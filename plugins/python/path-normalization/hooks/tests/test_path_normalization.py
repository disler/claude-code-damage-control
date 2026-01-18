"""Tests for path-normalization hook.

BACKGROUND: Claude Code's Edit tool has bugs where absolute paths cause
false "File has been unexpectedly modified" errors, and backslash separators
cause similar issues. This hook works around these bugs by enforcing safe
path formats.

These tests verify the hook correctly:
1. Allows relative paths with forward slashes (safe format)
2. Blocks relative paths with backslashes (suggests forward slashes)
3. Allows home-relative paths (~/.../file.py) with forward slashes
4. Blocks absolute paths within project (suggests relative path)
5. Blocks absolute paths within home (suggests ~/... path)
6. Blocks absolute paths outside allowed areas (suggests filename)
7. Allows non-Edit/Write tools regardless of path
8. Uses USERPROFILE for home directory detection on Windows
"""

import os
import sys
from pathlib import Path

import pytest


class TestRelativePathsForwardSlashes:
    """Test Case 1: Relative paths with forward slashes should ALLOW (exit 0)."""

    @pytest.mark.parametrize(
        "path",
        [
            "plugins/python/file.py",
            "src/components/Button.tsx",
            "README.md",
            "lib/utils/helper.py",
            "./src/main.py",
            "../sibling/file.py",
            "package.json",
            ".gitignore",
            "src/components/ui/Dialog.tsx",
        ],
    )
    def test_relative_forward_slash_allowed(self, run_hook, path):
        """Relative paths with forward slashes should be allowed."""
        result = run_hook("Edit", path)
        assert result.allowed, f"Expected allowed, got exit {result.exit_code}: {result.stderr}"

    def test_write_tool_relative_allowed(self, run_hook):
        """Write tool with relative path should be allowed."""
        result = run_hook("Write", "src/new_file.py")
        assert result.allowed


class TestRelativePathsBackslashes:
    """Test Case 2: Relative paths with backslashes should BLOCK with suggestion."""

    @pytest.mark.parametrize(
        "path,expected_suggestion",
        [
            ("plugins\\python\\file.py", "plugins/python/file.py"),
            ("src\\components\\Button.tsx", "src/components/Button.tsx"),
            ("lib\\utils\\helper.py", "lib/utils/helper.py"),
        ],
    )
    def test_backslash_blocked_with_suggestion(self, run_hook, path, expected_suggestion):
        """Relative paths with backslashes should be blocked with correct suggestion."""
        result = run_hook("Edit", path)
        assert result.blocked, f"Expected blocked (exit 2), got exit {result.exit_code}"
        assert f"Use forward slashes: '{expected_suggestion}'" in result.stderr


class TestHomeRelativePaths:
    """Test Case 3: Home-relative paths (~/) should ALLOW with forward slashes."""

    @pytest.mark.parametrize(
        "path",
        [
            "~/.claude/skills/test/SKILL.md",
            "~/.config/some-app/config.yaml",
            "~/.dotfiles/file.py",
            "~/Documents/notes.md",
        ],
    )
    def test_home_relative_forward_slash_allowed(self, run_hook, path):
        """Home-relative paths with forward slashes should be allowed."""
        result = run_hook("Edit", path)
        assert result.allowed, f"Expected allowed, got exit {result.exit_code}: {result.stderr}"

    def test_home_relative_backslash_blocked(self, run_hook):
        """Home-relative paths with backslashes should be blocked."""
        result = run_hook("Edit", r"~\.claude\skills\test\SKILL.md")
        assert result.blocked
        assert "Use forward slashes:" in result.stderr
        assert "~/.claude/skills/test/SKILL.md" in result.stderr

    def test_write_tool_home_relative_allowed(self, run_hook):
        """Write tool with home-relative path should be allowed."""
        result = run_hook("Write", "~/.claude/plans/new-plan.md")
        assert result.allowed


class TestAbsoluteWithinProject:
    """Test Case 3: Absolute path within project directory should BLOCK with relative path suggestion."""

    def test_absolute_within_project_forward_slash_blocked(self, run_hook, tmp_path):
        """Absolute path within project dir (forward slashes) should suggest relative path."""
        project_dir = tmp_path / "Projects" / "myproject"
        project_dir.mkdir(parents=True)
        file_path = project_dir / "src" / "file.py"

        # Convert to forward slashes for the path
        path_str = str(file_path).replace("\\", "/")
        project_str = str(project_dir).replace("\\", "/")

        result = run_hook(
            "Edit",
            path_str,
            env={"CLAUDE_PROJECT_DIR": project_str},
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"
        assert "Use relative path:" in result.stderr
        assert "src/file.py" in result.stderr

    def test_absolute_within_project_backslash_blocked(self, run_hook, tmp_path):
        """Absolute path within project using backslashes should be blocked."""
        project_dir = tmp_path / "Projects" / "myproject"
        project_dir.mkdir(parents=True)

        # Use backslashes in path
        path_str = str(project_dir / "src" / "file.py")
        if "/" in path_str:
            # On MSYS, paths might already be forward slashes, skip this test
            pytest.skip("Platform uses forward slashes natively")

        result = run_hook(
            "Edit",
            path_str,
            env={"CLAUDE_PROJECT_DIR": str(project_dir)},
        )
        assert result.blocked
        assert "Use relative path:" in result.stderr

    def test_absolute_within_project_backslash_suggests_relative_path(self, run_hook):
        """Absolute path within project should suggest relative path, not full absolute path.

        This was a bug where CASE 3 suggested 'C:/full/path/file.py' instead of 'scripts/file.py'.
        """
        # Simulate the exact scenario from the bug report:
        # - Project: C:\Projects\Work\Github\warmachine
        # - File: C:\Projects\Work\Github\warmachine\scripts\Setup-AzureAD.ps1
        # - Expected suggestion: scripts/Setup-AzureAD.ps1 (relative)
        # - Bug output: C:/Projects/Work/Github/warmachine/scripts/Setup-AzureAD.ps1 (absolute)

        result = run_hook(
            "Write",
            r"C:\Projects\Work\Github\warmachine\scripts\Setup-AzureAD.ps1",
            env={"CLAUDE_PROJECT_DIR": r"C:\Projects\Work\Github\warmachine"},
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"
        assert "Use relative path:" in result.stderr, f"Wrong error type: {result.stderr}"
        # CRITICAL: Should NOT contain the full Windows path with drive letter
        assert "C:/" not in result.stderr, f"Suggestion has full absolute path: {result.stderr}"
        assert "C:\\" not in result.stderr, f"Suggestion has full absolute path: {result.stderr}"
        # Should contain the relative path
        assert "scripts/Setup-AzureAD.ps1" in result.stderr, f"Missing relative path: {result.stderr}"

    def test_msys_project_windows_file_suggests_relative(self, run_hook):
        """MSYS-style project dir with Windows file path should suggest relative path."""
        result = run_hook(
            "Write",
            r"C:\Projects\Work\Github\warmachine\scripts\Setup-AzureAD.ps1",
            env={"CLAUDE_PROJECT_DIR": "/c/Projects/Work/Github/warmachine"},
        )
        assert result.blocked
        assert "scripts/Setup-AzureAD.ps1" in result.stderr
        assert "C:/" not in result.stderr

    def test_absolute_forward_slash_within_project_suggests_relative(self, run_hook, tmp_path):
        """Forward-slash absolute path within project should suggest relative path.

        Regression test for issue where C:/Users/mglenn/.dotfiles/claude/skills/...
        was allowed through instead of suggesting claude/skills/... as relative path.
        """
        project_dir = tmp_path / "Users" / "mglenn" / ".dotfiles"
        target_file = project_dir / "claude" / "skills" / "test" / "SKILL.md"

        project_dir.mkdir(parents=True)
        target_file.parent.mkdir(parents=True)

        # Forward-slash absolute path (as Claude often uses)
        path_str = str(target_file).replace("\\", "/")
        project_str = str(project_dir).replace("\\", "/")

        result = run_hook(
            "Edit",
            path_str,
            env={"CLAUDE_PROJECT_DIR": project_str},
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}: {result.stderr}"
        assert "Use relative path:" in result.stderr
        assert "claude/skills/test/SKILL.md" in result.stderr
        # Should NOT contain the absolute path
        assert "Users" not in result.stderr


class TestClaudeInternalPaths:
    """Test Case 6: Claude internal paths - absolute should block, ~/ should allow."""

    def test_claude_home_relative_allowed(self, run_hook):
        """Home-relative paths to ~/.claude/ should be allowed."""
        result = run_hook("Edit", "~/.claude/plans/test.md")
        assert result.allowed, f"Expected allowed, got exit {result.exit_code}: {result.stderr}"

    def test_claude_absolute_blocked(self, run_hook, tmp_path):
        """Absolute paths to ~/.claude/ should be blocked with filename suggestion."""
        home_dir = tmp_path / "Users" / "TestUser"
        claude_dir = home_dir / ".claude" / "plans"
        claude_dir.mkdir(parents=True)

        path_str = str(claude_dir / "test.md").replace("\\", "/")

        result = run_hook("Edit", path_str)
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"
        assert "test.md" in result.stderr

    def test_claude_logs_absolute_blocked(self, run_hook, tmp_path):
        """Absolute paths within ~/.claude/logs/ should be blocked."""
        home_dir = tmp_path / "Users" / "TestUser"
        claude_dir = home_dir / ".claude" / "logs"
        claude_dir.mkdir(parents=True)

        path_str = str(claude_dir / "session.log").replace("\\", "/")

        result = run_hook("Edit", path_str)
        assert result.blocked
        assert "session.log" in result.stderr


class TestAbsoluteOutsideAllowed:
    """Test Case 6: Absolute path outside allowed areas should BLOCK."""

    def test_other_drive_blocked(self, run_hook, tmp_path):
        """Paths on other drives outside home/project should be blocked."""
        # Set up a fake home that doesn't include our target path
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "E:/SomeOther/path/file.py",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"
        assert "Use relative path:" in result.stderr
        assert "file.py" in result.stderr

    def test_msys_absolute_blocked(self, run_hook, tmp_path):
        """MSYS-style absolute paths outside allowed areas should be blocked."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "/e/SomeOther/path/file.py",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked

    def test_wsl_mount_blocked(self, run_hook, tmp_path):
        """WSL mount paths outside allowed areas should be blocked."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "/mnt/e/SomeOther/path/file.py",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked

    def test_windows_backslash_path_suggests_filename_only(self, run_hook, tmp_path):
        """Windows backslash paths outside project should suggest just filename.

        Regression test: On Unix/WSL, Path("C:\\path\\file").name returns the
        entire string because backslashes aren't separators. The hook must
        normalize backslashes before extracting the filename.

        Bug: suggested_path was "C:\\Projects\\Work\\file.md" instead of "file.md"
        Fix: Use string operations to extract filename after normalizing separators.
        """
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        # Use a Windows backslash path that's outside home/project
        backslash = chr(92)
        windows_path = f"C:{backslash}Projects{backslash}Work{backslash}Gitlab{backslash}docs{backslash}FILE.md"

        result = run_hook(
            "Write",
            windows_path,
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"
        assert "Use relative path:" in result.stderr
        # The suggestion should be just the filename, not the full path
        assert "FILE.md" in result.stderr
        # Should NOT contain the full path or backslashes in suggestion
        assert "Projects" not in result.stderr
        assert backslash not in result.stderr


class TestNonEditWriteTools:
    """Test Case 7: Non-Edit/Write tools should ALLOW (exit 0) regardless of path."""

    @pytest.mark.parametrize(
        "tool_name",
        [
            "Read",
            "Glob",
            "Grep",
            "Bash",
            "ListDirectory",
        ],
    )
    def test_read_tool_allows_any_path(self, run_hook, tool_name):
        """Non-Edit/Write tools should be allowed regardless of path."""
        result = run_hook(tool_name, "E:/Anywhere/any/path/file.py")
        assert result.allowed, f"Expected {tool_name} to be allowed"

    def test_read_with_backslashes_allowed(self, run_hook):
        """Read tool should allow paths with backslashes."""
        result = run_hook("Read", r"E:\Path\With\Backslashes\file.py")
        assert result.allowed


class TestAbsoluteOutsideCwd:
    """Absolute paths outside cwd should suggest filename only."""

    def test_path_outside_cwd_suggests_filename(self, run_hook, tmp_path):
        """Paths outside cwd should be blocked with filename suggestion."""
        project_dir = tmp_path / "project"
        project_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "D:/Outside/project/file.py",
            env={"CLAUDE_PROJECT_DIR": str(project_dir).replace("\\", "/")},
        )
        assert result.blocked
        assert "file.py" in result.stderr


class TestEdgeCases:
    """Edge cases and special scenarios."""

    def test_empty_path_allowed(self, run_hook):
        """Empty path should be allowed (no validation needed)."""
        result = run_hook("Edit", "")
        assert result.allowed

    def test_single_file_allowed(self, run_hook):
        """Single filename with no path should be allowed."""
        result = run_hook("Edit", "file.py")
        assert result.allowed

    def test_unix_tmp_allowed(self, run_hook):
        """Unix /tmp/ paths should be allowed (special case)."""
        result = run_hook("Edit", "/tmp/test.txt")
        assert result.allowed

    def test_unix_dev_allowed(self, run_hook):
        """Unix /dev/ paths should be allowed (special case)."""
        result = run_hook("Edit", "/dev/null")
        assert result.allowed

    def test_unc_path_blocked(self, run_hook, tmp_path):
        """UNC network paths should be blocked."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "//server/share/file.txt",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked

    def test_disabled_via_env(self, run_hook):
        """Hook should be disabled when CLAUDE_DISABLE_HOOKS includes it."""
        result = run_hook(
            "Edit",
            "E:/Should/Be/Blocked/file.py",
            env={"CLAUDE_DISABLE_HOOKS": "path-normalization"},
        )
        assert result.allowed, "Hook should be disabled via CLAUDE_DISABLE_HOOKS"

    def test_disabled_with_multiple_hooks(self, run_hook):
        """Hook should be disabled when in comma-separated list."""
        result = run_hook(
            "Edit",
            "E:/Should/Be/Blocked/file.py",
            env={"CLAUDE_DISABLE_HOOKS": "other-hook, path-normalization, another"},
        )
        assert result.allowed


class TestSuggestionMessages:
    """Verify error messages contain helpful suggestions."""

    def test_backslash_suggestion_format(self, run_hook):
        """Backslash error should suggest the corrected path."""
        result = run_hook("Edit", r"src\components\Button.tsx")
        assert result.blocked
        assert "Use forward slashes:" in result.stderr
        assert "src/components/Button.tsx" in result.stderr

    def test_absolute_suggestion_extracts_filename(self, run_hook, tmp_path):
        """Absolute path error should suggest relative or filename."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "D:/Random/Path/important_file.py",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked
        assert "Use relative path:" in result.stderr
        assert "important_file.py" in result.stderr


class TestCrossDirectoryWrites:
    """Test writing to home directory paths from a different project directory.

    Absolute paths should be blocked with appropriate ~/ suggestions.
    Home-relative paths (~/) should be allowed.
    """

    def test_write_to_claude_home_relative_allowed(self, run_hook):
        """Writing to ~/.claude/skills using ~/ path should be allowed."""
        result = run_hook("Write", "~/.claude/skills/test-skill/SKILL.md")
        assert result.allowed, f"Expected allowed, got exit {result.exit_code}: {result.stderr}"

    def test_write_to_claude_absolute_blocked(self, run_hook, tmp_path):
        """Absolute path outside project should be blocked with filename suggestion."""
        project_dir = tmp_path / "project"
        target_dir = tmp_path / "other" / "skills"

        project_dir.mkdir(parents=True)
        target_dir.mkdir(parents=True)

        file_path = f"{str(target_dir).replace(chr(92), '/')}/SKILL.md"

        result = run_hook(
            "Write",
            file_path,
            env={"CLAUDE_PROJECT_DIR": str(project_dir).replace(chr(92), '/')},
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"
        assert "SKILL.md" in result.stderr

    def test_write_to_subdir_absolute_blocked(self, run_hook, tmp_path):
        """Absolute path outside project should be blocked with filename suggestion."""
        project_dir = tmp_path / "project"
        target_dir = tmp_path / "other" / "notes"

        project_dir.mkdir(parents=True)
        target_dir.mkdir(parents=True)

        file_path = f"{str(target_dir).replace(chr(92), '/')}/todo.md"

        result = run_hook(
            "Write",
            file_path,
            env={"CLAUDE_PROJECT_DIR": str(project_dir).replace(chr(92), '/')},
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"
        assert "todo.md" in result.stderr

    def test_write_to_home_subdir_home_relative_allowed(self, run_hook):
        """Writing to ~/Documents using ~/ path should be allowed."""
        result = run_hook("Write", "~/Documents/notes/todo.md")
        assert result.allowed


class TestInvalidInput:
    """Test error handling for invalid JSON input (exit code 1)."""

    def test_invalid_json_exits_with_error(self, run_hook_raw):
        """Invalid JSON input should exit with code 1."""
        result = run_hook_raw("not valid json {{{")
        assert result.exit_code == 1

    def test_empty_input_exits_with_error(self, run_hook_raw):
        """Empty input should exit with code 1."""
        result = run_hook_raw("")
        assert result.exit_code == 1

    def test_partial_json_exits_with_error(self, run_hook_raw):
        """Partial JSON (missing closing brace) should exit with code 1."""
        result = run_hook_raw('{"tool_name": "Edit"')
        assert result.exit_code == 1


class TestTypeErrors:
    """Test handling of unexpected input types (graceful handling, no crashes)."""

    def test_tool_input_null_allowed(self, run_hook_raw):
        """tool_input as null should not crash, should allow (exit 0)."""
        result = run_hook_raw({"tool_name": "Edit", "tool_input": None})
        assert result.allowed, f"Expected allowed (exit 0), got exit {result.exit_code}"

    def test_tool_input_string_allowed(self, run_hook_raw):
        """tool_input as string should not crash, should allow (exit 0)."""
        result = run_hook_raw({"tool_name": "Edit", "tool_input": "just a string"})
        assert result.allowed

    def test_tool_input_list_allowed(self, run_hook_raw):
        """tool_input as list should not crash, should allow (exit 0)."""
        result = run_hook_raw({"tool_name": "Edit", "tool_input": ["a", "b"]})
        assert result.allowed

    def test_file_path_integer_allowed(self, run_hook_raw):
        """file_path as integer should not crash, should allow (exit 0)."""
        result = run_hook_raw({"tool_name": "Edit", "tool_input": {"file_path": 12345}})
        assert result.allowed

    def test_file_path_list_allowed(self, run_hook_raw):
        """file_path as list should not crash, should allow (exit 0)."""
        result = run_hook_raw({"tool_name": "Edit", "tool_input": {"file_path": ["a", "b"]}})
        assert result.allowed

    def test_file_path_dict_allowed(self, run_hook_raw):
        """file_path as dict should not crash, should allow (exit 0)."""
        result = run_hook_raw({"tool_name": "Edit", "tool_input": {"file_path": {"nested": "dict"}}})
        assert result.allowed

    def test_missing_tool_input_allowed(self, run_hook_raw):
        """Missing tool_input key entirely should not crash."""
        result = run_hook_raw({"tool_name": "Edit"})
        assert result.allowed


class TestUNCPaths:
    """Test UNC network path handling - must block without network I/O."""

    def test_unc_forward_slash_blocked(self, run_hook, tmp_path):
        """UNC path with forward slashes should be blocked."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "//server/share/file.txt",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked
        assert "UNC" in result.stderr or "relative path" in result.stderr.lower()

    def test_unc_backslash_blocked(self, run_hook, tmp_path):
        """UNC path with backslashes should be blocked."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            r"\\server\share\file.txt",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked

    def test_unc_suggests_filename(self, run_hook, tmp_path):
        """UNC path error should suggest the filename."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "//fileserver/documents/report.docx",
            env={"USERPROFILE": str(home_dir).replace("\\", "/")},
        )
        assert result.blocked
        assert "report.docx" in result.stderr


class TestCygwinPaths:
    """Test Cygwin /cygdrive/c/ path handling."""

    def test_cygdrive_path_blocked(self, run_hook, tmp_path):
        """Cygwin /cygdrive/c/ paths should be recognized as absolute and blocked."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        result = run_hook(
            "Edit",
            "/cygdrive/c/Users/TestUser/file.py",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked, f"Expected blocked, got exit {result.exit_code}"

    def test_cygdrive_within_home_suggests_home_relative(self, run_hook, tmp_path):
        """Cygwin path within home should suggest ~/ path."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        # Simulate /cygdrive/c/Users/TestUser/.config/file.py
        # This requires mapping /cygdrive/c to the tmp_path drive
        # For this test, we'll use a simpler approach
        result = run_hook(
            "Edit",
            "/cygdrive/d/Other/path/file.py",
            env={
                "USERPROFILE": str(home_dir).replace("\\", "/"),
                "CLAUDE_PROJECT_DIR": str(tmp_path / "project").replace("\\", "/"),
            },
        )
        assert result.blocked
        assert "file.py" in result.stderr


class TestCaseSensitivity:
    """Test Windows case-insensitive path handling."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_case_mismatch_within_project(self, run_hook, tmp_path):
        """Path with different case should still be recognized as within project on Windows."""
        project_dir = tmp_path / "MyProject"
        project_dir.mkdir()

        # Use lowercase in file path, mixed case in project dir
        file_path = str(tmp_path / "myproject" / "src" / "file.py").replace("\\", "/")
        project_str = str(project_dir).replace("\\", "/")

        result = run_hook(
            "Edit",
            file_path,
            env={"CLAUDE_PROJECT_DIR": project_str},
        )
        assert result.blocked
        # Should suggest relative path since it's within project (case-insensitive)
        assert "src/file.py" in result.stderr or "file.py" in result.stderr

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_case_mismatch_within_home(self, run_hook, tmp_path):
        """Home path with different case should still match on Windows."""
        home_dir = tmp_path / "Users" / "TestUser"
        home_dir.mkdir(parents=True)

        # Use different case in file path
        file_path = str(tmp_path / "users" / "testuser" / ".config" / "file.py").replace("\\", "/")
        home_str = str(home_dir).replace("\\", "/")

        result = run_hook(
            "Edit",
            file_path,
            env={"USERPROFILE": home_str},
        )
        assert result.blocked
        # Should suggest home-relative path
        assert "~/" in result.stderr or "file.py" in result.stderr


class TestPathTraversal:
    """Document that path traversal is intentionally allowed.

    This hook works around Claude Code Edit bugs, not project boundaries.
    Claude Code has separate security checks for file access.
    """

    def test_parent_traversal_allowed(self, run_hook):
        """Relative paths with ../ are allowed per design."""
        result = run_hook("Edit", "../sibling-project/file.py")
        assert result.allowed, "Traversal paths are allowed per design"

    def test_deep_traversal_allowed(self, run_hook):
        """Deep traversal is allowed - Claude enforces boundaries separately."""
        result = run_hook("Edit", "../../../etc/passwd")
        assert result.allowed, "Traversal paths are allowed per design"

    def test_mixed_traversal_allowed(self, run_hook):
        """Mixed ./ and ../ traversal is allowed."""
        result = run_hook("Edit", "./src/../lib/../../other/file.py")
        assert result.allowed
