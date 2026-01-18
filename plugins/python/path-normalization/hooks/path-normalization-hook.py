# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Claude Code Path Normalization Hook

WORKAROUND FOR CLAUDE CODE BUGS:
Claude Code's Edit tool has bugs with path handling:
1. Absolute paths (C:/..., /c/..., /mnt/c/...) cause false "File has been
   unexpectedly modified" errors, even when the file hasn't changed.
2. Backslash separators (\\) cause similar issues.

Using relative paths with forward slashes works correctly.

SIMPLE RULES:
1. ~\\... → ~/...  (just fix backslashes in home-relative paths)
2. Absolute within cwd → relative to cwd
3. Absolute outside cwd → filename only

This hook blocks problematic path formats and suggests the correct alternative:
- Relative paths with forward slashes: "claude/skills/test/SKILL.md" ✓
- Home-relative paths with forward slashes: "~/.claude/skills/test.md" ✓
- Absolute paths: "C:/Users/.../file.py" ✗ (blocked, suggest relative or filename)
- Backslash separators: "claude\\skills\\test.md" ✗ (blocked, suggest forward slashes)

Note: Path traversal (../) in relative paths is intentionally allowed. This hook
works around Edit tool bugs, not project boundary enforcement. Claude Code has
separate security checks for file access.

Exit codes:
  0 = Allow (path format is safe)
  1 = Error (invalid JSON input)
  2 = Block (stderr fed back to Claude with correct path suggestion)
"""

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

HOOK_NAME = "path-normalization"
BACKSLASH = chr(92)


# ============================================================================
# AUDIT LOGGING
# ============================================================================

def get_log_path() -> Path:
    """Get path to daily audit log file.

    Creates ~/.claude/logs/path-normalization/ directory if it doesn't exist.
    Returns path in format: ~/.claude/logs/path-normalization/YYYY-MM-DD.log
    """
    logs_dir = Path(os.path.expanduser("~")) / ".claude" / "logs" / "path-normalization"
    logs_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    return logs_dir / f"{date_str}.log"


def log_decision(
    tool_name: str,
    file_path: str,
    decision: str,
    reason: str = "",
    suggested_path: str = "",
) -> None:
    """Log path normalization decision to audit log in JSONL format.

    Args:
        tool_name: Name of the tool (Edit or Write).
        file_path: Original file path from tool input.
        decision: "allowed" or "blocked".
        reason: Why the path was blocked (if blocked).
        suggested_path: Corrected path suggestion (if blocked).
    """
    try:
        log_path = get_log_path()
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "file_path": file_path,
            "decision": decision,
            "reason": reason,
            "suggested_path": suggested_path,
            "cwd": os.getcwd(),
            "session_id": os.getenv("CLAUDE_SESSION_ID", ""),
        }
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception:
        pass  # Never crash the hook due to logging failure


def is_hook_disabled() -> bool:
    disabled = os.environ.get("CLAUDE_DISABLE_HOOKS", "")
    return HOOK_NAME in [h.strip() for h in disabled.split(",")]


def normalize_separators(path_str: str) -> str:
    """Convert backslashes to forward slashes for consistent path handling.

    Critical for Unix/WSL: Path("C:\\path\\file").name returns the entire string
    because backslashes aren't recognized as separators. Normalizing first ensures
    Path operations work correctly regardless of input format.
    """
    return path_str.replace(BACKSLASH, '/')


def to_windows_path(path_str: str) -> str:
    """Convert MSYS (/c/), WSL (/mnt/c/), Cygwin (/cygdrive/c/), or backslash paths to Windows (C:/).

    Also normalizes backslashes to forward slashes for consistent handling.
    """
    # First normalize backslashes to forward slashes
    normalized = normalize_separators(path_str)
    # Handle MSYS/WSL/Cygwin style paths
    match = re.match(r'^(?:/mnt|/cygdrive)?/([a-zA-Z])/(.*)', normalized)
    return f"{match.group(1).upper()}:/{match.group(2)}" if match else normalized


def is_unc_path(path: str) -> bool:
    """Check if path is UNC (//server or \\\\server) without triggering network I/O."""
    if len(path) < 3:
        return False
    return path[0] in ('/', BACKSLASH) and path[1] in ('/', BACKSLASH)


def is_absolute(path: str) -> bool:
    """Check if path is absolute (Windows, MSYS, WSL, UNC)."""
    if not path:
        return False
    # UNC paths (//server or \server)
    if len(path) >= 2 and path[0] in ('/', BACKSLASH) and path[1] in ('/', BACKSLASH):
        return True
    # Windows drive letter (C:/ or C:\) - must check explicitly because
    # Path("C:/...").is_absolute() returns False on Unix/WSL
    if len(path) >= 2 and path[0].isalpha() and path[1] == ':':
        return True
    return Path(to_windows_path(path)).is_absolute()


def is_within(child: Path, parent: Path) -> bool:
    """Check if child path is within parent directory (case-insensitive on Windows)."""
    try:
        child_norm = os.path.normcase(str(child.resolve()))
        parent_norm = os.path.normcase(str(parent.resolve()))
        return (child_norm.startswith(parent_norm + os.sep) or
                child_norm == parent_norm)
    except (ValueError, OSError):
        return False


def block(tool_name: str, file_path: str, reason: str, suggested: str) -> None:
    """Exit with block status and error message, logging the decision."""
    log_decision(tool_name, file_path, "blocked", reason, suggested)
    # Format message based on the type of issue
    if "backslash" in reason:
        msg = f"Use forward slashes: '{suggested}'"
    elif suggested.startswith("~/"):
        msg = f"Use home-relative path: '{suggested}'"
    elif "UNC" in reason:
        msg = f"UNC paths not supported. Use relative path: '{suggested}'"
    else:
        msg = f"Use relative path: '{suggested}'"
    print(msg, file=sys.stderr)
    sys.exit(2)


def main() -> None:
    if is_hook_disabled():
        sys.exit(0)

    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(1)

    tool_name = data.get("tool_name", "")
    if tool_name not in ("Edit", "Write"):
        sys.exit(0)

    # Type validation - handle malformed input gracefully
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        sys.exit(0)

    path_str = tool_input.get("file_path", "")
    if not path_str or not isinstance(path_str, str):
        sys.exit(0)

    has_backslash = BACKSLASH in path_str

    # CASE 1: Home-relative paths (~/ or ~\) - ALLOW if using forward slashes
    if path_str.startswith('~/') or path_str.startswith('~' + BACKSLASH):
        if has_backslash:
            suggested = path_str.replace(BACKSLASH, '/')
            block(tool_name, path_str, "backslash in home-relative path", suggested)
        log_decision(tool_name, path_str, "allowed", "home-relative path")
        sys.exit(0)

    # CASE 2: Unix system paths - ALLOW (for WSL compatibility)
    if path_str.startswith(('/dev/', '/proc/', '/tmp/', '/var/')):
        log_decision(tool_name, path_str, "allowed", "unix system path")
        sys.exit(0)

    is_abs = is_absolute(path_str)

    # CASE 3: UNC paths - BLOCK early to avoid network I/O from resolve()
    if is_unc_path(path_str):
        filename = path_str.rsplit('/', 1)[-1].rsplit(BACKSLASH, 1)[-1]
        block(tool_name, path_str, "UNC path not supported", filename)

    # CASE 4: Relative path with backslashes - BLOCK, suggest forward slashes
    if not is_abs and has_backslash:
        suggested = path_str.replace(BACKSLASH, '/')
        block(tool_name, path_str, "backslash in relative path", suggested)

    # CASE 5: Clean relative path (forward slashes, no absolute) - ALLOW
    if not is_abs:
        log_decision(tool_name, path_str, "allowed", "clean relative path")
        sys.exit(0)

    # CASE 6: Absolute path - BLOCK, suggest relative path
    # This is the key fix: absolute paths cause Claude Code Edit bugs
    win_path = to_windows_path(path_str)
    file_path = Path(win_path).resolve()
    home = Path(os.path.expanduser('~')).resolve()
    cwd = Path(to_windows_path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd()))).resolve()

    # Check if within home directory - needed for prioritization
    if is_within(file_path, home):
        home_relative = str(file_path.relative_to(home)).replace(BACKSLASH, '/')

        # Priority 1: Dotfiles in home (like ~/.dotfiles/...) should use home-relative
        # for portability, even if cwd is within the dotfiles directory
        if home_relative.startswith('.'):
            suggested = f"~/{home_relative}"
            block(tool_name, path_str, "absolute path", suggested)

        # Priority 2: If within cwd (and not a dotfile), use cwd-relative (shorter)
        if is_within(file_path, cwd):
            relative = str(file_path.relative_to(cwd)).replace(BACKSLASH, '/')
            block(tool_name, path_str, "absolute path", relative)

        # Priority 3: Within home but not cwd -> use home-relative
        suggested = f"~/{home_relative}"
        block(tool_name, path_str, "absolute path", suggested)

    # Within cwd but not home -> use cwd-relative
    if is_within(file_path, cwd):
        relative = str(file_path.relative_to(cwd)).replace(BACKSLASH, '/')
        block(tool_name, path_str, "absolute path", relative)

    # Outside allowed areas -> suggest filename only (user must determine location)
    # Use string operations to extract filename since Path.name can fail with
    # cross-platform paths (e.g., Windows path on Unix)
    normalized = normalize_separators(path_str)
    filename = normalized.rsplit('/', 1)[-1]
    block(tool_name, path_str, "absolute path outside project/home", filename)


if __name__ == "__main__":
    main()
