# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml"]
# ///
"""
Claude Code Write Tool Damage Control
======================================

Blocks writes to protected files via PreToolUse hook on Write tool.
Loads zeroAccessPaths and readOnlyPaths from patterns.yaml.

Exit codes:
  0 = Allow write
  2 = Block write (stderr fed back to Claude)
"""

import json
import subprocess
import sys
import os
import fnmatch
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

import yaml


# ============================================================================
# AUDIT LOGGING
# ============================================================================

def get_log_path() -> Path:
    """Get path to daily audit log file.

    Creates ~/.claude/logs/damage-control/ directory if it doesn't exist.
    Returns path in format: ~/.claude/logs/damage-control/YYYY-MM-DD.log

    All entries for a given day are appended to the same file (JSONL format).
    """
    logs_dir = Path(os.path.expanduser("~")) / ".claude" / "logs" / "damage-control"
    logs_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"{date_str}.log"

    return logs_dir / filename


def log_decision(
    tool_name: str,
    file_path: str,
    decision: str,
    reason: str = "",
    context: Optional[str] = None,
) -> None:
    """Log security decision to audit log in JSONL format.

    Args:
        tool_name: Name of the tool (e.g., "Edit", "Write").
        file_path: Path to the file being accessed.
        decision: Security decision ("blocked" or "allowed").
        reason: Human-readable reason for blocking (if applicable).
        context: Context name if applicable (e.g., "documentation").
    """
    try:
        log_path = get_log_path()

        # Truncate file_path to 200 chars for display
        file_path_truncated = file_path[:200]
        if len(file_path) > 200:
            file_path_truncated += "..."

        # Get context information
        user = os.getenv("USER", "unknown")
        cwd = os.getcwd()
        session_id = os.getenv("CLAUDE_SESSION_ID", "")

        # Build JSONL record
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "file_path": file_path_truncated,
            "decision": decision,
            "reason": reason,
            "context": context,
            "user": user,
            "cwd": cwd,
            "session_id": session_id,
        }

        # Write as JSONL (one JSON object per line)
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    except Exception as e:
        # Never crash the hook due to logging failure
        print(f"Warning: Failed to write audit log: {e}", file=sys.stderr)


def spawn_log_rotation() -> None:
    """Fire-and-forget log rotation. Non-blocking, cross-platform."""
    rotate_script = Path(__file__).parent / "log_rotate.py"
    if not rotate_script.exists():
        return
    try:
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True

        subprocess.Popen([sys.executable, str(rotate_script)], **kwargs)
    except OSError:
        pass  # Don't crash hook if rotation fails to spawn


def is_glob_pattern(pattern: str) -> bool:
    """Check if pattern contains glob wildcards."""
    return '*' in pattern or '?' in pattern or '[' in pattern


def match_path(file_path: str, pattern: str) -> bool:
    """Match file path against pattern, supporting both prefix and glob matching."""
    expanded_pattern = os.path.expanduser(pattern)
    normalized = os.path.normpath(file_path)
    expanded_normalized = os.path.expanduser(normalized)

    if is_glob_pattern(pattern):
        # Glob pattern matching (case-insensitive for security)
        basename = os.path.basename(expanded_normalized)
        basename_lower = basename.lower()
        pattern_lower = pattern.lower()
        expanded_pattern_lower = expanded_pattern.lower()

        # Match against basename for patterns like *.pem, .env*
        if fnmatch.fnmatch(basename_lower, expanded_pattern_lower):
            return True
        if fnmatch.fnmatch(basename_lower, pattern_lower):
            return True
        # Also try full path match for patterns like /path/*.pem
        if fnmatch.fnmatch(expanded_normalized.lower(), expanded_pattern_lower):
            return True
        return False
    else:
        # Exact match or directory prefix matching
        # .env should NOT match .env.example (different files)
        # ~/.ssh/ SHOULD match ~/.ssh/id_rsa (directory contains file)
        if expanded_normalized == expanded_pattern or expanded_normalized == expanded_pattern.rstrip('/'):
            return True
        # Only prefix match if pattern is a directory (ends with /)
        if expanded_pattern.endswith('/') and expanded_normalized.startswith(expanded_pattern):
            return True
        # Also match if path is inside the directory (pattern without trailing /)
        if expanded_normalized.startswith(expanded_pattern + '/') or expanded_normalized.startswith(expanded_pattern + os.sep):
            return True
        return False


def get_config_path() -> Path:
    """Get path to patterns.yaml, checking multiple locations."""
    # 1. Check project hooks directory (installed location)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_config = Path(project_dir) / ".claude" / "hooks" / "damage-control" / "patterns.yaml"
        if project_config.exists():
            return project_config

    # 2. Check script's own directory (installed location)
    script_dir = Path(__file__).parent
    local_config = script_dir / "patterns.yaml"
    if local_config.exists():
        return local_config

    # 3. Check skill root directory (development location)
    skill_root = script_dir.parent.parent / "patterns.yaml"
    if skill_root.exists():
        return skill_root

    return local_config  # Default, even if it doesn't exist


def load_config() -> Dict[str, Any]:
    """Load config from YAML."""
    config_path = get_config_path()

    if not config_path.exists():
        return {"zeroAccessPaths": [], "readOnlyPaths": []}

    with open(config_path, "r") as f:
        config = yaml.safe_load(f) or {}

    return config


def detect_context(tool_name: str, tool_input: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Detect if we're in a special context that allows relaxed checks.

    For Edit/Write tools, this checks file extensions against documentation context.

    Args:
        tool_name: Name of the tool being invoked ("Edit", "Write").
        tool_input: Tool input parameters (file_path).
        config: Loaded configuration from patterns.yaml.

    Returns:
        Context name (e.g., 'documentation') or None if no context detected.
    """
    contexts_config = config.get("contexts", {})

    # Check for documentation context (file extension based)
    if tool_name in ("Edit", "Write"):
        doc_ctx = contexts_config.get("documentation", {})
        if doc_ctx.get("enabled", False):
            file_path = tool_input.get("file_path", "")
            extensions = doc_ctx.get("detection", {}).get("file_extensions", [])
            for ext in extensions:
                if file_path.endswith(ext):
                    return "documentation"

    return None


def check_path(file_path: str, config: Dict[str, Any], context: Optional[str] = None) -> Tuple[bool, str]:
    """Check if file_path is blocked. Returns (blocked, reason).

    Args:
        file_path: Path to file being written.
        config: Loaded configuration from patterns.yaml.
        context: Optional context name that may relax certain checks.
    """
    # Get context configuration to determine which checks to relax
    context_config = {}
    if context:
        context_config = config.get("contexts", {}).get(context, {})
    relaxed_checks = set(context_config.get("relaxed_checks", []))

    # Check zero-access paths first (no access at all)
    # Skip only if explicitly relaxed (should NEVER be relaxed for security)
    if "zeroAccessPaths" not in relaxed_checks:
        for zero_path in config.get("zeroAccessPaths", []):
            if match_path(file_path, zero_path):
                return True, f"zero-access path {zero_path} (no operations allowed)"

    # Check read-only paths (writes not allowed)
    # Skip only if explicitly relaxed
    if "readOnlyPaths" not in relaxed_checks:
        for readonly in config.get("readOnlyPaths", []):
            if match_path(file_path, readonly):
                return True, f"read-only path {readonly}"

    return False, ""


def main() -> None:
    config = load_config()

    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only check Write tool
    if tool_name != "Write":
        sys.exit(0)

    file_path = tool_input.get("file_path", "")
    if not file_path:
        sys.exit(0)

    # Detect context (e.g., documentation)
    context = detect_context(tool_name, tool_input, config)

    # Check if file is blocked with context awareness
    blocked, reason = check_path(file_path, config, context=context)

    # Log decision
    if blocked:
        log_decision("Write", file_path, "blocked", reason, context)
    else:
        log_decision("Write", file_path, "allowed", "", context)

    # Spawn log rotation (fire-and-forget)
    spawn_log_rotation()

    if blocked:
        print(f"SECURITY: Blocked write to {reason}: {file_path}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
