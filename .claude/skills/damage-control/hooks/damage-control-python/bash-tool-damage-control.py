# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml"]
# ///
"""
Claude Code Security Firewall - Python/UV Implementation
=========================================================

Blocks dangerous commands before execution via PreToolUse hook.
Loads patterns from patterns.yaml for easy customization.

Exit codes:
  0 = Allow command (or JSON output with permissionDecision)
  2 = Block command (stderr fed back to Claude)

JSON output for ask patterns:
  {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "..."}}
"""

import json
import sys
import re
import os
import fnmatch
from pathlib import Path
from typing import Tuple, List, Dict, Any

import yaml


def is_glob_pattern(pattern: str) -> bool:
    """Check if pattern contains glob wildcards."""
    return '*' in pattern or '?' in pattern or '[' in pattern


def expand_path(path: str) -> str:
    """Expand environment variables and user home in path (cross-platform)."""
    # Handle Windows %VAR% style
    expanded = os.path.expandvars(path)

    # Handle ~ for user home
    expanded = os.path.expanduser(expanded)

    return expanded


def normalize_for_matching(path: str) -> str:
    """Normalize path for comparison (handle case-insensitivity on Windows)."""
    normalized = os.path.normpath(expand_path(path))
    if sys.platform == "win32":
        normalized = normalized.lower()
    return normalized


def glob_to_regex(glob_pattern: str) -> str:
    """Convert a glob pattern to a regex pattern for matching in commands."""
    # Escape special regex chars except * and ?
    result = ""
    for char in glob_pattern:
        if char == '*':
            result += r'[^\s/]*'  # Match any chars except whitespace and path sep
        elif char == '?':
            result += r'[^\s/]'   # Match single char except whitespace and path sep
        elif char in r'\.^$+{}[]|()':
            result += '\\' + char
        else:
            result += char
    return result

# ============================================================================
# OPERATION PATTERNS - Edit these to customize what operations are blocked
# ============================================================================
# {path} will be replaced with the escaped path at runtime

# Unix operations blocked for READ-ONLY paths (all modifications)
UNIX_WRITE_PATTERNS = [
    (r'>\s*{path}', "write"),
    (r'\btee\s+(?!.*-a).*{path}', "write"),
]

UNIX_APPEND_PATTERNS = [
    (r'>>\s*{path}', "append"),
    (r'\btee\s+-a\s+.*{path}', "append"),
    (r'\btee\s+.*-a.*{path}', "append"),
]

UNIX_EDIT_PATTERNS = [
    (r'\bsed\s+-i.*{path}', "edit"),
    (r'\bperl\s+-[^\s]*i.*{path}', "edit"),
    (r'\bawk\s+-i\s+inplace.*{path}', "edit"),
]

UNIX_MOVE_COPY_PATTERNS = [
    (r'\bmv\s+.*\s+{path}', "move"),
    (r'\bcp\s+.*\s+{path}', "copy"),
]

UNIX_DELETE_PATTERNS = [
    (r'\brm\s+.*{path}', "delete"),
    (r'\bunlink\s+.*{path}', "delete"),
    (r'\brmdir\s+.*{path}', "delete"),
    (r'\bshred\s+.*{path}', "delete"),
]

UNIX_PERMISSION_PATTERNS = [
    (r'\bchmod\s+.*{path}', "chmod"),
    (r'\bchown\s+.*{path}', "chown"),
    (r'\bchgrp\s+.*{path}', "chgrp"),
]

UNIX_TRUNCATE_PATTERNS = [
    (r'\btruncate\s+.*{path}', "truncate"),
    (r':\s*>\s*{path}', "truncate"),
]

# Windows operations
WINDOWS_WRITE_PATTERNS = [
    (r'>\s*{path}', "write"),
    (r'\bOut-File\s+.*{path}', "write"),
    (r'\bSet-Content\s+.*{path}', "write"),
]

WINDOWS_COPY_PATTERNS = [
    (r'\bcopy\s+.*\s+{path}', "copy"),
    (r'\bxcopy\s+.*\s+{path}', "copy"),
    (r'\bCopy-Item\s+.*{path}', "copy"),
    (r'\brobocopy\s+.*\s+{path}', "copy"),
]

WINDOWS_MOVE_PATTERNS = [
    (r'\bmove\s+.*\s+{path}', "move"),
    (r'\bMove-Item\s+.*{path}', "move"),
]

WINDOWS_DELETE_PATTERNS = [
    (r'\bdel\s+.*{path}', "delete"),
    (r'\berase\s+.*{path}', "delete"),
    (r'\brd\s+.*{path}', "delete"),
    (r'\brmdir\s+.*{path}', "delete"),
    (r'\bRemove-Item\s+.*{path}', "delete"),
]

WINDOWS_PERMISSION_PATTERNS = [
    (r'\bicacls\s+.*{path}', "icacls"),
    (r'\bcacls\s+.*{path}', "cacls"),
    (r'\btakeown\s+.*{path}', "takeown"),
    (r'\battrib\s+.*{path}', "attrib"),
    (r'\bSet-Acl\s+.*{path}', "Set-Acl"),
]

# Combined patterns for read-only paths (block ALL modifications)
def get_read_only_blocked() -> List[Tuple[str, str]]:
    """Get the appropriate read-only blocked patterns for the current platform."""
    if sys.platform == "win32":
        return (
            WINDOWS_WRITE_PATTERNS +
            WINDOWS_COPY_PATTERNS +
            WINDOWS_MOVE_PATTERNS +
            WINDOWS_DELETE_PATTERNS +
            WINDOWS_PERMISSION_PATTERNS
        )
    else:
        return (
            UNIX_WRITE_PATTERNS +
            UNIX_APPEND_PATTERNS +
            UNIX_EDIT_PATTERNS +
            UNIX_MOVE_COPY_PATTERNS +
            UNIX_DELETE_PATTERNS +
            UNIX_PERMISSION_PATTERNS +
            UNIX_TRUNCATE_PATTERNS
        )


def get_no_delete_blocked() -> List[Tuple[str, str]]:
    """Get the appropriate no-delete patterns for the current platform."""
    if sys.platform == "win32":
        return WINDOWS_DELETE_PATTERNS
    else:
        return UNIX_DELETE_PATTERNS

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

def get_config_dir() -> Path:
    """Get the directory containing pattern config files."""
    # 1. Check project hooks directory (installed location)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_config_dir = Path(project_dir) / ".claude" / "hooks" / "damage-control"
        if (project_config_dir / "patterns-base.yaml").exists():
            return project_config_dir

    # 2. Check script's own directory (installed location)
    script_dir = Path(__file__).parent
    if (script_dir / "patterns-base.yaml").exists():
        return script_dir

    # 3. Check skill root directory (development location)
    skill_root = script_dir.parent.parent
    if (skill_root / "patterns-base.yaml").exists():
        return skill_root

    # 4. Fallback to old single-file location for backwards compatibility
    if project_dir:
        project_config = Path(project_dir) / ".claude" / "hooks" / "damage-control" / "patterns.yaml"
        if project_config.exists():
            return project_config.parent

    return skill_root  # Default


def get_platform_name() -> str:
    """Get the platform-specific config file suffix."""
    if sys.platform == "win32":
        return "windows"
    elif sys.platform == "darwin":
        return "unix"  # macOS uses Unix patterns
    else:
        return "unix"  # Linux and other Unix-like systems


def merge_configs(base: Dict[str, Any], platform: Dict[str, Any]) -> Dict[str, Any]:
    """Merge base config with platform-specific config."""
    merged = {}

    # Merge list fields by concatenation
    list_fields = ["bashToolPatterns", "zeroAccessPaths", "readOnlyPaths", "noDeletePaths"]
    for field in list_fields:
        base_list = base.get(field, [])
        platform_list = platform.get(field, [])
        merged[field] = base_list + platform_list

    return merged


def load_config() -> Dict[str, Any]:
    """Load patterns from YAML config files (base + platform-specific)."""
    config_dir = get_config_dir()
    platform = get_platform_name()

    base_config: Dict[str, Any] = {}
    platform_config: Dict[str, Any] = {}

    # Load base config
    base_path = config_dir / "patterns-base.yaml"
    if base_path.exists():
        with open(base_path, "r") as f:
            base_config = yaml.safe_load(f) or {}

    # Load platform-specific config
    platform_path = config_dir / f"patterns-{platform}.yaml"
    if platform_path.exists():
        with open(platform_path, "r") as f:
            platform_config = yaml.safe_load(f) or {}

    # If we have split configs, merge them
    if base_config or platform_config:
        return merge_configs(base_config, platform_config)

    # Fallback: try loading old single-file patterns.yaml
    legacy_path = config_dir / "patterns.yaml"
    if legacy_path.exists():
        with open(legacy_path, "r") as f:
            return yaml.safe_load(f) or {}

    print(f"Warning: No config found in {config_dir}", file=sys.stderr)
    return {"bashToolPatterns": [], "zeroAccessPaths": [], "readOnlyPaths": [], "noDeletePaths": []}


# ============================================================================
# PATH CHECKING
# ============================================================================

def check_path_patterns(command: str, path: str, patterns: List[Tuple[str, str]], path_type: str) -> Tuple[bool, str]:
    """Check command against a list of patterns for a specific path.

    Supports both:
    - Literal paths: ~/.bashrc, /etc/hosts (prefix matching)
    - Glob patterns: *.lock, *.md, src/* (glob matching)
    """
    if is_glob_pattern(path):
        # Glob pattern - convert to regex for command matching
        glob_regex = glob_to_regex(path)
        for pattern_template, operation in patterns:
            # For glob patterns, we check if the operation + glob appears in command
            # e.g., "rm *.lock" should match DELETE_PATTERNS with *.lock
            try:
                # Build a regex that matches: operation ... glob_pattern
                # Extract the command prefix from pattern_template (e.g., '\brm\s+.*' from '\brm\s+.*{path}')
                cmd_prefix = pattern_template.replace("{path}", "")
                if cmd_prefix and re.search(cmd_prefix + glob_regex, command, re.IGNORECASE):
                    return True, f"Blocked: {operation} operation on {path_type} {path}"
            except re.error:
                continue
    else:
        # Original literal path matching (prefix-based)
        expanded = expand_path(path)
        escaped_expanded = re.escape(expanded)
        escaped_original = re.escape(path)

        for pattern_template, operation in patterns:
            # Check both expanded path (/Users/x/.ssh/) and original tilde form (~/.ssh/)
            pattern_expanded = pattern_template.replace("{path}", escaped_expanded)
            pattern_original = pattern_template.replace("{path}", escaped_original)
            try:
                if re.search(pattern_expanded, command) or re.search(pattern_original, command):
                    return True, f"Blocked: {operation} operation on {path_type} {path}"
            except re.error:
                continue

    return False, ""


def check_command(command: str, config: Dict[str, Any]) -> Tuple[bool, bool, str]:
    """Check if command should be blocked or requires confirmation.

    Returns: (blocked, ask, reason)
      - blocked=True, ask=False: Block the command
      - blocked=False, ask=True: Show confirmation dialog
      - blocked=False, ask=False: Allow the command
    """
    patterns = config.get("bashToolPatterns", [])
    zero_access_paths = config.get("zeroAccessPaths", [])
    read_only_paths = config.get("readOnlyPaths", [])
    no_delete_paths = config.get("noDeletePaths", [])

    # 1. Check against patterns from YAML (may block or ask)
    for item in patterns:
        pattern = item.get("pattern", "")
        reason = item.get("reason", "Blocked by pattern")
        should_ask = item.get("ask", False)

        try:
            if re.search(pattern, command, re.IGNORECASE):
                if should_ask:
                    return False, True, reason  # Ask for confirmation
                else:
                    return True, False, f"Blocked: {reason}"  # Block
        except re.error:
            continue

    # 2. Check for ANY access to zero-access paths (including reads)
    for zero_path in zero_access_paths:
        if is_glob_pattern(zero_path):
            # Convert glob to regex for command matching
            glob_regex = glob_to_regex(zero_path)
            try:
                if re.search(glob_regex, command, re.IGNORECASE):
                    return True, False, f"Blocked: zero-access pattern {zero_path} (no operations allowed)"
            except re.error:
                continue
        else:
            # Original literal path matching
            expanded = expand_path(zero_path)
            escaped_expanded = re.escape(expanded)
            escaped_original = re.escape(zero_path)

            # Check both expanded path and original form
            # On Windows, also check case-insensitively
            flags = re.IGNORECASE if sys.platform == "win32" else 0
            if re.search(escaped_expanded, command, flags) or re.search(escaped_original, command, flags):
                return True, False, f"Blocked: zero-access path {zero_path} (no operations allowed)"

    # 3. Check for modifications to read-only paths (reads allowed)
    read_only_blocked = get_read_only_blocked()
    for readonly in read_only_paths:
        blocked, reason = check_path_patterns(command, readonly, read_only_blocked, "read-only path")
        if blocked:
            return True, False, reason

    # 4. Check for deletions on no-delete paths (read/write/edit allowed)
    no_delete_blocked = get_no_delete_blocked()
    for no_delete in no_delete_paths:
        blocked, reason = check_path_patterns(command, no_delete, no_delete_blocked, "no-delete path")
        if blocked:
            return True, False, reason

    return False, False, ""


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    config = load_config()

    # Read hook input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only check Bash commands
    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    # Check the command
    is_blocked, should_ask, reason = check_command(command, config)

    if is_blocked:
        print(f"SECURITY: {reason}", file=sys.stderr)
        print(f"Command: {command[:100]}{'...' if len(command) > 100 else ''}", file=sys.stderr)
        sys.exit(2)
    elif should_ask:
        # Output JSON to trigger confirmation dialog
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason
            }
        }
        print(json.dumps(output))
        sys.exit(0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
