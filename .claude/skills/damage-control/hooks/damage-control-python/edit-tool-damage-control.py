# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml"]
# ///
"""
Claude Code Edit Tool Damage Control
=====================================

Blocks edits to protected files via PreToolUse hook on Edit tool.
Loads zeroAccessPaths and readOnlyPaths from patterns.yaml.

Exit codes:
  0 = Allow edit
  2 = Block edit (stderr fed back to Claude)
"""

import json
import sys
import os
import fnmatch
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

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


def normalize_path(path: str) -> str:
    """Normalize path for comparison (handle case-insensitivity on Windows)."""
    normalized = os.path.normpath(expand_path(path))
    if sys.platform == "win32":
        normalized = normalized.lower()
    return normalized


def match_path(file_path: str, pattern: str) -> bool:
    """Match file path against pattern, supporting both prefix and glob matching."""
    expanded_pattern = expand_path(pattern)
    normalized = os.path.normpath(file_path)
    expanded_normalized = expand_path(normalized)

    # On Windows, do case-insensitive matching
    if sys.platform == "win32":
        expanded_pattern = expanded_pattern.lower()
        expanded_normalized = expanded_normalized.lower()

    if is_glob_pattern(pattern):
        # Glob pattern matching (case-insensitive for security)
        basename = os.path.basename(expanded_normalized)
        pattern_lower = pattern.lower() if sys.platform == "win32" else pattern
        expanded_pattern_check = expanded_pattern.lower() if sys.platform != "win32" else expanded_pattern

        # Match against basename for patterns like *.pem, .env*
        if fnmatch.fnmatch(basename.lower(), expanded_pattern_check.lower()):
            return True
        if fnmatch.fnmatch(basename.lower(), pattern_lower.lower()):
            return True
        # Also try full path match for patterns like /path/*.pem
        if fnmatch.fnmatch(expanded_normalized.lower(), expanded_pattern_check.lower()):
            return True
        return False
    else:
        # Prefix matching (original behavior for directories)
        # Normalize path separators for comparison
        expanded_pattern_norm = expanded_pattern.replace('/', os.sep).replace('\\', os.sep)
        expanded_normalized_norm = expanded_normalized.replace('/', os.sep).replace('\\', os.sep)

        if expanded_normalized_norm.startswith(expanded_pattern_norm) or \
           expanded_normalized_norm == expanded_pattern_norm.rstrip('/').rstrip('\\'):
            return True
        return False


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

    return {"zeroAccessPaths": [], "readOnlyPaths": []}


def check_path(file_path: str, config: Dict[str, Any]) -> Tuple[bool, str]:
    """Check if file_path is blocked. Returns (blocked, reason)."""
    # Check zero-access paths first (no access at all)
    for zero_path in config.get("zeroAccessPaths", []):
        if match_path(file_path, zero_path):
            return True, f"zero-access path {zero_path} (no operations allowed)"

    # Check read-only paths (edits not allowed)
    for readonly in config.get("readOnlyPaths", []):
        if match_path(file_path, readonly):
            return True, f"read-only path {readonly}"

    return False, ""


def main() -> None:
    config = load_config()

    # Read hook input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only check Edit tool
    if tool_name != "Edit":
        sys.exit(0)

    file_path = tool_input.get("file_path", "")
    if not file_path:
        sys.exit(0)

    # Check if file is blocked
    blocked, reason = check_path(file_path, config)
    if blocked:
        print(f"SECURITY: Blocked edit to {reason}: {file_path}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
