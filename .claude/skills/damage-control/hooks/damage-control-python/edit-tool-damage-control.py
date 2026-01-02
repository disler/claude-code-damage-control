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
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import yaml


def get_config_path() -> Path:
    """Get path to patterns.yaml."""
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_config = Path(project_dir) / ".claude" / "hooks" / "damage-control" / "patterns.yaml"
        if project_config.exists():
            return project_config

    script_dir = Path(__file__).parent
    return script_dir / "patterns.yaml"


def load_config() -> Dict[str, Any]:
    """Load config from YAML."""
    config_path = get_config_path()

    if not config_path.exists():
        return {"zeroAccessPaths": [], "readOnlyPaths": []}

    with open(config_path, "r") as f:
        config = yaml.safe_load(f) or {}

    return config


def check_path(file_path: str, config: Dict[str, Any]) -> Tuple[bool, str]:
    """Check if file_path is blocked. Returns (blocked, reason)."""
    normalized = os.path.expanduser(file_path)

    # Check zero-access paths first (no access at all)
    for zero_path in config.get("zeroAccessPaths", []):
        expanded = os.path.expanduser(zero_path)
        if normalized.startswith(expanded) or normalized == expanded.rstrip('/'):
            return True, f"zero-access path {zero_path} (no operations allowed)"

    # Check read-only paths (edits not allowed)
    for readonly in config.get("readOnlyPaths", []):
        expanded = os.path.expanduser(readonly)
        if normalized.startswith(expanded) or normalized == expanded.rstrip('/'):
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
