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
import subprocess
import sys
import re
import os
import fnmatch
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
from datetime import datetime

import yaml


# ============================================================================
# CONFIGURATION COMPILATION AND CACHING
# ============================================================================

# Module-level cache for compiled configuration
_compiled_config_cache: Optional[Dict[str, Any]] = None


def compile_regex_patterns(patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pre-compile regex patterns from bashToolPatterns config.

    Args:
        patterns: List of pattern dictionaries from YAML config.

    Returns:
        List of pattern dictionaries with added 'compiled' field containing
        compiled regex objects. Invalid patterns are skipped with warning.
    """
    compiled = []
    for idx, item in enumerate(patterns):
        pattern = item.get("pattern", "")
        if not pattern:
            continue

        try:
            # Pre-compile with IGNORECASE flag (used throughout check_command)
            compiled_regex = re.compile(pattern, re.IGNORECASE)
            # Create new dict with compiled pattern added
            compiled_item = item.copy()
            compiled_item["compiled"] = compiled_regex
            compiled.append(compiled_item)
        except re.error as e:
            # Skip invalid patterns with warning (don't crash)
            print(f"Warning: Invalid regex pattern at index {idx}: {pattern} - {e}", file=sys.stderr)
            continue

    return compiled


def preprocess_path_list(paths: List[str]) -> List[Dict[str, Any]]:
    """Pre-process path list for fast matching.

    For glob patterns: pre-compile glob-to-regex conversion
    For literal paths: pre-compute expanded path and escaped forms

    Args:
        paths: List of path strings (may contain globs like *.pem or literals like ~/.ssh/)

    Returns:
        List of path dictionaries with pre-computed data:
        - is_glob: bool
        - original: str (original path string)
        - glob_regex: compiled regex (only for globs)
        - expanded: str (only for literals)
        - escaped_expanded: str (only for literals)
        - escaped_original: str (only for literals)
    """
    processed = []
    for path in paths:
        if not path:
            continue

        path_obj = {
            "original": path,
            "is_glob": is_glob_pattern(path),
        }

        if path_obj["is_glob"]:
            # Pre-compile glob-to-regex for command matching
            try:
                glob_regex_str = glob_to_regex(path)
                path_obj["glob_regex"] = re.compile(glob_regex_str, re.IGNORECASE)
            except re.error as e:
                print(f"Warning: Invalid glob pattern: {path} - {e}", file=sys.stderr)
                continue
        else:
            # Pre-compute expanded path and escaped forms for literal paths
            try:
                expanded = os.path.expanduser(path)
                path_obj["expanded"] = expanded
                path_obj["escaped_expanded"] = re.escape(expanded)
                path_obj["escaped_original"] = re.escape(path)
            except Exception as e:
                print(f"Warning: Failed to process path: {path} - {e}", file=sys.stderr)
                continue

        processed.append(path_obj)

    return processed


def compile_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Compile configuration for fast pattern matching.

    Pre-processes all patterns and paths at load time:
    - Compiles all regex patterns with IGNORECASE
    - Pre-processes all path lists (glob-to-regex, expanduser, re.escape)

    Args:
        config: Raw configuration from load_config()

    Returns:
        Compiled configuration with pre-computed data added
    """
    compiled = config.copy()

    # Compile bashToolPatterns regex patterns
    patterns = config.get("bashToolPatterns", [])
    compiled["bashToolPatterns_compiled"] = compile_regex_patterns(patterns)

    # Pre-process all path lists
    zero_access = config.get("zeroAccessPaths", [])
    compiled["zeroAccessPaths_compiled"] = preprocess_path_list(zero_access)

    read_only = config.get("readOnlyPaths", [])
    compiled["readOnlyPaths_compiled"] = preprocess_path_list(read_only)

    no_delete = config.get("noDeletePaths", [])
    compiled["noDeletePaths_compiled"] = preprocess_path_list(no_delete)

    return compiled


def get_compiled_config() -> Dict[str, Any]:
    """Get compiled configuration, using module-level cache.

    Loads and compiles configuration once, then returns cached version
    on subsequent calls. Cache persists for the lifetime of the process.

    Returns:
        Compiled configuration dictionary
    """
    global _compiled_config_cache

    if _compiled_config_cache is None:
        # Load and compile configuration once
        raw_config = load_config()
        _compiled_config_cache = compile_config(raw_config)

    return _compiled_config_cache


# ============================================================================
# AUDIT LOGGING
# ============================================================================

def get_log_path() -> Path:
    """Get path to daily audit log file.

    Creates ~/.claude/logs/damage-control/ directory if it doesn't exist.
    Returns path in format: ~/.claude/logs/damage-control/YYYY-MM-DD.log

    All entries for a given day are appended to the same file (JSONL format).

    Returns:
        Path object for the daily log file.
    """
    logs_dir = Path(os.path.expanduser("~")) / ".claude" / "logs" / "damage-control"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Use date-only for daily log files
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"{date_str}.log"

    return logs_dir / filename


def redact_secrets(command: str) -> str:
    """Redact sensitive information from command string.

    Patterns redacted (case-insensitive):
    - API keys: apikey=, api_key=, token= (20+ chars), bearer
    - Passwords: password=, passwd=, pwd=
    - AWS keys: AKIA[0-9A-Z]{16}
    - Secrets: secret=, credential=
    - Env vars: GITHUB_TOKEN=, NPM_TOKEN=, DOCKER_PASSWORD=

    Args:
        command: Command string that may contain secrets.

    Returns:
        Command string with secrets replaced by ***REDACTED***.
    """
    redacted = command

    # List of patterns to redact, with optional character constraints
    patterns = [
        # API keys and tokens
        (r'apikey\s*=\s*[\w\-\.]+', re.IGNORECASE),
        (r'api_key\s*=\s*[\w\-\.]+', re.IGNORECASE),
        (r'token\s*=\s*[\w\-\.]{20,}', re.IGNORECASE),
        (r'bearer\s+[\w\-\.]+', re.IGNORECASE),
        # Passwords (match any non-space after = or flag-attached like -pPassword)
        (r'password\s*=\s*\S+', re.IGNORECASE),
        (r'passwd\s*=\s*\S+', re.IGNORECASE),
        (r'pwd\s*=\s*\S+', re.IGNORECASE),
        (r'-p\S+', 0),  # MySQL -pPassword or similar
        # AWS access keys
        (r'AKIA[0-9A-Z]{16}', 0),
        # Secrets and credentials
        (r'secret\s*=\s*\S+', re.IGNORECASE),
        (r'credential\s*=\s*\S+', re.IGNORECASE),
        # Environment variables with sensitive values
        (r'GITHUB_TOKEN\s*=\s*\S+', re.IGNORECASE),
        (r'NPM_TOKEN\s*=\s*\S+', re.IGNORECASE),
        (r'DOCKER_PASSWORD\s*=\s*\S+', re.IGNORECASE),
    ]

    for pattern, flags in patterns:
        try:
            redacted = re.sub(pattern, "***REDACTED***", redacted, flags=flags)
        except re.error:
            # Skip invalid patterns
            pass

    return redacted


def log_decision(
    tool_name: str,
    command: str,
    decision: str,
    reason: str,
    pattern_matched: str = "",
    unwrapped: bool = False,
    semantic_match: bool = False,
    context: Optional[str] = None,
) -> None:
    """Log security decision to audit log in JSONL format.

    One JSON object per line, containing timestamp, tool, command (truncated),
    redacted command, decision (blocked/ask/allowed), reason, flags, and context.

    Args:
        tool_name: Name of the tool (e.g., "Bash").
        command: Full command that was checked.
        decision: Security decision ("blocked", "ask", or "allowed").
        reason: Human-readable reason for the decision.
        pattern_matched: Pattern that matched (if any), e.g., "semantic_git" or "regex_pattern_name".
        unwrapped: True if command was unwrapped from a shell wrapper.
        semantic_match: True if decision based on semantic analysis (e.g., git dangerous operations).
        context: Context name if applicable (e.g., "documentation", "commit_message").
    """
    try:
        log_path = get_log_path()

        # Truncate command to 200 chars for display
        command_truncated = command[:200]
        if len(command) > 200:
            command_truncated += "..."

        # Create redacted version for logging
        command_redacted = redact_secrets(command)
        command_redacted_truncated = command_redacted[:200]
        if len(command_redacted) > 200:
            command_redacted_truncated += "..."

        # Get context information
        user = os.getenv("USER", "unknown")
        cwd = os.getcwd()
        session_id = os.getenv("CLAUDE_SESSION_ID", "")

        # Build JSONL record
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "command": command_truncated,
            "command_redacted": command_redacted_truncated,
            "decision": decision,
            "reason": reason,
            "pattern_matched": pattern_matched,
            "user": user,
            "cwd": cwd,
            "session_id": session_id,
            "unwrapped": unwrapped,
            "semantic_match": semantic_match,
            "context": context,
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


# ============================================================================
# SHELL WRAPPER UNWRAPPING
# ============================================================================

def extract_system_call(python_code: str) -> Optional[str]:
    """Extract shell commands from Python code strings.

    Detects patterns like:
    - os.system('cmd')
    - subprocess.run(['cmd', 'args'])
    - subprocess.call(['cmd'])
    - subprocess.Popen(['cmd'])

    Args:
        python_code: Python code string to analyze

    Returns:
        Extracted command string or None if no system call found
    """
    if not python_code:
        return None

    # Pattern for os.system('command') or os.system("command")
    system_patterns = [
        r'os\.system\s*\(\s*["\']([^"\']+)["\']\s*\)',
        r'subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*["\']([^"\']+)["\']\s*\)',
    ]

    for pattern in system_patterns:
        match = re.search(pattern, python_code)
        if match:
            return match.group(1)

    # Pattern for subprocess with list arguments: ['cmd', 'arg1', 'arg2']
    list_pattern = r'subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*\[([^\]]+)\]'
    match = re.search(list_pattern, python_code)
    if match:
        # Extract list contents and join as command
        list_contents = match.group(1)
        # Remove quotes and commas, split by whitespace
        parts = re.findall(r'["\']([^"\']+)["\']', list_contents)
        if parts:
            return ' '.join(parts)

    return None


def unwrap_command(command: str, depth: int = 0) -> Tuple[str, bool]:
    """Recursively unwrap shell wrapper commands.

    Detects and unwraps commands hidden in shell wrappers:
    - bash/sh/zsh/ksh/dash -c "command"
    - python/python2/python3 -c "code"
    - env VAR=val command
    - Nested wrappers up to depth 5

    Args:
        command: Command string to unwrap
        depth: Current recursion depth (max 5)

    Returns:
        Tuple of (unwrapped_command, was_unwrapped)
        - unwrapped_command: The innermost command found
        - was_unwrapped: True if any unwrapping occurred

    Examples:
        >>> unwrap_command('bash -c "rm -rf /"')
        ('rm -rf /', True)
        >>> unwrap_command('python -c "import os; os.system(\\"rm -rf /\\")"')
        ('rm -rf /', True)
        >>> unwrap_command('bash -c "sh -c \'rm -rf /\'"')
        ('rm -rf /', True)
    """
    if depth >= 5:
        # Max recursion depth reached, return what we have
        return command, depth > 0

    if not command or not command.strip():
        return command, False

    original_command = command
    command = command.strip()
    was_unwrapped = False

    # Pattern for shell -c wrappers: bash -c "command" or sh -c 'command'
    shell_wrappers = ['bash', 'sh', 'zsh', 'ksh', 'dash']
    for shell in shell_wrappers:
        # Match: shell -c "command" or shell -c 'command'
        # Handle both single and double quotes
        pattern = rf'\b{shell}\s+-c\s+(["\'])(.+?)\1'
        match = re.search(pattern, command)
        if match:
            inner_command = match.group(2)
            # Recursively unwrap in case of nested wrappers
            return unwrap_command(inner_command, depth + 1)

    # Pattern for Python -c wrappers: python -c "code"
    python_wrappers = ['python', 'python2', 'python3']
    for python_cmd in python_wrappers:
        pattern = rf'\b{python_cmd}\s+-c\s+(["\'])(.+?)\1'
        match = re.search(pattern, command)
        if match:
            python_code = match.group(2)
            # Extract system calls from Python code
            extracted = extract_system_call(python_code)
            if extracted:
                # Recursively unwrap in case of nested wrappers
                return unwrap_command(extracted, depth + 1)
            # If no system call found, return the Python code itself
            # (it might still contain dangerous operations)
            return unwrap_command(python_code, depth + 1)

    # Pattern for env wrappers: env VAR=val command
    env_pattern = r'\benv\s+(?:[A-Z_][A-Z0-9_]*=[^\s]+\s+)*(.+)'
    match = re.search(env_pattern, command)
    if match:
        inner_command = match.group(1)
        # Recursively unwrap in case of nested wrappers
        return unwrap_command(inner_command, depth + 1)

    # No wrapper found
    return command, depth > 0


# ============================================================================
# GIT SEMANTIC ANALYSIS
# ============================================================================

def analyze_git_command(command: str) -> Tuple[bool, str]:
    """Analyze git commands for dangerous operations based on semantic understanding.

    Distinguishes between safe and dangerous git operations:
    - Safe: git checkout -b feature (creating branch)
    - Dangerous: git checkout -- . (discard changes)
    - Safe: git push --force-with-lease (safe force push)
    - Dangerous: git push --force (unsafe force push)

    Args:
        command: Command string to analyze

    Returns:
        Tuple of (is_dangerous, reason)
        - is_dangerous: True if command is dangerous
        - reason: Human-readable explanation of why it's dangerous

    Examples:
        >>> analyze_git_command('git checkout -b feature')
        (False, '')
        >>> analyze_git_command('git checkout -- .')
        (True, 'git checkout with -- discards uncommitted changes')
        >>> analyze_git_command('git push --force-with-lease')
        (False, '')
        >>> analyze_git_command('git push --force')
        (True, 'git push --force can overwrite remote history')
    """
    if not command or not command.strip():
        return False, ""

    command = command.strip()

    # Check if it's a git command
    if not command.startswith('git '):
        return False, ""

    # Parse command into parts
    parts = command.split()
    if len(parts) < 2:
        return False, ""  # Just "git" with no subcommand

    subcommand = parts[1]
    args = parts[2:] if len(parts) > 2 else []

    # Join args for easier pattern matching
    args_str = ' '.join(args)

    # ========================================================================
    # GIT CHECKOUT
    # ========================================================================
    if subcommand == 'checkout':
        # Safe: -b or --branch (creating new branch)
        if '-b' in args or '--branch' in args:
            return False, ""

        # Dangerous: -- with path arguments (discarding changes)
        if '--' in args:
            # Find position of --
            try:
                dash_idx = args.index('--')
                # If there are arguments after --, it's discarding changes
                if dash_idx < len(args) - 1:
                    return True, "git checkout with -- discards uncommitted changes"
            except ValueError:
                pass

        # Dangerous: --force or -f
        if '--force' in args or '-f' in args:
            return True, "git checkout --force discards uncommitted changes"

        # Check for combined short flags containing -f
        for arg in args:
            if arg.startswith('-') and not arg.startswith('--') and len(arg) > 1:
                # It's a short flag combination like -fb
                if 'f' in arg[1:]:  # Skip the first '-'
                    return True, "git checkout -f discards uncommitted changes"

    # ========================================================================
    # GIT PUSH
    # ========================================================================
    elif subcommand == 'push':
        # Safe: --force-with-lease (check this FIRST before checking --force)
        if '--force-with-lease' in args_str:
            return False, ""

        # Dangerous: --force (without lease)
        if '--force' in args:
            return True, "git push --force can overwrite remote history without safety checks"

        # Dangerous: -f short flag
        if '-f' in args:
            return True, "git push -f can overwrite remote history without safety checks"

        # Check for combined short flags containing -f
        for arg in args:
            if arg.startswith('-') and not arg.startswith('--') and len(arg) > 1:
                # It's a short flag combination like -fu
                if 'f' in arg[1:]:  # Skip the first '-'
                    return True, "git push -f can overwrite remote history without safety checks"

    # ========================================================================
    # GIT RESET
    # ========================================================================
    elif subcommand == 'reset':
        # Safe: --soft or --mixed (default)
        if '--soft' in args or '--mixed' in args:
            return False, ""

        # Dangerous: --hard
        if '--hard' in args:
            return True, "git reset --hard permanently discards uncommitted changes"

    # ========================================================================
    # GIT CLEAN
    # ========================================================================
    elif subcommand == 'clean':
        # Dangerous: -f or -d flags
        if '-f' in args or '-d' in args:
            return True, "git clean removes untracked files permanently"

        # Check for combined short flags containing -f or -d
        for arg in args:
            if arg.startswith('-') and not arg.startswith('--') and len(arg) > 1:
                # It's a short flag combination like -fd
                if 'f' in arg[1:] or 'd' in arg[1:]:
                    return True, "git clean removes untracked files permanently"

    # Not a dangerous git command or not a known subcommand
    return False, ""


def is_glob_pattern(pattern: str) -> bool:
    """Check if pattern contains glob wildcards."""
    return '*' in pattern or '?' in pattern or '[' in pattern


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

# Operations blocked for READ-ONLY paths (all modifications)
WRITE_PATTERNS = [
    (r'>\s*{path}', "write"),
    (r'\btee\s+(?!.*-a).*{path}', "write"),
]

APPEND_PATTERNS = [
    (r'>>\s*{path}', "append"),
    (r'\btee\s+-a\s+.*{path}', "append"),
    (r'\btee\s+.*-a.*{path}', "append"),
]

EDIT_PATTERNS = [
    (r'\bsed\s+-i.*{path}', "edit"),
    (r'\bperl\s+-[^\s]*i.*{path}', "edit"),
    (r'\bawk\s+-i\s+inplace.*{path}', "edit"),
]

MOVE_COPY_PATTERNS = [
    (r'\bmv\s+.*\s+{path}', "move"),
    (r'\bcp\s+.*\s+{path}', "copy"),
]

DELETE_PATTERNS = [
    (r'\brm\s+.*{path}', "delete"),
    (r'\bunlink\s+.*{path}', "delete"),
    (r'\brmdir\s+.*{path}', "delete"),
    (r'\bshred\s+.*{path}', "delete"),
]

PERMISSION_PATTERNS = [
    (r'\bchmod\s+.*{path}', "chmod"),
    (r'\bchown\s+.*{path}', "chown"),
    (r'\bchgrp\s+.*{path}', "chgrp"),
]

TRUNCATE_PATTERNS = [
    (r'\btruncate\s+.*{path}', "truncate"),
    (r':\s*>\s*{path}', "truncate"),
]

# Combined patterns for read-only paths (block ALL modifications)
READ_ONLY_BLOCKED = (
    WRITE_PATTERNS +
    APPEND_PATTERNS +
    EDIT_PATTERNS +
    MOVE_COPY_PATTERNS +
    DELETE_PATTERNS +
    PERMISSION_PATTERNS +
    TRUNCATE_PATTERNS
)

# Patterns for no-delete paths (block ONLY delete operations)
NO_DELETE_BLOCKED = DELETE_PATTERNS

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

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
    """Load patterns from YAML config file."""
    config_path = get_config_path()

    if not config_path.exists():
        print(f"Warning: Config not found at {config_path}", file=sys.stderr)
        return {"bashToolPatterns": [], "zeroAccessPaths": [], "readOnlyPaths": [], "noDeletePaths": []}

    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


# ============================================================================
# CONTEXT DETECTION
# ============================================================================

def detect_context(tool_name: str, tool_input: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Detect if we're in a special context that allows relaxed checks.

    Contexts are defined in patterns.yaml and can relax certain security checks
    when operating in specific scenarios (e.g., writing documentation with
    command examples, or committing messages that mention dangerous commands).

    Args:
        tool_name: Name of the tool being invoked ("Bash", "Edit", "Write").
        tool_input: Tool input parameters (command, file_path, etc.).
        config: Loaded configuration from patterns.yaml.

    Returns:
        Context name (e.g., 'documentation', 'commit_message') or None if no context detected.

    Examples:
        >>> detect_context("Edit", {"file_path": "README.md"}, config)
        'documentation'
        >>> detect_context("Bash", {"command": "git commit -m 'test'"}, config)
        'commit_message'
        >>> detect_context("Write", {"file_path": "script.py"}, config)
        None
    """
    contexts_config = config.get("contexts", {})

    # Check Edit/Write tools for documentation context (file extension based)
    if tool_name in ("Edit", "Write"):
        doc_ctx = contexts_config.get("documentation", {})
        if doc_ctx.get("enabled", False):
            file_path = tool_input.get("file_path", "")
            extensions = doc_ctx.get("detection", {}).get("file_extensions", [])
            for ext in extensions:
                if file_path.endswith(ext):
                    return "documentation"

    # Check Bash tool for commit message context (command pattern based)
    elif tool_name == "Bash":
        commit_ctx = contexts_config.get("commit_message", {})
        if commit_ctx.get("enabled", False):
            command = tool_input.get("command", "")
            patterns = commit_ctx.get("detection", {}).get("command_patterns", [])
            for pattern in patterns:
                try:
                    if re.search(pattern, command, re.IGNORECASE):
                        return "commit_message"
                except re.error:
                    # Skip invalid regex patterns
                    continue

    return None


# ============================================================================
# PATH CHECKING
# ============================================================================

def check_path_patterns(command: str, path_obj: Dict[str, Any], patterns: List[Tuple[str, str]], path_type: str) -> Tuple[bool, str]:
    """Check command against a list of patterns for a specific path.

    Uses pre-processed path objects from preprocess_path_list().

    Args:
        command: Command string to check
        path_obj: Pre-processed path object with compiled regex/escaped forms
        patterns: List of (pattern_template, operation) tuples
        path_type: Human-readable path type for error messages

    Returns:
        Tuple of (is_blocked, reason)
    """
    path_str = path_obj["original"]

    if path_obj["is_glob"]:
        # Use pre-compiled glob regex
        glob_regex_compiled = path_obj.get("glob_regex")
        if not glob_regex_compiled:
            return False, ""

        glob_regex_str = glob_regex_compiled.pattern

        for pattern_template, operation in patterns:
            # For glob patterns, we check if the operation + glob appears in command
            # e.g., "rm *.lock" should match DELETE_PATTERNS with *.lock
            try:
                # Build a regex that matches: operation ... glob_pattern
                # Extract the command prefix from pattern_template (e.g., '\brm\s+.*' from '\brm\s+.*{path}')
                cmd_prefix = pattern_template.replace("{path}", "")
                if cmd_prefix and re.search(cmd_prefix + glob_regex_str, command, re.IGNORECASE):
                    return True, f"Blocked: {operation} operation on {path_type} {path_str}"
            except re.error:
                continue
    else:
        # Use pre-computed escaped forms for literal paths
        escaped_expanded = path_obj.get("escaped_expanded", "")
        escaped_original = path_obj.get("escaped_original", "")

        if not escaped_expanded or not escaped_original:
            return False, ""

        for pattern_template, operation in patterns:
            # Check both expanded path (/Users/x/.ssh/) and original tilde form (~/.ssh/)
            pattern_expanded = pattern_template.replace("{path}", escaped_expanded)
            pattern_original = pattern_template.replace("{path}", escaped_original)
            try:
                if re.search(pattern_expanded, command) or re.search(pattern_original, command):
                    return True, f"Blocked: {operation} operation on {path_type} {path_str}"
            except re.error:
                continue

    return False, ""


def check_command(command: str, config: Dict[str, Any], context: Optional[str] = None) -> Tuple[bool, bool, str, str, bool, bool]:
    """Check if command should be blocked or requires confirmation.

    Args:
        command: Command string to check.
        config: Configuration (either raw from load_config() or compiled from get_compiled_config()).
        context: Optional context name (e.g., 'documentation', 'commit_message') that may relax certain checks.

    Returns: (blocked, ask, reason, pattern_matched, was_unwrapped, semantic_match)
      - blocked=True, ask=False: Block the command
      - blocked=False, ask=True: Show confirmation dialog
      - blocked=False, ask=False: Allow the command
      - pattern_matched: Pattern identifier that triggered decision (e.g., "semantic_git", "yaml_pattern_0")
      - was_unwrapped: True if command was unwrapped from shell wrapper
      - semantic_match: True if decision based on semantic analysis (e.g., git dangerous operations)
    """
    # Get context configuration to determine which checks to relax
    context_config = {}
    if context:
        context_config = config.get("contexts", {}).get(context, {})
    relaxed_checks = set(context_config.get("relaxed_checks", []))

    # Unwrap shell wrappers first to detect hidden commands
    unwrapped_cmd, was_unwrapped = unwrap_command(command)

    # Semantic git analysis - check AFTER unwrapping, BEFORE regex patterns
    # Only skip if explicitly relaxed in context (unlikely for most contexts)
    if "semantic_git" not in relaxed_checks:
        is_dangerous_git, git_reason = analyze_git_command(unwrapped_cmd)
        if is_dangerous_git:
            return True, False, f"Blocked: {git_reason}", "semantic_git", was_unwrapped, True

    # Check if config is compiled (has _compiled keys) or raw
    # For backward compatibility with tests that pass raw configs
    has_compiled = "bashToolPatterns_compiled" in config

    if has_compiled:
        # Use pre-compiled patterns from config
        compiled_patterns = config.get("bashToolPatterns_compiled", [])
        compiled_zero_access = config.get("zeroAccessPaths_compiled", [])
        compiled_read_only = config.get("readOnlyPaths_compiled", [])
        compiled_no_delete = config.get("noDeletePaths_compiled", [])
    else:
        # Compile on the fly for backward compatibility (slower path)
        raw_patterns = config.get("bashToolPatterns", [])
        compiled_patterns = compile_regex_patterns(raw_patterns)

        raw_zero_access = config.get("zeroAccessPaths", [])
        compiled_zero_access = preprocess_path_list(raw_zero_access)

        raw_read_only = config.get("readOnlyPaths", [])
        compiled_read_only = preprocess_path_list(raw_read_only)

        raw_no_delete = config.get("noDeletePaths", [])
        compiled_no_delete = preprocess_path_list(raw_no_delete)

    # 1. Check against patterns from YAML (may block or ask)
    # Skip if bashToolPatterns is relaxed in this context (e.g., documentation)
    if "bashToolPatterns" not in relaxed_checks:
        for idx, item in enumerate(compiled_patterns):
            compiled_regex = item.get("compiled")
            reason = item.get("reason", "Blocked by pattern")
            should_ask = item.get("ask", False)

            if not compiled_regex:
                continue

            try:
                # Use pre-compiled regex (already has IGNORECASE flag)
                if compiled_regex.search(unwrapped_cmd):
                    pattern_id = f"yaml_pattern_{idx}"
                    if should_ask:
                        return False, True, reason, pattern_id, was_unwrapped, False  # Ask for confirmation
                    else:
                        return True, False, f"Blocked: {reason}", pattern_id, was_unwrapped, False  # Block
            except re.error:
                continue

    # 2. Check for ANY access to zero-access paths (including reads)
    # Skip only if explicitly relaxed in context (should NEVER be relaxed for security)
    if "zeroAccessPaths" not in relaxed_checks:
        for path_obj in compiled_zero_access:
            if path_obj["is_glob"]:
                # Use pre-compiled glob regex
                glob_regex_compiled = path_obj.get("glob_regex")
                if glob_regex_compiled:
                    try:
                        if glob_regex_compiled.search(unwrapped_cmd):
                            return True, False, f"Blocked: zero-access pattern {path_obj['original']} (no operations allowed)", "zero_access_glob", was_unwrapped, False
                    except re.error:
                        continue
            else:
                # Use pre-computed escaped forms for literal paths
                escaped_expanded = path_obj.get("escaped_expanded", "")
                escaped_original = path_obj.get("escaped_original", "")

                if escaped_expanded or escaped_original:
                    # Check both expanded path (/Users/x/.ssh/) and original tilde form (~/.ssh/)
                    if (escaped_expanded and re.search(escaped_expanded, unwrapped_cmd)) or \
                       (escaped_original and re.search(escaped_original, unwrapped_cmd)):
                        return True, False, f"Blocked: zero-access path {path_obj['original']} (no operations allowed)", "zero_access_literal", was_unwrapped, False

    # 3. Check for modifications to read-only paths (reads allowed)
    # Skip only if explicitly relaxed in context
    if "readOnlyPaths" not in relaxed_checks:
        for path_obj in compiled_read_only:
            blocked, reason = check_path_patterns(unwrapped_cmd, path_obj, READ_ONLY_BLOCKED, "read-only path")
            if blocked:
                return True, False, reason, "readonly_path", was_unwrapped, False

    # 4. Check for deletions on no-delete paths (read/write/edit allowed)
    # Skip only if explicitly relaxed in context
    if "noDeletePaths" not in relaxed_checks:
        for path_obj in compiled_no_delete:
            blocked, reason = check_path_patterns(unwrapped_cmd, path_obj, NO_DELETE_BLOCKED, "no-delete path")
            if blocked:
                return True, False, reason, "nodelete_path", was_unwrapped, False

    return False, False, "", "", was_unwrapped, False


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    # Get compiled configuration (uses module-level cache)
    config = get_compiled_config()

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

    # Detect context (e.g., documentation, commit_message)
    context = detect_context(tool_name, tool_input, config)

    # Check the command with context awareness (uses compiled config)
    is_blocked, should_ask, reason, pattern_matched, was_unwrapped, semantic_match = check_command(command, config, context=context)

    # Log the decision with all metadata
    decision = "blocked" if is_blocked else ("ask" if should_ask else "allowed")
    log_decision(
        tool_name=tool_name,
        command=command,
        decision=decision,
        reason=reason,
        pattern_matched=pattern_matched,
        unwrapped=was_unwrapped,
        semantic_match=semantic_match,
        context=context,
    )

    # Spawn log rotation (fire-and-forget)
    spawn_log_rotation()

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
