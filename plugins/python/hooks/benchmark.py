# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml"]
# ///
"""
Damage Control Pattern Matching Benchmark
==========================================

Benchmarks bash command and path pattern matching performance.
Run with: uv run benchmark.py [--dry-run] [--note "description"]

Output:
  - Prints statistics (count, avg, min, max, p50, p95, p99) in milliseconds
  - Appends results to BENCHMARKS.md unless --dry-run is specified
"""

import argparse
import json
import re
import os
import sys
import time
import fnmatch
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple
from statistics import median, quantiles

import yaml


# ============================================================================
# PATTERN MATCHING LOGIC (from bash-tool-damage-control.py)
# ============================================================================

def is_glob_pattern(pattern: str) -> bool:
    """Check if pattern contains glob wildcards."""
    return '*' in pattern or '?' in pattern or '[' in pattern


def glob_to_regex(glob_pattern: str) -> str:
    """Convert a glob pattern to a regex pattern for matching in commands."""
    result = ""
    for char in glob_pattern:
        if char == '*':
            result += r'[^\s/]*'
        elif char == '?':
            result += r'[^\s/]'
        elif char in r'\.^$+{}[]|()':
            result += '\\' + char
        else:
            result += char
    return result


# ============================================================================
# COMPILATION AND CACHING (Phase 1 optimizations)
# ============================================================================

def compile_regex_patterns(patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pre-compile regex patterns from bashToolPatterns config."""
    compiled = []
    for idx, item in enumerate(patterns):
        pattern = item.get("pattern", "")
        if not pattern:
            continue

        try:
            compiled_regex = re.compile(pattern, re.IGNORECASE)
            compiled_item = item.copy()
            compiled_item["compiled"] = compiled_regex
            compiled.append(compiled_item)
        except re.error:
            continue

    return compiled


def preprocess_path_list(paths: List[str]) -> List[Dict[str, Any]]:
    """Pre-process path list for fast matching."""
    processed = []
    for path in paths:
        if not path:
            continue

        path_obj = {
            "original": path,
            "is_glob": is_glob_pattern(path),
        }

        if path_obj["is_glob"]:
            try:
                glob_regex_str = glob_to_regex(path)
                path_obj["glob_regex"] = re.compile(glob_regex_str, re.IGNORECASE)
            except re.error:
                continue
        else:
            try:
                expanded = os.path.expanduser(path)
                path_obj["expanded"] = expanded
                path_obj["escaped_expanded"] = re.escape(expanded)
                path_obj["escaped_original"] = re.escape(path)
            except Exception:
                continue

        processed.append(path_obj)

    return processed


def compile_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Compile configuration for fast pattern matching."""
    compiled = config.copy()

    patterns = config.get("bashToolPatterns", [])
    compiled["bashToolPatterns_compiled"] = compile_regex_patterns(patterns)

    zero_access = config.get("zeroAccessPaths", [])
    compiled["zeroAccessPaths_compiled"] = preprocess_path_list(zero_access)

    read_only = config.get("readOnlyPaths", [])
    compiled["readOnlyPaths_compiled"] = preprocess_path_list(read_only)

    no_delete = config.get("noDeletePaths", [])
    compiled["noDeletePaths_compiled"] = preprocess_path_list(no_delete)

    return compiled


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

READ_ONLY_BLOCKED = (
    WRITE_PATTERNS +
    APPEND_PATTERNS +
    EDIT_PATTERNS +
    MOVE_COPY_PATTERNS +
    DELETE_PATTERNS +
    PERMISSION_PATTERNS +
    TRUNCATE_PATTERNS
)

NO_DELETE_BLOCKED = DELETE_PATTERNS


def check_path_patterns(command: str, path_obj: Dict[str, Any], patterns: List[Tuple[str, str]], path_type: str) -> Tuple[bool, str]:
    """Check command against a list of patterns for a specific path (optimized version)."""
    path_str = path_obj["original"]

    if path_obj["is_glob"]:
        glob_regex_compiled = path_obj.get("glob_regex")
        if not glob_regex_compiled:
            return False, ""

        glob_regex_str = glob_regex_compiled.pattern

        for pattern_template, operation in patterns:
            try:
                cmd_prefix = pattern_template.replace("{path}", "")
                if cmd_prefix and re.search(cmd_prefix + glob_regex_str, command, re.IGNORECASE):
                    return True, f"Blocked: {operation} operation on {path_type} {path_str}"
            except re.error:
                continue
    else:
        escaped_expanded = path_obj.get("escaped_expanded", "")
        escaped_original = path_obj.get("escaped_original", "")

        if not escaped_expanded or not escaped_original:
            return False, ""

        for pattern_template, operation in patterns:
            pattern_expanded = pattern_template.replace("{path}", escaped_expanded)
            pattern_original = pattern_template.replace("{path}", escaped_original)
            try:
                if re.search(pattern_expanded, command) or re.search(pattern_original, command):
                    return True, f"Blocked: {operation} operation on {path_type} {path_str}"
            except re.error:
                continue

    return False, ""


def check_command(command: str, config: Dict[str, Any]) -> Tuple[bool, bool, str]:
    """Check if command should be blocked or requires confirmation (optimized version).

    Returns: (blocked, ask, reason)
    """
    # Check if config is compiled (has _compiled keys) or raw
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

    # 1. Check against bash tool patterns
    for item in compiled_patterns:
        compiled_regex = item.get("compiled")
        reason = item.get("reason", "Blocked by pattern")
        should_ask = item.get("ask", False)

        if not compiled_regex:
            continue

        try:
            if compiled_regex.search(command):
                if should_ask:
                    return False, True, reason
                else:
                    return True, False, f"Blocked: {reason}"
        except re.error:
            continue

    # 2. Check for ANY access to zero-access paths
    for path_obj in compiled_zero_access:
        if path_obj["is_glob"]:
            glob_regex_compiled = path_obj.get("glob_regex")
            if glob_regex_compiled:
                try:
                    if glob_regex_compiled.search(command):
                        return True, False, f"Blocked: zero-access pattern {path_obj['original']}"
                except re.error:
                    continue
        else:
            escaped_expanded = path_obj.get("escaped_expanded", "")
            escaped_original = path_obj.get("escaped_original", "")

            if escaped_expanded or escaped_original:
                if (escaped_expanded and re.search(escaped_expanded, command)) or \
                   (escaped_original and re.search(escaped_original, command)):
                    return True, False, f"Blocked: zero-access path {path_obj['original']}"

    # 3. Check for modifications to read-only paths
    for path_obj in compiled_read_only:
        blocked, reason = check_path_patterns(command, path_obj, READ_ONLY_BLOCKED, "read-only path")
        if blocked:
            return True, False, reason

    # 4. Check for deletions on no-delete paths
    for path_obj in compiled_no_delete:
        blocked, reason = check_path_patterns(command, path_obj, NO_DELETE_BLOCKED, "no-delete path")
        if blocked:
            return True, False, reason

    return False, False, ""


# ============================================================================
# TEST CORPUS
# ============================================================================

BASH_COMMANDS = [
    # Safe commands
    "git status",
    "git diff",
    "git log",
    "npm install",
    "npm run build",
    "npm test",
    "python -m pytest",
    "python script.py",
    "docker ps",
    "docker logs container",
    "kubectl get pods",
    "kubectl describe pod mypod",
    "ls -la",
    "cat README.md",
    "grep -r pattern .",
    "find . -name '*.py'",
    "echo 'hello world'",
    "mkdir -p src/components",
    "touch newfile.txt",
    "cp file.txt backup.txt",
    "mv oldname.txt newname.txt",
    "tar -czf archive.tar.gz files/",
    "unzip archive.zip",
    "curl https://api.example.com",
    "wget https://example.com/file.zip",
    "ssh user@host",
    "scp file.txt user@host:/path",
    "rsync -av src/ dest/",
    "make test",
    "make build",
    "cargo build",
    "cargo test",
    "go build",
    "go test ./...",
    "npm run lint",
    "npm run format",
    "pytest tests/",
    "pytest --cov",
    "black .",
    "mypy src/",
    "ruff check .",
    "eslint src/",
    "prettier --write .",
    "git add .",
    "git commit -m 'feat: add feature'",
    "git push",
    "git pull",
    "git checkout -b feature-branch",
    "git merge main",
    "git rebase main",

    # Dangerous commands (should be blocked/asked)
    "rm -rf /",
    "rm -rf ~",
    "rm -rf $HOME",
    "rm -rf /mnt/c/Users",
    "rm -f important.txt",
    "git rm file.txt",
    "chmod 777 script.sh",
    "git reset --hard",
    "git push --force",
    "terraform destroy",
    "docker system prune -a",
    "kubectl delete namespace prod",
    "aws s3 rm s3://bucket --recursive",
    "DROP DATABASE production;",
    "DELETE FROM users;",
    "TRUNCATE TABLE orders;",
    "redis-cli FLUSHALL",
    "heroku apps:destroy",
    "rm -rf node_modules",
    "git stash drop",
    "git branch -D feature",
]

FILE_PATHS = [
    # Safe paths
    "src/index.ts",
    "src/components/Button.tsx",
    "tests/unit/test_api.py",
    "README.md",
    "package.json",
    "tsconfig.json",
    "docker-compose.yml",
    "Makefile",
    ".gitignore",
    "docs/api.md",
    "scripts/build.sh",
    "config/settings.yaml",
    "lib/utils.js",
    "app/main.py",

    # Would-be-blocked paths (zero-access)
    ".env",
    ".env.local",
    ".env.production",
    "~/.ssh/id_rsa",
    "~/.ssh/config",
    "~/.aws/credentials",
    "~/.kube/config",
    "production.env",
    "credentials.json",
    "serviceAccount.json",
    "private-key.pem",
    "cert.key",
    "terraform.tfstate",
    "firebase-adminsdk.json",

    # Read-only paths
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "uv.lock",
    "~/.bashrc",
    "~/.zshrc",
    "~/.bash_history",
    "/etc/hosts",
    "/etc/passwd",
    "dist/bundle.min.js",
    "build/app.bundle.js",
    "node_modules/package/index.js",

    # No-delete paths
    "LICENSE",
    "LICENSE.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "Dockerfile",
    ".github/workflows/ci.yml",
]


# ============================================================================
# BENCHMARKING
# ============================================================================

def load_patterns() -> Dict[str, Any]:
    """Load patterns.yaml from the same directory."""
    script_dir = Path(__file__).parent
    config_path = script_dir / "patterns.yaml"

    if not config_path.exists():
        print(f"Error: patterns.yaml not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


def run_benchmark(config: Dict[str, Any], iterations: int = 1000, use_compiled: bool = False) -> Dict[str, Any]:
    """Run benchmark on bash commands and path patterns.

    Args:
        config: Configuration dictionary (raw or compiled)
        iterations: Number of iterations to run
        use_compiled: If True, compile the config once before benchmarking

    Returns:
        Dictionary with bash and path statistics
    """
    # Compile config once if requested (simulates module-level caching)
    if use_compiled:
        config = compile_config(config)

    bash_times = []
    path_times = []

    # Benchmark bash command patterns
    for _ in range(iterations):
        for command in BASH_COMMANDS:
            start = time.perf_counter()
            check_command(command, config)
            end = time.perf_counter()
            bash_times.append((end - start) * 1000)  # Convert to milliseconds

    # Benchmark path patterns (simulate checking paths in commands)
    test_commands = [
        f"cat {path}" for path in FILE_PATHS
    ] + [
        f"rm {path}" for path in FILE_PATHS
    ] + [
        f"vim {path}" for path in FILE_PATHS
    ]

    path_iterations = max(1, iterations // len(test_commands)) * len(test_commands)
    for _ in range(path_iterations // len(test_commands)):
        for command in test_commands:
            start = time.perf_counter()
            check_command(command, config)
            end = time.perf_counter()
            path_times.append((end - start) * 1000)

    # Calculate statistics
    def calc_stats(times: List[float]) -> Dict[str, float]:
        times.sort()
        return {
            "count": len(times),
            "avg": sum(times) / len(times),
            "min": min(times),
            "max": max(times),
            "p50": median(times),
            "p95": quantiles(times, n=20)[18],  # 95th percentile
            "p99": quantiles(times, n=100)[98],  # 99th percentile
        }

    return {
        "bash": calc_stats(bash_times),
        "path": calc_stats(path_times),
    }


def format_stats(stats: Dict[str, float]) -> str:
    """Format statistics for display."""
    return (
        f"  Count: {stats['count']}\n"
        f"  Avg:   {stats['avg']:.4f} ms\n"
        f"  Min:   {stats['min']:.4f} ms\n"
        f"  Max:   {stats['max']:.4f} ms\n"
        f"  P50:   {stats['p50']:.4f} ms\n"
        f"  P95:   {stats['p95']:.4f} ms\n"
        f"  P99:   {stats['p99']:.4f} ms"
    )


def append_to_benchmarks(config: Dict[str, Any], stats: Dict[str, Any], note: str = "") -> None:
    """Append benchmark results to BENCHMARKS.md."""
    script_dir = Path(__file__).parent
    benchmarks_path = script_dir / "BENCHMARKS.md"

    # Ensure file exists with header
    if not benchmarks_path.exists():
        with open(benchmarks_path, "w") as f:
            f.write("# Damage Control Benchmark History\n\n")
            f.write("Track pattern matching performance over time. Run `uv run benchmark.py` to add entries.\n\n")
            f.write("| Date | Bash Patterns | Path Patterns | Iterations | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Notes |\n")
            f.write("|------|---------------|---------------|------------|----------|----------|----------|----------|-------|\n")

    # Append new row
    date = datetime.now().strftime("%Y-%m-%d %H:%M")
    bash_count = len(config.get("bashToolPatterns", []))
    path_count = (
        len(config.get("zeroAccessPaths", [])) +
        len(config.get("readOnlyPaths", [])) +
        len(config.get("noDeletePaths", []))
    )

    # Combined average across bash and path checks
    total_checks = stats["bash"]["count"] + stats["path"]["count"]
    combined_avg = (
        stats["bash"]["avg"] * stats["bash"]["count"] +
        stats["path"]["avg"] * stats["path"]["count"]
    ) / total_checks
    combined_p50 = (stats["bash"]["p50"] + stats["path"]["p50"]) / 2
    combined_p95 = (stats["bash"]["p95"] + stats["path"]["p95"]) / 2
    combined_p99 = (stats["bash"]["p99"] + stats["path"]["p99"]) / 2

    row = (
        f"| {date} | "
        f"{bash_count} | "
        f"{path_count} | "
        f"{total_checks:,} | "
        f"{combined_avg:.4f} | "
        f"{combined_p50:.4f} | "
        f"{combined_p95:.4f} | "
        f"{combined_p99:.4f} | "
        f"{note} |\n"
    )

    with open(benchmarks_path, "a") as f:
        f.write(row)

    print(f"\nResults appended to {benchmarks_path}")


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark damage-control pattern matching")
    parser.add_argument("--dry-run", action="store_true", help="Print results without appending to BENCHMARKS.md")
    parser.add_argument("--note", type=str, default="", help="Optional note to include in benchmark table")
    parser.add_argument("--iterations", type=int, default=1000, help="Number of iterations (default: 1000)")
    parser.add_argument("--compiled", action="store_true", help="Use compiled patterns (Phase 1 optimizations)")
    args = parser.parse_args()

    print("Loading patterns...")
    config = load_patterns()

    bash_count = len(config.get("bashToolPatterns", []))
    path_count = (
        len(config.get("zeroAccessPaths", [])) +
        len(config.get("readOnlyPaths", [])) +
        len(config.get("noDeletePaths", []))
    )

    mode = "compiled" if args.compiled else "raw"
    print(f"Patterns loaded: {bash_count} bash patterns, {path_count} path patterns")
    print(f"Mode: {mode}")
    print(f"Test corpus: {len(BASH_COMMANDS)} bash commands, {len(FILE_PATHS)} file paths")
    print(f"Running {args.iterations} iterations...\n")

    stats = run_benchmark(config, args.iterations, use_compiled=args.compiled)

    print("Bash Command Pattern Matching:")
    print(format_stats(stats["bash"]))
    print()
    print("Path Pattern Matching:")
    print(format_stats(stats["path"]))

    if not args.dry_run:
        append_to_benchmarks(config, stats, args.note)
    else:
        print("\n(dry-run mode: results not appended to BENCHMARKS.md)")


if __name__ == "__main__":
    main()
