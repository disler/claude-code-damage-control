# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
Path Normalization Hook Test Runner
====================================

Tests path normalization hook via CLI, interactive, or batch test suite mode.

Usage:
  # Interactive mode - test paths interactively
  uv run test-path-normalization.py -i
  uv run test-path-normalization.py --interactive

  # CLI mode - test a single path
  uv run test-path-normalization.py <tool_name> <path> [--expect-blocked|--expect-allowed]

  # Batch test suite mode
  uv run test-path-normalization.py --test-suite all
  uv run test-path-normalization.py --test-suite absolute
  uv run test-path-normalization.py --test-suite backslash
  uv run test-path-normalization.py --test-suite relative

Examples:
  # Interactive mode
  uv run test-path-normalization.py -i

  # Test absolute path is blocked
  uv run test-path-normalization.py Edit "E:/Projects/test.py" --expect-blocked

  # Test relative path is allowed
  uv run test-path-normalization.py Edit "src/file.py" --expect-allowed

  # Run batch test suite
  uv run test-path-normalization.py --test-suite all

Exit codes:
  0 = All tests passed (expectation matched)
  1 = Test(s) failed (expectation not matched)
"""

import subprocess
import json
import sys
import argparse
from pathlib import Path
from typing import Tuple, List


# ============================================================================
# TEST FIXTURES
# ============================================================================

# Paths that should be BLOCKED (absolute paths or backslashes)
BLOCKED_PATHS = [
    # Windows absolute paths
    {"path": "C:/Users/test/file.py", "reason": "Windows C: drive path"},
    {"path": "E:/Projects/myproject/src/file.py", "reason": "Windows E: drive path"},
    {"path": "D:\\Code\\project\\main.py", "reason": "Windows backslash path"},
    {"path": "c:/windows/system32/test.dll", "reason": "Lowercase drive letter"},
    # MSYS/Git Bash paths
    {"path": "/c/Users/test/file.py", "reason": "MSYS /c/ path"},
    {"path": "/e/Projects/work/app.js", "reason": "MSYS /e/ path"},
    {"path": "/d/code/project/index.ts", "reason": "MSYS /d/ path"},
    # WSL paths
    {"path": "/mnt/c/Users/test/file.py", "reason": "WSL /mnt/c/ path"},
    {"path": "/mnt/d/Projects/app/main.go", "reason": "WSL /mnt/d/ path"},
    # UNC paths
    {"path": "//server/share/file.txt", "reason": "UNC forward slash path"},
    {"path": "\\\\server\\share\\file.txt", "reason": "UNC backslash path"},
    # Unix absolute paths (multi-segment)
    {"path": "/home/user/projects/file.py", "reason": "Unix absolute path"},
    {"path": "/usr/local/bin/script.sh", "reason": "Unix /usr/local path"},
    # Backslash paths (even if relative-looking)
    {"path": "src\\components\\Button.tsx", "reason": "Relative with backslashes"},
    {"path": "lib\\utils\\helper.py", "reason": "Relative with backslashes"},
]

# Paths that should be ALLOWED (relative paths with forward slashes)
ALLOWED_PATHS = [
    {"path": "src/file.py", "reason": "Simple relative path"},
    {"path": "lib/utils/helper.py", "reason": "Nested relative path"},
    {"path": "README.md", "reason": "Single file in root"},
    {"path": "./src/main.py", "reason": "Explicit current directory"},
    {"path": "components/Button.tsx", "reason": "Component path"},
    {"path": "tests/test_main.py", "reason": "Test file path"},
    {"path": "../sibling/file.py", "reason": "Parent directory reference"},
    {"path": "package.json", "reason": "Config file"},
    {"path": ".gitignore", "reason": "Dotfile"},
    {"path": "src/components/ui/Dialog.tsx", "reason": "Deep nested path"},
    # Allowed special Unix paths
    {"path": "/tmp/test.txt", "reason": "Unix /tmp/ allowed"},
    {"path": "/dev/null", "reason": "Unix /dev/ allowed"},
]


# ============================================================================
# HELPERS
# ============================================================================

def get_script_dir() -> Path:
    return Path(__file__).parent


def get_hook_path() -> Path:
    return get_script_dir() / "path-normalization-hook.py"


def run_test(tool_name: str, path: str, expectation: str, verbose: bool = True) -> bool:
    """Run a single test and return True if passed.

    expectation: "blocked" or "allowed"
    - blocked: exit code 2
    - allowed: exit code 0
    """
    hook_path = get_hook_path()

    input_json = json.dumps({
        "tool_name": tool_name,
        "tool_input": {"file_path": path}
    })

    try:
        # On Windows, hide console windows to avoid focus-stealing during tests
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            ["uv", "run", str(hook_path)],
            input=input_json,
            capture_output=True,
            text=True,
            timeout=10,
            **kwargs
        )
        exit_code = result.returncode
        stderr = result.stderr.strip()
    except subprocess.TimeoutExpired:
        if verbose:
            print("TIMEOUT")
        return False
    except Exception as e:
        if verbose:
            print(f"ERROR: {e}")
        return False

    # Determine actual result
    actual = "blocked" if exit_code == 2 else "allowed"
    passed = actual == expectation

    if verbose:
        if passed:
            print(f"PASS: {expectation.upper()} - {path}")
        else:
            print(f"FAIL: Expected {expectation.upper()}, got {actual.upper()} - {path}")
            if stderr:
                # Show first line of error
                first_line = stderr.split('\n')[0]
                print(f"  stderr: {first_line}")

    return passed


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def print_banner():
    """Print interactive mode banner."""
    print("\n" + "=" * 60)
    print("  Path Normalization Hook Tester")
    print("=" * 60)
    print("  Test file paths against path normalization rules.")
    print("  Type 'quit' or 'q' to exit.")
    print("=" * 60 + "\n")


def run_interactive_mode():
    """Run interactive testing mode."""
    print_banner()

    print("Rules enforced:")
    print("  - Use RELATIVE paths (not absolute)")
    print("  - Use forward slashes (/) not backslashes (\\)")
    print()

    while True:
        try:
            path = input("Path> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not path or path.lower() in ('q', 'quit'):
            print("\nGoodbye!")
            break

        # Test with Edit tool
        print()
        run_test("Edit", path, "blocked")  # Will show PASS/FAIL
        print()


# ============================================================================
# BATCH TEST SUITE MODE
# ============================================================================

def run_test_suite(suite_name: str) -> int:
    """Run predefined test suite.

    Returns:
        0 if all tests pass
        1 if any test fails
    """
    total_tests = 0
    passed_tests = 0

    # Determine which test sets to run
    run_blocked = suite_name in ("all", "absolute", "backslash")
    run_allowed = suite_name in ("all", "relative")

    if suite_name == "absolute":
        # Only absolute path tests (exclude backslash-only)
        blocked_tests = [t for t in BLOCKED_PATHS if "backslash" not in t["reason"].lower() or "absolute" in t["reason"].lower()]
    elif suite_name == "backslash":
        # Only backslash tests
        blocked_tests = [t for t in BLOCKED_PATHS if "backslash" in t["reason"].lower()]
    else:
        blocked_tests = BLOCKED_PATHS

    # Run blocked tests
    if run_blocked:
        print(f"\n{'=' * 60}")
        print(f"Test Suite: Blocked Paths")
        print(f"{'=' * 60}\n")

        for test_case in blocked_tests:
            path = test_case["path"]
            reason = test_case["reason"]

            total_tests += 1
            print(f"  [{total_tests}] {reason}")
            print(f"       Path: {path}")
            if run_test("Edit", path, "blocked", verbose=False):
                passed_tests += 1
                print(f"       PASS")
            else:
                print(f"       FAIL")

    # Run allowed tests
    if run_allowed:
        print(f"\n{'=' * 60}")
        print(f"Test Suite: Allowed Paths")
        print(f"{'=' * 60}\n")

        for test_case in ALLOWED_PATHS:
            path = test_case["path"]
            reason = test_case["reason"]

            total_tests += 1
            print(f"  [{total_tests}] {reason}")
            print(f"       Path: {path}")
            if run_test("Edit", path, "allowed", verbose=False):
                passed_tests += 1
                print(f"       PASS")
            else:
                print(f"       FAIL")

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"Test Summary")
    print(f"{'=' * 60}")
    print(f"Total: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    if total_tests > 0:
        pass_rate = (passed_tests / total_tests) * 100
        print(f"Pass Rate: {pass_rate:.1f}%")
    print()

    return 0 if passed_tests == total_tests else 1


def main():
    parser = argparse.ArgumentParser(
        description="Path Normalization Hook Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Run interactive mode')
    parser.add_argument('--test-suite', choices=['all', 'absolute', 'backslash', 'relative'],
                        help='Run batch test suite')

    # Positional args for CLI mode
    parser.add_argument('tool_name', nargs='?', default=None,
                        help='Tool name: Edit or Write')
    parser.add_argument('path', nargs='?', default=None,
                        help='File path to test')
    parser.add_argument('--expect-blocked', action='store_const', const='blocked', dest='expectation',
                        help='Expect path to be blocked')
    parser.add_argument('--expect-allowed', action='store_const', const='allowed', dest='expectation',
                        help='Expect path to be allowed')

    args = parser.parse_args()

    # Interactive mode
    if args.interactive:
        run_interactive_mode()
        sys.exit(0)

    # Batch test suite mode
    if args.test_suite:
        exit_code = run_test_suite(args.test_suite)
        sys.exit(exit_code)

    # CLI mode
    if not args.tool_name or not args.path:
        parser.print_help()
        sys.exit(1)

    expectation = args.expectation or "blocked"
    passed = run_test(args.tool_name, args.path, expectation)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
