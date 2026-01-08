# Damage Control Hook Tests

Unit and integration tests for the bash-tool-damage-control hook.

## Running Tests

```bash
# Run all tests
cd ~/.dotfiles/claude/hooks/damage-control/tests
python test_git_semantic.py
python test_integration.py

# Or run both together
python test_git_semantic.py && python test_integration.py
```

## Test Files

### test_git_semantic.py
Unit tests for the `analyze_git_command()` function. Tests semantic understanding of git commands to distinguish safe vs dangerous operations.

**Test cases:**
- `git checkout -b feature` → Safe (creating branch)
- `git checkout -- .` → Dangerous (discard changes)
- `git push --force-with-lease` → Safe (safe force push)
- `git push --force` → Dangerous (unsafe force push)
- `git reset --hard` → Dangerous (permanent discard)
- `git clean -fd` → Dangerous (remove untracked files)
- Combined short flags (e.g., `-fu`, `-fb`, `-fd`)
- Edge cases (no subcommand, unknown aliases, etc.)

### test_integration.py
Integration tests for the full `check_command()` pipeline. Tests the combination of:
1. Shell wrapper unwrapping (Task 1)
2. Git semantic analysis (Task 2)
3. Pattern matching from YAML config

**Test cases:**
- Direct git commands (semantic analysis)
- Wrapped git commands (unwrapping + semantic analysis)
- Safe git operations (should allow)

## Test Output

Each test prints:
- `[PASS]` or `[FAIL]` status
- Test description
- Command being tested
- Expected vs actual result
- Block reason (if dangerous)

Final summary:
- `[SUCCESS] All tests passed!` (exit code 0)
- `[FAILURE] Some tests failed!` (exit code 1)
