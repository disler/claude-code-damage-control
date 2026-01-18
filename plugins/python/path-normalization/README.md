# Path Normalization Plugin

Enforces relative paths with forward slashes for Claude Code's Edit and Write tools.

## What It Does

- **Blocks absolute paths** - Guides Claude to use relative paths from workspace root
- **Enforces forward slashes** - Prevents Windows-style backslashes in paths
- **Detects multiple formats**:
  - Windows drive letters: `C:/`, `E:\`
  - MSYS/Git Bash style: `/c/`, `/e/`
  - WSL mount paths: `/mnt/c/`, `/mnt/d/`
  - UNC network paths: `//server/share`
  - Unix absolute paths: `/home/user/...`

## Installation

```bash
/plugin install github:ilude/claude-code-damage-control/plugins/path-normalization
```

Or locally:
```bash
/plugin install ./plugins/path-normalization
```

## Requirements

- Python 3.8+
- [UV package manager](https://astral.sh/uv) (automatically manages Python)

## Testing

```bash
cd plugins/path-normalization/hooks

# Run full test suite
uv run test-path-normalization.py --test-suite all

# Test specific suites
uv run test-path-normalization.py --test-suite absolute
uv run test-path-normalization.py --test-suite backslash
uv run test-path-normalization.py --test-suite relative

# Interactive mode
uv run test-path-normalization.py -i
```

## Exit Codes

- `0` - Allow (path is relative with forward slashes)
- `2` - Block (stderr contains guidance for Claude)
