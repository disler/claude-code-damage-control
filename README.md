# Claude Code Damage Control

<img src="images/claude-code-damage-control.png" width="800" alt="Claude Code Damage Control">

Defense-in-depth protection for Claude Code. Blocks dangerous commands and protects sensitive files via PreToolUse hooks.

## Installation

### Via Plugin Marketplace (Recommended)

```bash
# Add the marketplace
/plugin marketplace add ilude/claude-code-damage-control

# Install Python version (recommended - uses UV)
/plugin install damage-control

# OR install TypeScript version (uses Bun)
/plugin install damage-control-typescript

# Optional: Install path-normalization plugin
/plugin install path-normalization
```

### Direct GitHub Install

```bash
# Python version
/plugin install github:ilude/claude-code-damage-control/plugins/python

# TypeScript version
/plugin install github:ilude/claude-code-damage-control/plugins/typescript

# Path normalization
/plugin install github:ilude/claude-code-damage-control/plugins/python/path-normalization
```

### Manual Installation (Development)

```bash
git clone https://github.com/ilude/claude-code-damage-control.git
cd claude-code-damage-control

# Install Python version
/plugin install ./plugins/python

# OR TypeScript version
/plugin install ./plugins/typescript

# Path normalization
/plugin install ./plugins/python/path-normalization
```

### Requirements

**Python version (`damage-control`)**:
- [UV package manager](https://astral.sh/uv) (automatically manages Python 3.8+)

**TypeScript version (`damage-control-typescript`)**:
- [Bun](https://bun.sh/) 1.0+ (install via `curl -fsSL https://bun.sh/install | bash` or `npm install -g bun`)

---

## Key Features

- **Command Pattern Blocking** - Blocks dangerous bash commands (rm -rf, git reset --hard, etc.)
- **Ask Patterns** - Triggers confirmation dialog for risky-but-valid operations
- **Path Protection** - Three levels: zeroAccess, readOnly, noDelete
- **Shell Wrapper Unwrapping** - Detects hidden commands in `bash -c`, `python -c`, etc.
- **Semantic Git Analysis** - Distinguishes safe (`checkout -b`) from dangerous (`checkout -- .`) git operations
- **Context-Aware Security** - Relaxes checks in documentation files and commit messages
- **Audit Logging** - JSONL logs with automatic secret redaction
- **Cross-Platform** - Works on Unix, Windows (PowerShell/cmd), WSL, and Git Bash

---

## Path Normalization Plugin

A separate plugin that enforces consistent path usage across platforms.

### What It Does

- **Blocks absolute paths** in Edit/Write operations (e.g., `C:/Users/...`, `/home/user/...`)
- **Enforces forward slashes** - blocks backslash paths like `src\components\file.ts`
- **Guides to relative paths** - suggests the correct relative path when blocking

### Why Use It

| Problem | Solution |
|---------|----------|
| Absolute paths break on other machines | Enforces relative paths from project root |
| Backslashes cause cross-platform issues | Requires forward slashes consistently |
| Subagents may use inconsistent paths | Normalizes all Edit/Write operations |

### Path Detection

The plugin detects and blocks:

```
C:/Users/mike/project/file.py     → Windows absolute
/c/Users/mike/project/file.py     → MSYS/Git Bash absolute
/home/user/project/file.py        → Unix absolute
/mnt/c/Users/mike/project/file.py → WSL mount path
\\server\share\file.py            → UNC network path
src\components\Button.tsx         → Backslash path
```

And suggests the relative equivalent:

```
Use relative path: 'src/components/Button.tsx'
```

### Exceptions

The plugin allows:
- Paths within the current project directory (even if absolute)
- Claude Code internal paths (`~/.claude/...`)
- Paths within the user's home directory (for subagent compatibility)
- System paths like `/tmp/`, `/dev/`

### Testing

```bash
cd plugins/python/path-normalization/hooks
python test-path-normalization.py --test-suite all
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Claude Code Tool Call                              │
└─────────────────────────────────────────────────────────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
    ┌───────────┐         ┌───────────┐         ┌───────────┐
    │   Bash    │         │   Edit    │         │   Write   │
    │   Tool    │         │   Tool    │         │   Tool    │
    └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
          │                     │                     │
          ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ bash-tool-      │   │ edit-tool-      │   │ write-tool-     │
│ damage-control  │   │ damage-control  │   │ damage-control  │
│                 │   │                 │   │                 │
│ • bashTool-     │   │ • zeroAccess-   │   │ • zeroAccess-   │
│   Patterns      │   │   Paths         │   │   Paths         │
│ • zeroAccess-   │   │ • readOnlyPaths │   │ • readOnlyPaths │
│   Paths         │   │                 │   │                 │
│ • readOnlyPaths │   │                 │   │                 │
│ • noDeletePaths │   │                 │   │                 │
└────────┬────────┘   └────────┬────────┘   └────────┬────────┘
         │                     │                     │
         ▼                     ▼                     ▼
   exit 0 = allow        exit 0 = allow        exit 0 = allow
   exit 2 = BLOCK        exit 2 = BLOCK        exit 2 = BLOCK
   JSON   = ASK
```

---

## Path Protection Levels

All path configurations are in `patterns.yaml`. Each level provides different protection:

| Path Type         | Read | Write | Edit | Delete | Enforced By       |
| ----------------- | ---- | ----- | ---- | ------ | ----------------- |
| `zeroAccessPaths` | ✗    | ✗     | ✗    | ✗      | Bash, Edit, Write |
| `readOnlyPaths`   | ✓    | ✗     | ✗    | ✗      | Bash, Edit, Write |
| `noDeletePaths`   | ✓    | ✓     | ✓    | ✗      | Bash only         |

### zeroAccessPaths
**No access at all** - for secrets and credentials that should never be touched.
```yaml
zeroAccessPaths:
  - ~/.ssh/
  - ~/.aws/
  - ~/.gnupg/
```

### readOnlyPaths
**Read allowed, modifications blocked** - for system files and configs.
```yaml
readOnlyPaths:
  - /etc/
  - ~/.bashrc
  - ~/.zshrc
```

### noDeletePaths
**All operations except delete** - protect important files from accidental removal.
```yaml
noDeletePaths:
  - .claude/hooks/
  - .claude/commands/
```

---

## Plugin Commands

After installation, these commands are available:

- `/damage-control:install` - Configure or reinstall hooks
- `/damage-control:test` - Run test suite to verify protection
- `/damage-control:prime` - Orient Claude on the codebase

---

## Repository Structure

```
/
├── .claude-plugin/
│   └── marketplace.json           # Marketplace listing
│
├── shared/                        # Shared resources
│   ├── patterns.yaml              # Security patterns (single source)
│   ├── skills/
│   │   └── damage-control/
│   │       ├── SKILL.md
│   │       ├── cookbook/
│   │       └── test-prompts/
│   └── commands/
│       ├── install.md
│       ├── prime.md
│       └── test.md
│
├── plugins/
│   ├── python/                    # damage-control plugin
│   │   ├── .claude-plugin/
│   │   │   └── plugin.json
│   │   ├── hooks/
│   │   │   ├── hooks.json
│   │   │   ├── bash-tool-damage-control.py
│   │   │   ├── edit-tool-damage-control.py
│   │   │   ├── write-tool-damage-control.py
│   │   │   ├── log_rotate.py
│   │   │   └── tests/
│   │   ├── skills/
│   │   ├── commands/
│   │   │
│   │   └── path-normalization/    # path-normalization plugin
│   │       ├── .claude-plugin/
│   │       │   └── plugin.json
│   │       └── hooks/
│   │           ├── hooks.json
│   │           ├── path-normalization-hook.py
│   │           └── test-path-normalization.py
│   │
│   └── typescript/                # damage-control-typescript plugin
│       ├── .claude-plugin/
│       │   └── plugin.json
│       ├── hooks/
│       │   ├── hooks.json
│       │   ├── bash-tool-damage-control.ts
│       │   ├── edit-tool-damage-control.ts
│       │   ├── write-tool-damage-control.ts
│       │   └── log_rotate.ts
│       ├── skills/
│       └── commands/
```

---

## Configuration

### patterns.yaml

```yaml
# Dangerous command patterns (Bash tool only)
bashToolPatterns:
  # Block these entirely
  - pattern: '\brm\s+-[rRf]'
    reason: rm with recursive or force flags

  - pattern: '\bDELETE\s+FROM\s+\w+\s*;'
    reason: DELETE without WHERE clause

  # Ask for confirmation (triggers permission dialog)
  - pattern: '\bDELETE\s+FROM\s+\w+\s+WHERE\b.*\bid\s*='
    reason: SQL DELETE with specific ID
    ask: true

# No access at all - secrets/credentials
zeroAccessPaths:
  - ~/.ssh/
  - ~/.aws/

# Read allowed, modifications blocked
readOnlyPaths:
  - /etc/
  - ~/.bashrc

# All operations except delete
noDeletePaths:
  - .claude/hooks/
```

---

## What Gets Blocked

See [`shared/patterns.yaml`](shared/patterns.yaml) for the complete list of blocked commands, protected paths, and security patterns.

### Path Protection Matrix

| Operation       | zeroAccessPaths | readOnlyPaths | noDeletePaths |
| --------------- | --------------- | ------------- | ------------- |
| Read (`cat`)    | ✅ Blocked       | ❌ Allowed     | ❌ Allowed     |
| Write (`>`)     | ✅ Blocked       | ✅ Blocked     | ❌ Allowed     |
| Append (`>>`)   | ✅ Blocked       | ✅ Blocked     | ❌ Allowed     |
| Edit (`sed -i`) | ✅ Blocked       | ✅ Blocked     | ❌ Allowed     |
| Delete (`rm`)   | ✅ Blocked       | ✅ Blocked     | ✅ Blocked     |
| Move (`mv`)     | ✅ Blocked       | ✅ Blocked     | ❌ Allowed     |
| Chmod           | ✅ Blocked       | ✅ Blocked     | ❌ Allowed     |

---

## Ask Patterns

Patterns with `ask: true` trigger a confirmation dialog instead of blocking. This lets users approve risky-but-valid operations.

```yaml
bashToolPatterns:
  # Block entirely (default)
  - pattern: '\bDELETE\s+FROM\s+\w+\s*;'
    reason: DELETE without WHERE clause

  # Ask for confirmation
  - pattern: '\bDELETE\s+FROM\s+\w+\s+WHERE\b.*\bid\s*='
    reason: SQL DELETE with specific ID
    ask: true
```

**Behavior:**
- Pattern without `ask` → Blocked (exit code 2)
- Pattern with `ask: true` → Shows permission dialog (JSON output)

---

## Advanced Features

### Shell Wrapper Unwrapping

Detects and analyzes commands hidden inside shell wrappers (up to 5 levels deep):

```bash
# All of these are detected and blocked:
bash -c "rm -rf /"
python -c "import os; os.system('rm -rf /')"
sh -c 'bash -c "rm -rf /"'
```

### Semantic Git Analysis

Intelligently distinguishes safe from dangerous git operations:

| Safe Operations | Dangerous Operations |
|-----------------|---------------------|
| `git checkout -b feature` | `git checkout -- .` |
| `git push --force-with-lease` | `git push --force` |
| `git reset --soft HEAD~1` | `git reset --hard` |
| `git status` | `git clean -fd` |

### Context-Aware Security

The `contexts` section in patterns.yaml relaxes checks in appropriate situations:

```yaml
contexts:
  documentation:
    enabled: true
    detection:
      file_extensions: [".md", ".rst", ".txt"]
    relaxed_checks:
      - bashToolPatterns  # Allow mentioning dangerous commands in docs
    enforced_checks:
      - zeroAccessPaths   # Still protect secrets
```

This allows writing documentation that mentions `rm -rf` without triggering blocks.

### Audit Logging

All decisions are logged to `~/.claude/logs/damage-control/YYYY-MM-DD.log`:

```json
{"timestamp": "2024-01-07T12:00:00", "tool": "Bash", "command": "rm -rf /tmp", "decision": "blocked", "reason": "rm with recursive flags"}
```

Features:
- Automatic secret redaction (API keys, passwords, tokens)
- Fire-and-forget log rotation (30 days archive, 90 days delete)
- JSONL format for easy parsing

### Hook Disable (Development Only)

For hook development, you can temporarily disable hooks via environment variable:

```bash
CLAUDE_DISABLE_HOOKS=damage-control claude
# or
CLAUDE_DISABLE_HOOKS=path-normalization claude
# or both
CLAUDE_DISABLE_HOOKS=damage-control,path-normalization claude
```

> **Warning:** Only use this when modifying the hooks themselves. Never use it to bypass security checks during normal work.

---

## Testing

### Interactive Tester

Test commands and file paths interactively against your security patterns:

**Python/UV:**
```bash
cd plugins/python/hooks
uv run test-damage-control.py -i
```

**Bun/TypeScript:**
```bash
cd plugins/typescript/hooks
bun run test-damage-control.ts -i
```

### CLI Testing

Test individual commands without interactive mode:

```bash
# Test bash hook blocks rm -rf
uv run test-damage-control.py bash Bash "rm -rf /tmp" --expect-blocked

# Test edit hook blocks zero-access path
uv run test-damage-control.py edit Edit "~/.ssh/id_rsa" --expect-blocked

# Test bash allows safe command
uv run test-damage-control.py bash Bash "ls -la" --expect-allowed
```

### Test Suite

Run the full test suite (174 tests):

```bash
cd plugins/python/hooks
uv run pytest tests/ -v
```

---

## Exit Codes

| Code  | Meaning | Behavior                               |
| ----- | ------- | -------------------------------------- |
| `0`   | Allow   | Command proceeds                       |
| `0`   | Ask     | JSON output triggers permission dialog |
| `2`   | Block   | Command blocked, stderr sent to Claude |
| Other | Error   | Warning shown, command proceeds        |

---

## Uninstall

```bash
/plugin uninstall damage-control
# or
/plugin uninstall damage-control-typescript
```

---

## Troubleshooting

### Hook not firing

1. Check `/hooks` in Claude Code to verify registration
2. Validate plugin: `/plugin validate .`
3. Check permissions: `chmod +x hooks/*.py`

### Commands still getting through

1. Use interactive tester: `uv run test-damage-control.py -i`
2. Check case sensitivity (patterns use case-insensitive matching)
3. Run with debug: `claude --debug`

---

## License

MIT

---

## Official Documentation

- [Hooks Reference](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [Settings Configuration](https://docs.anthropic.com/en/docs/claude-code/settings)
- [Plugins Reference](https://code.claude.com/docs/en/plugins-reference.md)

---

## Master **Agentic Coding**
> Prepare for the future of software engineering

Learn tactical agentic coding patterns with [Tactical Agentic Coding](https://agenticengineer.com/tactical-agentic-coding?y=dmgctl)

Follow the [IndyDevDan YouTube channel](https://www.youtube.com/@indydevdan) to improve your agentic coding advantage.
