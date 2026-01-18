---
description: Sync damage-control and path-normalization hooks from dotfiles
---

# Purpose

Sync the latest hook changes from ~/.dotfiles/claude/hooks/ into this repo. This includes:
- **damage-control**: Copy Python files, update patterns.yaml, port logic changes to TypeScript
- **path-normalization**: Copy hook and test files

## Source Locations

### Damage Control
- Python hooks: `~/.dotfiles/claude/hooks/damage-control/`
- patterns.yaml: `~/.dotfiles/claude/skills/damage-control/patterns.yaml`
- Tests: `~/.dotfiles/claude/hooks/damage-control/tests/`

### Path Normalization
- Hook: `~/.dotfiles/claude/hooks/path-normalization/path-normalization-hook.py`
- Tests: `~/.dotfiles/claude/hooks/path-normalization/test-path-normalization.py`

## Target Locations

### Damage Control
- Python hooks: `plugins/python/hooks/`
- TypeScript hooks: `plugins/typescript/hooks/`
- Shared patterns: `shared/patterns.yaml`

### Path Normalization
- Plugin: `plugins/python/path-normalization/hooks/`

## Workflow

### Step 1: Show Differences

Diff each Python file to understand what changed:

```bash
diff ~/.dotfiles/claude/hooks/damage-control/bash-tool-damage-control.py plugins/python/hooks/bash-tool-damage-control.py
diff ~/.dotfiles/claude/hooks/damage-control/edit-tool-damage-control.py plugins/python/hooks/edit-tool-damage-control.py
diff ~/.dotfiles/claude/hooks/damage-control/write-tool-damage-control.py plugins/python/hooks/write-tool-damage-control.py
diff ~/.dotfiles/claude/hooks/damage-control/test-damage-control.py plugins/python/hooks/test-damage-control.py
diff ~/.dotfiles/claude/skills/damage-control/patterns.yaml plugins/python/hooks/patterns.yaml
```

### Step 2: Copy Python Files

```bash
cp ~/.dotfiles/claude/hooks/damage-control/bash-tool-damage-control.py plugins/python/hooks/
cp ~/.dotfiles/claude/hooks/damage-control/edit-tool-damage-control.py plugins/python/hooks/
cp ~/.dotfiles/claude/hooks/damage-control/write-tool-damage-control.py plugins/python/hooks/
cp ~/.dotfiles/claude/hooks/damage-control/test-damage-control.py plugins/python/hooks/
cp ~/.dotfiles/claude/hooks/damage-control/log_rotate.py plugins/python/hooks/
cp ~/.dotfiles/claude/hooks/damage-control/benchmark.py plugins/python/hooks/
```

### Step 3: Copy Test Files

```bash
cp ~/.dotfiles/claude/hooks/damage-control/tests/*.py plugins/python/hooks/tests/
cp ~/.dotfiles/claude/hooks/damage-control/tests/*.yaml plugins/python/hooks/tests/
```

### Step 4: Copy patterns.yaml to All Locations

```bash
cp ~/.dotfiles/claude/skills/damage-control/patterns.yaml plugins/python/hooks/patterns.yaml
cp ~/.dotfiles/claude/skills/damage-control/patterns.yaml plugins/typescript/hooks/patterns.yaml
cp ~/.dotfiles/claude/skills/damage-control/patterns.yaml shared/patterns.yaml
```

### Step 5: Port Python Changes to TypeScript

Review the diffs from Step 1. For any **logic changes** (not just patterns.yaml), update the corresponding TypeScript files:

- `plugins/typescript/hooks/bash-tool-damage-control.ts`
- `plugins/typescript/hooks/edit-tool-damage-control.ts`
- `plugins/typescript/hooks/write-tool-damage-control.ts`

Common changes to look for:
- Return value changes (blocked vs ask)
- New regex patterns or matching logic
- Path matching improvements
- New helper functions

### Step 6: Run Tests

```bash
cd plugins/python/hooks && uv run --with pytest --with pyyaml pytest tests/ -v --tb=short
```

### Step 7: Fix Test Failures

If tests fail, update the test files or fixtures to match the new patterns/behavior.

---

## Path Normalization Sync

### Step 8: Show Path Normalization Differences

```bash
diff ~/.dotfiles/claude/hooks/path-normalization/path-normalization-hook.py plugins/python/path-normalization/hooks/path-normalization-hook.py
diff ~/.dotfiles/claude/hooks/path-normalization/test-path-normalization.py plugins/python/path-normalization/hooks/test-path-normalization.py
```

### Step 9: Copy Path Normalization Files

```bash
cp ~/.dotfiles/claude/hooks/path-normalization/path-normalization-hook.py plugins/python/path-normalization/hooks/
cp ~/.dotfiles/claude/hooks/path-normalization/test-path-normalization.py plugins/python/path-normalization/hooks/
```

### Step 10: Run Path Normalization Tests

```bash
cd plugins/python/path-normalization/hooks && uv run test-path-normalization.py --test-suite all
```

---

## Cleanup

### Step 11: Remove Temp Files

Claude Code's hook runner creates temporary files during execution. Clean them up:

```bash
rm -f tmpclaude-*-cwd
```

---

## Report

After completing the sync, summarize:

1. **Damage Control files synced** - List files copied with line count changes
2. **Python changes** - Brief description of logic changes (not just patterns)
3. **TypeScript updates** - What was ported to TypeScript
4. **Damage Control test results** - Pass/fail count
5. **Path Normalization files synced** - List files copied
6. **Path Normalization test results** - Pass/fail count
7. **Action items** - Any remaining manual work needed
