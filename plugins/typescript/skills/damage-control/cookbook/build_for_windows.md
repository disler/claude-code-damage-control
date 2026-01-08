---
model: opus
description: Convert Damage Control patterns for Windows (PowerShell/cmd) compatibility
---

# Purpose

Update an existing Damage Control installation to work on Windows machines by converting Unix patterns to Windows PowerShell and cmd equivalents.

## Variables

GLOBAL_PATTERNS: ~/.claude/hooks/damage-control/patterns.yaml
PROJECT_PATTERNS: .claude/hooks/damage-control/patterns.yaml

## Instructions

- Check for existing damage control installation
- If not installed, ask user if they want to install first
- Convert Unix command patterns to Windows equivalents
- Add Windows-specific dangerous patterns
- Preserve existing path protections (paths work cross-platform)
- DO NOT remove Unix patterns - ADD Windows patterns alongside them

**IMPORTANT**: This creates a cross-platform patterns.yaml that works on both Unix and Windows.

## Windows Command Equivalents

| Unix Command | Windows PowerShell | Windows cmd |
|--------------|-------------------|-------------|
| `rm -rf` | `Remove-Item -Recurse -Force` | `rd /s /q`, `del /f /s /q` |
| `rm -r` | `Remove-Item -Recurse` | `rd /s` |
| `chmod 777` | `icacls * /grant Everyone:F` | `icacls` |
| `chown` | `takeown`, `icacls` | `takeown` |
| `sudo rm` | `Start-Process -Verb RunAs` | N/A |
| `git reset --hard` | Same | Same |
| `git push --force` | Same | Same |
| `mkfs` | `Format-Volume` | `format` |
| `dd` | N/A | N/A |
| `kill -9` | `Stop-Process -Force` | `taskkill /F` |
| `history -c` | `Clear-History` | `doskey /reinstall` |

## Workflow

### Step 1: Determine Installation Level

1. Use AskUserQuestion:

```
Question: "Which Damage Control installation do you want to update for Windows?"
Options:
- Global (~/.claude/hooks/damage-control/)
- Project (.claude/hooks/damage-control/)
- Project Personal (same location, different settings file)
```

2. Set PATTERNS_FILE based on selection

### Step 2: Check Installation Exists

3. Read PATTERNS_FILE to check if it exists

4. **If not found**: Use AskUserQuestion:
```
Question: "Damage Control is not installed at this level. Would you like to install it first?"
Options:
- Yes, install first (then run Windows conversion)
- No, cancel
```

5. If Yes → Read and execute [install_damage_control_ag_workflow.md](install_damage_control_ag_workflow.md), then continue

### Step 3: Read Current Patterns

6. Read the existing patterns.yaml file
7. Parse the `bashToolPatterns` section

### Step 4: Add Windows Patterns

8. Add the following Windows-specific patterns to `bashToolPatterns`:

```yaml
# ===========================================================================
# WINDOWS PATTERNS
# ===========================================================================

# ---------------------------------------------------------------------------
# WINDOWS CATASTROPHIC - Unix-style paths (WSL / Git Bash / MSYS2)
# ---------------------------------------------------------------------------
# WSL path to Windows home (/mnt/c/Users/...)
- pattern: '\brm\s+.*-[rR].*\s+/mnt/c/[Uu]sers(/[^/\s]*)?(/\*?)?(\s*$|\s+[;&|])'
  reason: rm recursive on Windows home via WSL (/mnt/c/Users) - CATASTROPHIC

# Git Bash / MSYS2 path to Windows home (/c/Users/...)
- pattern: '\brm\s+.*-[rR].*\s+/c/[Uu]sers(/[^/\s]*)?(/\*?)?(\s*$|\s+[;&|])'
  reason: rm recursive on Windows home via Git Bash (/c/Users) - CATASTROPHIC

# ---------------------------------------------------------------------------
# WINDOWS CATASTROPHIC - Hard block (PowerShell)
# ---------------------------------------------------------------------------
# Home directory via ~ or $HOME or $env:USERPROFILE
- pattern: '\bRemove-Item\s+.*-Recurse.*\s+~[/\\]?(\s|$)'
  reason: Remove-Item -Recurse on home directory (~) - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+\$HOME[/\\]?(\s|$)'
  reason: Remove-Item -Recurse on $HOME - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+\$env:USERPROFILE[/\\]?(\s|$)'
  reason: Remove-Item -Recurse on $env:USERPROFILE - CATASTROPHIC

# Windows Users directory (C:\Users or C:/Users)
- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\][Uu]sers[/\\]?[^/\\\s]*[''"]?(\s|$)'
  reason: Remove-Item -Recurse on C:\Users - CATASTROPHIC

# System root (C:\ alone)
- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\]?[''"]?(\s|$)'
  reason: Remove-Item -Recurse on C:\ root - CATASTROPHIC

# Windows system directories
- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\]Windows'
  reason: Remove-Item -Recurse on C:\Windows - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\]Program Files'
  reason: Remove-Item -Recurse on C:\Program Files - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\]ProgramData'
  reason: Remove-Item -Recurse on C:\ProgramData - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\]Boot'
  reason: Remove-Item -Recurse on C:\Boot - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\]Recovery'
  reason: Remove-Item -Recurse on C:\Recovery - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+[''"]?[Cc]:[/\\]System Volume Information'
  reason: Remove-Item -Recurse on C:\System Volume Information - CATASTROPHIC

# PowerShell environment variables pointing to system paths
- pattern: '\bRemove-Item\s+.*-Recurse.*\s+\$env:SystemRoot'
  reason: Remove-Item -Recurse on $env:SystemRoot - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+\$env:ProgramFiles'
  reason: Remove-Item -Recurse on $env:ProgramFiles - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+\$env:ProgramData'
  reason: Remove-Item -Recurse on $env:ProgramData - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+\$env:APPDATA'
  reason: Remove-Item -Recurse on $env:APPDATA - CATASTROPHIC

- pattern: '\bRemove-Item\s+.*-Recurse.*\s+\$env:LOCALAPPDATA'
  reason: Remove-Item -Recurse on $env:LOCALAPPDATA - CATASTROPHIC

# ---------------------------------------------------------------------------
# WINDOWS CATASTROPHIC - Hard block (cmd)
# ---------------------------------------------------------------------------
# rd /s on critical paths
- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\][Uu]sers[/\\]?[^/\\\s]*[''"]?(\s|$)'
  reason: rd /s on C:\Users - CATASTROPHIC

- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\]?[''"]?(\s|$)'
  reason: rd /s on C:\ root - CATASTROPHIC

- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\]Windows'
  reason: rd /s on C:\Windows - CATASTROPHIC

- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\]Program Files'
  reason: rd /s on C:\Program Files - CATASTROPHIC

- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\]ProgramData'
  reason: rd /s on C:\ProgramData - CATASTROPHIC

- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\]Boot'
  reason: rd /s on C:\Boot - CATASTROPHIC

- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\]Recovery'
  reason: rd /s on C:\Recovery - CATASTROPHIC

- pattern: '\brd\s+/s.*\s+[''"]?[Cc]:[/\\]System Volume Information'
  reason: rd /s on C:\System Volume Information - CATASTROPHIC

# rmdir /s on critical paths
- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\][Uu]sers[/\\]?[^/\\\s]*[''"]?(\s|$)'
  reason: rmdir /s on C:\Users - CATASTROPHIC

- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\]?[''"]?(\s|$)'
  reason: rmdir /s on C:\ root - CATASTROPHIC

- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\]Windows'
  reason: rmdir /s on C:\Windows - CATASTROPHIC

- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\]Program Files'
  reason: rmdir /s on C:\Program Files - CATASTROPHIC

- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\]ProgramData'
  reason: rmdir /s on C:\ProgramData - CATASTROPHIC

- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\]Boot'
  reason: rmdir /s on C:\Boot - CATASTROPHIC

- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\]Recovery'
  reason: rmdir /s on C:\Recovery - CATASTROPHIC

- pattern: '\brmdir\s+/s.*\s+[''"]?[Cc]:[/\\]System Volume Information'
  reason: rmdir /s on C:\System Volume Information - CATASTROPHIC

# ---------------------------------------------------------------------------
# WINDOWS DESTRUCTIVE FILE OPERATIONS (PowerShell) - Ask
# ---------------------------------------------------------------------------
- pattern: '\bRemove-Item\s+.*-Recurse'
  reason: Remove-Item with -Recurse flag (PowerShell rm -rf equivalent)
  ask: true

- pattern: '\bRemove-Item\s+.*-Force'
  reason: Remove-Item with -Force flag (PowerShell rm -f equivalent)
  ask: true

- pattern: '\bri\s+.*-Recurse'
  reason: ri (Remove-Item alias) with -Recurse
  ask: true

- pattern: '\bdel\s+.*-Recurse'
  reason: del (Remove-Item alias) with -Recurse
  ask: true

# ---------------------------------------------------------------------------
# WINDOWS DESTRUCTIVE FILE OPERATIONS (cmd) - Ask
# ---------------------------------------------------------------------------
- pattern: '\brd\s+/s'
  reason: rd /s (recursive directory delete)
  ask: true

- pattern: '\brmdir\s+/s'
  reason: rmdir /s (recursive directory delete)
  ask: true

- pattern: '\bdel\s+/[fF]'
  reason: del /f (force delete)
  ask: true

- pattern: '\bdel\s+/[sS]'
  reason: del /s (recursive delete)
  ask: true

- pattern: '\berase\s+/[fFsS]'
  reason: erase with force/recursive flags
  ask: true

# ---------------------------------------------------------------------------
# WINDOWS PERMISSION CHANGES
# ---------------------------------------------------------------------------
- pattern: '\bicacls\s+.*Everyone:F'
  reason: icacls granting Everyone full control

- pattern: '\bicacls\s+.*\*:F'
  reason: icacls granting full control

- pattern: '\btakeown\s+/[rR]'
  reason: takeown with recursive flag

- pattern: '\battrib\s+.*-[rRhHsS]'
  reason: attrib removing protection attributes

# ---------------------------------------------------------------------------
# WINDOWS PROCESS DESTRUCTION
# ---------------------------------------------------------------------------
- pattern: '\bStop-Process\s+.*-Force'
  reason: Stop-Process -Force (PowerShell kill -9)

- pattern: '\btaskkill\s+/[fF]'
  reason: taskkill /F (force kill)

- pattern: '\btaskkill\s+.*\/IM\s+\*'
  reason: taskkill targeting all processes

- pattern: '\bkill\s+.*-Force'
  reason: kill alias with -Force

# ---------------------------------------------------------------------------
# WINDOWS SYSTEM OPERATIONS
# ---------------------------------------------------------------------------
- pattern: '\bFormat-Volume'
  reason: Format-Volume (disk format)

- pattern: '\bformat\s+[a-zA-Z]:'
  reason: format command targeting drive

- pattern: '\bClear-Disk'
  reason: Clear-Disk (wipe disk)

- pattern: '\bInitialize-Disk'
  reason: Initialize-Disk (can destroy partitions)

# ---------------------------------------------------------------------------
# WINDOWS HISTORY/SHELL MANIPULATION
# ---------------------------------------------------------------------------
- pattern: '\bClear-History'
  reason: Clear-History (PowerShell history clear)

- pattern: '\bdoskey\s+/reinstall'
  reason: doskey /reinstall (cmd history clear)

# ---------------------------------------------------------------------------
# WINDOWS REGISTRY (dangerous)
# ---------------------------------------------------------------------------
- pattern: '\bRemove-ItemProperty\s+.*HKLM:'
  reason: Removing HKEY_LOCAL_MACHINE registry keys

- pattern: '\bRemove-Item\s+.*HKLM:'
  reason: Removing HKEY_LOCAL_MACHINE registry paths

- pattern: '\breg\s+delete\s+HKLM'
  reason: reg delete on HKEY_LOCAL_MACHINE

- pattern: '\breg\s+delete\s+.*\/f'
  reason: reg delete with force flag
```

### Step 5: Write Updated Patterns

9. Write the updated patterns.yaml with Windows patterns added

10. Show the user what was added

### Step 6: Restart Reminder

11. **IMPORTANT**: Tell the user:

> **Restart your agent for these changes to take effect.**

## Report

Present the update summary:

---

## Damage Control Updated for Windows

**Installation Level**: [Global/Project/Project Personal]
**Patterns File**: `[PATTERNS_FILE]`

### Windows Patterns Added

**CATASTROPHIC (Hard Block) - WSL / Git Bash / MSYS2**:
- `rm -r` on `/mnt/c/Users` (WSL path to Windows home)
- `rm -r` on `/c/Users` (Git Bash/MSYS2 path to Windows home)

**CATASTROPHIC (Hard Block) - PowerShell**:
- `Remove-Item -Recurse` on `~`, `$HOME`, `$env:USERPROFILE`
- `Remove-Item -Recurse` on `C:\Users`, `C:\`, `C:\Windows`
- `Remove-Item -Recurse` on `C:\Program Files`, `C:\ProgramData`, `C:\Boot`, `C:\Recovery`
- `Remove-Item -Recurse` on `$env:SystemRoot`, `$env:ProgramFiles`, `$env:APPDATA`

**CATASTROPHIC (Hard Block) - cmd**:
- `rd /s` and `rmdir /s` on `C:\Users`, `C:\`, `C:\Windows`
- `rd /s` and `rmdir /s` on `C:\Program Files`, `C:\ProgramData`, `C:\Boot`, `C:\Recovery`

**Ask Confirmation - PowerShell**:
- `Remove-Item -Recurse/-Force` (general paths)
- `ri`, `del` aliases with recursive flags

**Ask Confirmation - cmd**:
- `rd /s`, `rmdir /s` (general paths)
- `del /f /s`, `erase`

**Permission Changes**:
- `icacls` granting full control
- `takeown` with recursive flag

**Process Destruction**:
- `Stop-Process -Force`
- `taskkill /F`

**System Operations**:
- `Format-Volume`, `format`
- `Clear-Disk`, `Initialize-Disk`

**Registry Protection**:
- `Remove-ItemProperty` on HKLM
- `reg delete` on HKLM

### Existing Unix Patterns

All existing Unix patterns have been preserved. Your patterns.yaml now works on both Unix and Windows.

### IMPORTANT

**Restart your agent for these changes to take effect.**

### Next Steps

1. Review the updated patterns.yaml
2. Add any additional Windows-specific paths to protect
3. Test with: "test damage control"
