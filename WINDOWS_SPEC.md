# Windows Adaptation Spec for Claude Code Damage Control

## Status: IMPLEMENTED

The cross-platform support has been implemented. See the new file structure below.

## Overview

This spec outlines changes needed to make damage-control work properly on Windows. The existing implementation is Unix/Linux-focused and needs significant additions for Windows equivalents.

## Implementation Summary

The following changes have been made:

### New Config Files
- `patterns-base.yaml` - Cross-platform patterns (git, cloud CLIs, SQL, docker, k8s, etc.)
- `patterns-unix.yaml` - Unix/macOS-specific patterns (rm -rf, chmod, chown, etc.)
- `patterns-windows.yaml` - Windows-specific patterns (Remove-Item, icacls, registry, etc.)

### Updated Python Hooks
All three Python hooks now:
- Auto-detect platform (`sys.platform`)
- Load `patterns-base.yaml` + platform-specific config
- Merge the configs at runtime
- Handle Windows environment variables (`%VAR%`)
- Support case-insensitive path matching on Windows

### New Settings Files
- `unix-settings.json` - Settings for Mac/Linux (was python-settings.json)
- `windows-settings.json` - Settings for Windows with PowerShell-aware prompts

---

## 1. Hook Execution Changes

### Current (Unix)
```json
{
  "command": "uv run \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/damage-control/bash-tool-damage-control.py"
}
```

### Windows Adaptation
```json
{
  "command": "uv run \"%CLAUDE_PROJECT_DIR%\\.claude\\hooks\\damage-control\\bash-tool-damage-control.py\""
}
```

**Alternative (PowerShell-native):**
```json
{
  "command": "python \"$env:CLAUDE_PROJECT_DIR\\.claude\\hooks\\damage-control\\bash-tool-damage-control.py\""
}
```

> **Note**: Need to verify how Claude Code sets `CLAUDE_PROJECT_DIR` on Windows and whether it uses `%VAR%` or `$env:VAR` syntax.

---

## 2. PowerShell Destructive Patterns

Add a new section to `patterns.yaml`:

```yaml
# ---------------------------------------------------------------------------
# POWERSHELL DESTRUCTIVE OPERATIONS
# ---------------------------------------------------------------------------

# Recursive deletion
- pattern: '\bRemove-Item\s+.*-Recurse'
  reason: Remove-Item with -Recurse (equivalent to rm -rf)

- pattern: '\bRemove-Item\s+.*-Force'
  reason: Remove-Item with -Force flag

- pattern: '\brd\s+/s\s+/q'
  reason: rd /s /q (recursive delete, quiet mode)

- pattern: '\bdel\s+/s\s+/q'
  reason: del /s /q (recursive file delete)

- pattern: '\brmdir\s+/s\s+/q'
  reason: rmdir /s /q (recursive directory delete)

# PowerShell aliases for Remove-Item
- pattern: '\bri\s+.*-Recurse'
  reason: ri (Remove-Item alias) with -Recurse

- pattern: '\brm\s+.*-Recurse'
  reason: rm (Remove-Item alias) with -Recurse

- pattern: '\bdel\s+.*-Recurse'
  reason: del (Remove-Item alias) with -Recurse

# Format/disk operations
- pattern: '\bFormat-Volume\b'
  reason: Format-Volume (disk format)

- pattern: '\bClear-Disk\b'
  reason: Clear-Disk (wipes disk)

- pattern: '\bInitialize-Disk\b'
  reason: Initialize-Disk (can destroy partition table)

- pattern: '\bformat\s+[a-zA-Z]:'
  reason: format drive command

# Permission changes
- pattern: '\bicacls\s+.*\/grant.*Everyone:\(F\)'
  reason: icacls granting full control to Everyone

- pattern: '\bicacls\s+.*\/grant.*\*S-1-1-0:\(F\)'
  reason: icacls granting full control to Everyone (SID)

- pattern: '\btakeown\s+/r'
  reason: takeown with recursive flag

- pattern: '\bSet-Acl\b'
  reason: Set-Acl (permission modification)
  ask: true

# Registry operations
- pattern: '\bRemove-ItemProperty\s+.*HKLM:'
  reason: Removing HKLM registry key

- pattern: '\bRemove-Item\s+.*HKLM:'
  reason: Removing HKLM registry path

- pattern: '\breg\s+delete\s+HKLM'
  reason: reg delete on HKLM

- pattern: '\breg\s+delete\s+HKEY_LOCAL_MACHINE'
  reason: reg delete on HKEY_LOCAL_MACHINE

# Service destruction
- pattern: '\bStop-Service\s+.*-Force'
  reason: Force stopping service

- pattern: '\bRemove-Service\b'
  reason: Removing Windows service

- pattern: '\bsc\s+delete\b'
  reason: sc delete (service removal)

# Scheduled task destruction
- pattern: '\bUnregister-ScheduledTask\b'
  reason: Removing scheduled task

- pattern: '\bschtasks\s+/delete'
  reason: schtasks delete

# Windows Defender / Security
- pattern: '\bSet-MpPreference\s+.*-DisableRealtimeMonitoring'
  reason: Disabling Windows Defender realtime monitoring

- pattern: '\bRemove-MpPreference\b'
  reason: Removing Windows Defender preferences

# Event log clearing
- pattern: '\bClear-EventLog\b'
  reason: Clearing Windows event logs

- pattern: '\bwevtutil\s+cl\b'
  reason: wevtutil clear logs

# Certificate store
- pattern: '\bRemove-Item\s+.*Cert:\\'
  reason: Removing certificates from store

# Hyper-V / VM destruction
- pattern: '\bRemove-VM\s+.*-Force'
  reason: Force removing Hyper-V VM

- pattern: '\bRemove-VMSnapshot\b'
  reason: Removing VM snapshot

# IIS
- pattern: '\bRemove-Website\b'
  reason: Removing IIS website

- pattern: '\bRemove-WebAppPool\b'
  reason: Removing IIS app pool

# SQL Server
- pattern: '\bInvoke-Sqlcmd.*DROP\s+DATABASE'
  reason: DROP DATABASE via Invoke-Sqlcmd

- pattern: '\bsqlcmd.*DROP\s+DATABASE'
  reason: DROP DATABASE via sqlcmd

# ---------------------------------------------------------------------------
# POWERSHELL OPERATIONS REQUIRING CONFIRMATION (ask: true)
# ---------------------------------------------------------------------------

- pattern: '\bRestart-Computer\b'
  reason: Restarting computer
  ask: true

- pattern: '\bStop-Computer\b'
  reason: Shutting down computer
  ask: true

- pattern: '\bshutdown\s+'
  reason: System shutdown command
  ask: true

- pattern: '\bRestart-Service\b'
  reason: Restarting service
  ask: true
```

---

## 3. Windows Protected Paths

Update the path sections in `patterns.yaml`:

```yaml
# ---------------------------------------------------------------------------
# ZERO ACCESS PATHS - Windows Additions
# ---------------------------------------------------------------------------
zeroAccessPaths:
  # Existing Unix paths (keep for cross-platform)...

  # Windows User Profile Secrets
  - "%USERPROFILE%\\.ssh\\"
  - "$env:USERPROFILE\\.ssh\\"
  - "~\\.ssh\\"

  # Windows Credential Stores
  - "%APPDATA%\\Microsoft\\Credentials\\"
  - "%LOCALAPPDATA%\\Microsoft\\Credentials\\"
  - "%USERPROFILE%\\.azure\\"
  - "%USERPROFILE%\\.aws\\"
  - "%USERPROFILE%\\.kube\\"
  - "%USERPROFILE%\\.docker\\"

  # Windows Certificate Private Keys
  - "%APPDATA%\\Microsoft\\Crypto\\"
  - "%PROGRAMDATA%\\Microsoft\\Crypto\\"

  # Git Credentials Windows
  - "%USERPROFILE%\\.git-credentials"
  - "%APPDATA%\\git\\credentials"

  # npm/node Windows
  - "%USERPROFILE%\\.npmrc"
  - "%APPDATA%\\npm\\"

  # VS Code secrets
  - "%APPDATA%\\Code\\User\\secrets\\"

  # Rider/JetBrains secrets
  - "%APPDATA%\\JetBrains\\*\\options\\security.xml"

  # NuGet credentials
  - "%APPDATA%\\NuGet\\NuGet.Config"

# ---------------------------------------------------------------------------
# READ-ONLY PATHS - Windows Additions
# ---------------------------------------------------------------------------
readOnlyPaths:
  # Existing Unix paths...

  # Windows System Directories
  - "C:\\Windows\\"
  - "C:\\Windows\\System32\\"
  - "C:\\Windows\\SysWOW64\\"
  - "C:\\Program Files\\"
  - "C:\\Program Files (x86)\\"

  # PowerShell History
  - "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
  - "$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"

  # Windows PowerShell Profiles
  - "$PROFILE"
  - "%USERPROFILE%\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1"
  - "%USERPROFILE%\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1"

  # Lock files (keep existing, they work cross-platform)

  # Windows Build Artifacts
  - "bin\\"
  - "obj\\"
  - "packages\\"

# ---------------------------------------------------------------------------
# NO-DELETE PATHS - Windows Additions
# ---------------------------------------------------------------------------
noDeletePaths:
  # Existing paths...

  # Visual Studio solution files
  - "*.sln"
  - "*.csproj"
  - "*.fsproj"
  - "*.vbproj"

  # NuGet config
  - "nuget.config"
  - "packages.config"
```

---

## 4. Path Matching Code Changes

The Python code uses `os.path.expanduser()` which works on Windows, but needs updates for Windows environment variable patterns:

```python
def expand_windows_vars(path: str) -> str:
    """Expand Windows environment variables in path."""
    import os

    # Handle %VAR% style
    result = os.path.expandvars(path)

    # Handle $env:VAR style (PowerShell)
    if '$env:' in result:
        import re
        def replace_ps_var(match):
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))
        result = re.sub(r'\$env:(\w+)', replace_ps_var, result)

    # Handle ~ (works on Windows with expanduser)
    result = os.path.expanduser(result)

    return result


def normalize_path(path: str) -> str:
    """Normalize path for cross-platform comparison."""
    expanded = expand_windows_vars(path)
    # Normalize slashes and case (Windows is case-insensitive)
    normalized = os.path.normpath(expanded)
    if os.name == 'nt':
        normalized = normalized.lower()
    return normalized
```

---

## 5. Operation Pattern Updates for Windows

The `bash-tool-damage-control.py` has patterns for Unix file operations. Add Windows equivalents:

```python
# Windows write operations
WINDOWS_WRITE_PATTERNS = [
    (r'>\s*{path}', "write"),
    (r'Out-File\s+.*{path}', "write"),
    (r'Set-Content\s+.*{path}', "write"),
    (r'\bcopy\s+.*\s+{path}', "copy"),
    (r'\bxcopy\s+.*\s+{path}', "copy"),
    (r'Copy-Item\s+.*{path}', "copy"),
    (r'\bmove\s+.*\s+{path}', "move"),
    (r'Move-Item\s+.*{path}', "move"),
]

WINDOWS_DELETE_PATTERNS = [
    (r'\bdel\s+.*{path}', "delete"),
    (r'\berase\s+.*{path}', "delete"),
    (r'\brd\s+.*{path}', "delete"),
    (r'\brmdir\s+.*{path}', "delete"),
    (r'Remove-Item\s+.*{path}', "delete"),
]

WINDOWS_PERMISSION_PATTERNS = [
    (r'\bicacls\s+.*{path}', "icacls"),
    (r'\bcacls\s+.*{path}', "cacls"),
    (r'\btakeown\s+.*{path}', "takeown"),
    (r'\battrib\s+.*{path}', "attrib"),
]
```

---

## 6. Settings.json for Windows

Create `windows-settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python \"%CLAUDE_PROJECT_DIR%\\.claude\\hooks\\damage-control\\bash-tool-damage-control.py\"",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python \"%CLAUDE_PROJECT_DIR%\\.claude\\hooks\\damage-control\\edit-tool-damage-control.py\"",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "python \"%CLAUDE_PROJECT_DIR%\\.claude\\hooks\\damage-control\\write-tool-damage-control.py\"",
            "timeout": 5
          }
        ]
      }
    ]
  },

  "permissions": {
    "deny": [
      "Bash(Remove-Item * -Recurse -Force:*)",
      "Bash(rd /s /q:*)",
      "Bash(del /s /q:*)",
      "Bash(Format-Volume:*)",
      "Bash(Clear-Disk:*)",
      "Bash(reg delete HKLM:*)"
    ],
    "ask": [
      "Bash(git push --force:*)",
      "Bash(git reset --hard:*)",
      "Bash(Restart-Computer:*)",
      "Bash(Stop-Service:*)"
    ]
  }
}
```

---

## 7. Implementation Priority

### Phase 1: Critical (Do First)
1. Add PowerShell destructive patterns (`Remove-Item -Recurse`, `rd /s /q`, etc.)
2. Add Windows credential paths to zeroAccessPaths
3. Update path matching to handle Windows environment variables

### Phase 2: Important
4. Add Windows permission modification patterns (`icacls`, `takeown`, etc.)
5. Add Windows system paths to readOnlyPaths
6. Add registry operation patterns

### Phase 3: Nice to Have
7. Add Windows service/scheduled task patterns
8. Add Windows-specific confirmation patterns
9. Create separate `windows-patterns.yaml` that extends base patterns

---

## 8. Testing Considerations

Need to test:
- Path matching with both `/` and `\` separators
- Case-insensitivity of Windows paths
- Environment variable expansion (`%VAR%`, `$env:VAR`, `~`)
- PowerShell command aliases (`ri`, `rm`, `del` all map to `Remove-Item`)
- CMD vs PowerShell command detection

---

## 9. Architecture Decision: Single vs Separate Config

**Option A: Single patterns.yaml with platform detection**
- Pro: One file to maintain
- Con: Gets large, harder to read

**Option B: Separate windows-patterns.yaml**
- Pro: Clean separation
- Con: Need to load/merge configs

**Recommendation**: Start with Option A (single file with clearly marked sections), split later if it becomes unwieldy.
