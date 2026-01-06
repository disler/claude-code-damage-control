# Damage Control - Node.js Implementation

## Windows Compatibility Fix

This implementation addresses [Issue #1](https://github.com/paulrobello/claude-code-damage-control/issues/1) - Windows compatibility for stdin reading.

### The Problem

The synchronous file descriptor approach to reading stdin does NOT work on Windows:

```javascript
// ❌ BROKEN ON WINDOWS
const fd = fs.openSync(0, 'r');
while ((bytesRead = fs.readSync(fd, buf, 0, BUFSIZE)) > 0) {
  input += buf.toString('utf8', 0, bytesRead);
}
```

This pattern throws an error on Windows:
```
The "path" argument must be of type string or an instance of Buffer or URL. Received type number (0)
```

When this fails silently, the hook receives empty input and approves ALL commands - **effectively disabling all damage control protection on Windows**.

### The Solution

Use async stdin reading with `process.stdin`:

```javascript
// ✅ WORKS ON WINDOWS (and Unix)
function main() {
  let input = "";

  process.stdin.setEncoding("utf8");
  process.stdin.on("readable", () => {
    let chunk;
    while ((chunk = process.stdin.read()) !== null) {
      input += chunk;
    }
  });
  process.stdin.on("end", () => {
    processInput(input);
  });
  process.stdin.on("error", () => {
    // Handle no stdin gracefully
    process.exit(0);
  });
}
```

This pattern works cross-platform on:
- Windows 11
- macOS
- Linux

## Installation

### 1. Install Dependencies

```bash
cd .claude/skills/damage-control/hooks/damage-control-nodejs
npm install
```

### 2. Copy Hooks to Your Project

```bash
cd /path/to/your/project
mkdir -p .claude/hooks/damage-control
cp .claude/skills/damage-control/hooks/damage-control-nodejs/*.js .claude/hooks/damage-control/
cp .claude/skills/damage-control/hooks/damage-control-nodejs/package.json .claude/hooks/damage-control/
cp .claude/skills/damage-control/patterns.yaml .claude/hooks/damage-control/

# Install dependencies in the hooks directory
cd .claude/hooks/damage-control
npm install
```

### 3. Configure Settings

Copy the Node.js settings to your settings file:

```bash
cp .claude/skills/damage-control/hooks/damage-control-nodejs/nodejs-settings.json .claude/settings.local.json
```

Or manually add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "node \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/damage-control/bash-tool-damage-control.js",
          "timeout": 5
        }]
      },
      {
        "matcher": "Edit",
        "hooks": [{
          "type": "command",
          "command": "node \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/damage-control/edit-tool-damage-control.js",
          "timeout": 5
        }]
      },
      {
        "matcher": "Write",
        "hooks": [{
          "type": "command",
          "command": "node \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/damage-control/write-tool-damage-control.js",
          "timeout": 5
        }]
      }
    ]
  }
}
```

### 4. Make Scripts Executable (Unix/macOS)

```bash
chmod +x .claude/hooks/damage-control/*.js
```

### 5. Test

Test that the hooks work:

```bash
# Should be blocked
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | node .claude/hooks/damage-control/bash-tool-damage-control.js

# Should be allowed
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | node .claude/hooks/damage-control/bash-tool-damage-control.js
```

## Comparison with Other Implementations

| Implementation | Runtime | Stdin Method | Windows Support |
|---------------|---------|--------------|-----------------|
| **Python/UV** | UV (Python) | `sys.stdin` (built-in) | ✅ Yes |
| **TypeScript/Bun** | Bun | `Bun.stdin.stream()` | ✅ Yes |
| **Node.js** | Node.js | `process.stdin` (async) | ✅ Yes |

## Requirements

- Node.js >= 14.0.0
- npm (for dependency management)

## Files

- `bash-tool-damage-control.js` - Bash tool hook
- `edit-tool-damage-control.js` - Edit tool hook
- `write-tool-damage-control.js` - Write tool hook
- `package.json` - Dependencies
- `nodejs-settings.json` - Settings template
- `README.md` - This file

## Credits

Issue reported by: [@TC407-api](https://github.com/TC407-api)
