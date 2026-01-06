#!/usr/bin/env node
/**
 * Claude Code Security Firewall - Node.js Implementation
 * =======================================================
 *
 * Blocks dangerous commands before execution via PreToolUse hook.
 * Loads patterns from patterns.yaml for easy customization.
 *
 * IMPORTANT: Uses async stdin reading for Windows compatibility.
 * The synchronous fs.openSync(0, 'r') pattern does NOT work on Windows.
 *
 * Requires: npm install yaml
 *
 * Exit codes:
 *   0 = Allow command (or JSON output with permissionDecision)
 *   2 = Block command (stderr fed back to Claude)
 *
 * JSON output for ask patterns:
 *   {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "..."}}
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const yaml = require("yaml");

// =============================================================================
// GLOB PATTERN UTILITIES
// =============================================================================

function isGlobPattern(pattern) {
  return pattern.includes('*') || pattern.includes('?') || pattern.includes('[');
}

function globToRegex(globPattern) {
  // Convert glob pattern to regex for matching in commands
  let result = "";
  for (const char of globPattern) {
    if (char === '*') {
      result += '[^\\s/]*';  // Match any chars except whitespace and path sep
    } else if (char === '?') {
      result += '[^\\s/]';   // Match single char except whitespace and path sep
    } else if ('.+^${}()|[]\\'.includes(char)) {
      result += '\\' + char;
    } else {
      result += char;
    }
  }
  return result;
}

// =============================================================================
// OPERATION PATTERNS - Edit these to customize what operations are blocked
// =============================================================================
// {path} will be replaced with the escaped path at runtime

// Operations blocked for READ-ONLY paths (all modifications)
const WRITE_PATTERNS = [
  [">\\s*{path}", "write"],
  ["\\btee\\s+(?!.*-a).*{path}", "write"],
];

const APPEND_PATTERNS = [
  [">>\\s*{path}", "append"],
  ["\\btee\\s+-a\\s+.*{path}", "append"],
  ["\\btee\\s+.*-a.*{path}", "append"],
];

const EDIT_PATTERNS = [
  ["\\bsed\\s+-i.*{path}", "edit"],
  ["\\bperl\\s+-[^\\s]*i.*{path}", "edit"],
  ["\\bawk\\s+-i\\s+inplace.*{path}", "edit"],
];

const MOVE_COPY_PATTERNS = [
  ["\\bmv\\s+.*\\s+{path}", "move"],
  ["\\bcp\\s+.*\\s+{path}", "copy"],
];

const DELETE_PATTERNS = [
  ["\\brm\\s+.*{path}", "delete"],
  ["\\bunlink\\s+.*{path}", "delete"],
  ["\\brmdir\\s+.*{path}", "delete"],
  ["\\bshred\\s+.*{path}", "delete"],
];

const PERMISSION_PATTERNS = [
  ["\\bchmod\\s+.*{path}", "chmod"],
  ["\\bchown\\s+.*{path}", "chown"],
  ["\\bchgrp\\s+.*{path}", "chgrp"],
];

const TRUNCATE_PATTERNS = [
  ["\\btruncate\\s+.*{path}", "truncate"],
  [":\\s*>\\s*{path}", "truncate"],
];

// Combined patterns for read-only paths (block ALL modifications)
const READ_ONLY_BLOCKED = [
  ...WRITE_PATTERNS,
  ...APPEND_PATTERNS,
  ...EDIT_PATTERNS,
  ...MOVE_COPY_PATTERNS,
  ...DELETE_PATTERNS,
  ...PERMISSION_PATTERNS,
  ...TRUNCATE_PATTERNS,
];

// Patterns for no-delete paths (block ONLY delete operations)
const NO_DELETE_BLOCKED = DELETE_PATTERNS;

// =============================================================================
// CONFIGURATION
// =============================================================================

function getConfigPath() {
  // 1. Check project hooks directory (installed location)
  const projectDir = process.env.CLAUDE_PROJECT_DIR;
  if (projectDir) {
    const projectConfig = path.join(projectDir, ".claude", "hooks", "damage-control", "patterns.yaml");
    if (fs.existsSync(projectConfig)) {
      return projectConfig;
    }
  }

  // 2. Check script's own directory (installed location)
  const scriptDir = __dirname;
  const localConfig = path.join(scriptDir, "patterns.yaml");
  if (fs.existsSync(localConfig)) {
    return localConfig;
  }

  // 3. Check skill root directory (development location)
  const skillRoot = path.join(scriptDir, "..", "..", "patterns.yaml");
  if (fs.existsSync(skillRoot)) {
    return skillRoot;
  }

  return localConfig; // Default, even if it doesn't exist
}

function loadConfig() {
  const configPath = getConfigPath();

  if (!fs.existsSync(configPath)) {
    console.error(`Warning: Config not found at ${configPath}`);
    return { bashToolPatterns: [], zeroAccessPaths: [], readOnlyPaths: [], noDeletePaths: [] };
  }

  const content = fs.readFileSync(configPath, "utf-8");
  const config = yaml.parse(content) || {};

  return {
    bashToolPatterns: config.bashToolPatterns || [],
    zeroAccessPaths: config.zeroAccessPaths || [],
    readOnlyPaths: config.readOnlyPaths || [],
    noDeletePaths: config.noDeletePaths || [],
  };
}

// =============================================================================
// PATH CHECKING
// =============================================================================

function checkPathPatterns(command, pathPattern, patterns, pathType) {
  /**
   * Supports both:
   * - Literal paths: ~/.bashrc, /etc/hosts (prefix matching)
   * - Glob patterns: *.lock, *.md, src/* (glob matching)
   */
  if (isGlobPattern(pathPattern)) {
    // Glob pattern - convert to regex for command matching
    const globRegex = globToRegex(pathPattern);
    for (const [patternTemplate, operation] of patterns) {
      try {
        // Build a regex that matches: operation ... glob_pattern
        const cmdPrefix = patternTemplate.replace("{path}", "");
        if (cmdPrefix) {
          const regex = new RegExp(cmdPrefix + globRegex, "i");
          if (regex.test(command)) {
            return {
              blocked: true,
              reason: `Blocked: ${operation} operation on ${pathType} ${pathPattern}`,
            };
          }
        }
      } catch {
        continue;
      }
    }
  } else {
    // Original literal path matching (prefix-based)
    const expanded = pathPattern.replace(/^~/, os.homedir());
    const escapedExpanded = expanded.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const escapedOriginal = pathPattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    for (const [patternTemplate, operation] of patterns) {
      // Check both expanded path (/Users/x/.ssh/) and original tilde form (~/.ssh/)
      const patternExpanded = patternTemplate.replace("{path}", escapedExpanded);
      const patternOriginal = patternTemplate.replace("{path}", escapedOriginal);
      try {
        const regexExpanded = new RegExp(patternExpanded);
        const regexOriginal = new RegExp(patternOriginal);
        if (regexExpanded.test(command) || regexOriginal.test(command)) {
          return {
            blocked: true,
            reason: `Blocked: ${operation} operation on ${pathType} ${pathPattern}`,
          };
        }
      } catch {
        continue;
      }
    }
  }

  return { blocked: false, reason: "" };
}

function checkCommand(command, config) {
  // 1. Check against patterns from YAML (may block or ask)
  for (const { pattern, reason, ask: shouldAsk } of config.bashToolPatterns) {
    try {
      const regex = new RegExp(pattern, "i");
      if (regex.test(command)) {
        if (shouldAsk) {
          return { blocked: false, ask: true, reason }; // Ask for confirmation
        } else {
          return { blocked: true, ask: false, reason: `Blocked: ${reason}` }; // Block
        }
      }
    } catch {
      continue;
    }
  }

  // 2. Check for ANY access to zero-access paths (including reads)
  for (const zeroPath of config.zeroAccessPaths) {
    if (isGlobPattern(zeroPath)) {
      // Convert glob to regex for command matching
      const globRegex = globToRegex(zeroPath);
      try {
        const regex = new RegExp(globRegex, 'i');
        if (regex.test(command)) {
          return {
            blocked: true,
            ask: false,
            reason: `Blocked: zero-access pattern ${zeroPath} (no operations allowed)`,
          };
        }
      } catch {
        continue;
      }
    } else {
      // Original literal path matching
      const expanded = zeroPath.replace(/^~/, os.homedir());
      // Check both expanded path (/Users/x/.ssh/) and original tilde form (~/.ssh/)
      if (command.includes(expanded) || command.includes(zeroPath)) {
        return {
          blocked: true,
          ask: false,
          reason: `Blocked: zero-access path ${zeroPath} (no operations allowed)`,
        };
      }
    }
  }

  // 3. Check for modifications to read-only paths (reads allowed)
  for (const readonlyPath of config.readOnlyPaths) {
    const result = checkPathPatterns(command, readonlyPath, READ_ONLY_BLOCKED, "read-only path");
    if (result.blocked) {
      return { ...result, ask: false };
    }
  }

  // 4. Check for deletions on no-delete paths (read/write/edit allowed)
  for (const noDeletePath of config.noDeletePaths) {
    const result = checkPathPatterns(command, noDeletePath, NO_DELETE_BLOCKED, "no-delete path");
    if (result.blocked) {
      return { ...result, ask: false };
    }
  }

  return { blocked: false, ask: false, reason: "" };
}

// =============================================================================
// MAIN - ASYNC STDIN READING (WINDOWS COMPATIBLE)
// =============================================================================

function main() {
  const config = loadConfig();
  let input = "";

  // CRITICAL: Use async stdin reading for Windows compatibility
  // DO NOT use fs.openSync(0, 'r') - it fails on Windows
  process.stdin.setEncoding("utf8");

  process.stdin.on("readable", () => {
    let chunk;
    while ((chunk = process.stdin.read()) !== null) {
      input += chunk;
    }
  });

  process.stdin.on("end", () => {
    processInput(input, config);
  });

  process.stdin.on("error", (err) => {
    // Handle no stdin gracefully
    console.error(`Stdin error: ${err.message}`);
    process.exit(0); // Fail open
  });
}

function processInput(inputText, config) {
  // Parse input
  let input;
  try {
    input = JSON.parse(inputText);
  } catch (e) {
    console.error(`Error: Invalid JSON input: ${e}`);
    process.exit(1);
  }

  // Only check Bash commands
  if (input.tool_name !== "Bash") {
    process.exit(0);
  }

  const command = input.tool_input?.command || "";
  if (!command) {
    process.exit(0);
  }

  // Check the command
  const { blocked, ask, reason } = checkCommand(command, config);

  if (blocked) {
    console.error(`SECURITY: ${reason}`);
    console.error(
      `Command: ${command.slice(0, 100)}${command.length > 100 ? "..." : ""}`
    );
    process.exit(2);
  } else if (ask) {
    // Output JSON to trigger confirmation dialog
    const output = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: reason,
      },
    };
    console.log(JSON.stringify(output));
    process.exit(0);
  } else {
    process.exit(0);
  }
}

// Start the main function
main();
