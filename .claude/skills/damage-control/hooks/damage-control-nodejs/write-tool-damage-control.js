#!/usr/bin/env node
/**
 * Claude Code Write Tool Damage Control - Node.js Implementation
 * ===============================================================
 *
 * Blocks writes to protected files via PreToolUse hook on Write tool.
 * Loads protectedPaths from patterns.yaml.
 *
 * IMPORTANT: Uses async stdin reading for Windows compatibility.
 *
 * Requires: npm install yaml
 *
 * Exit codes:
 *   0 = Allow write
 *   2 = Block write (stderr fed back to Claude)
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const yaml = require("yaml");

function isGlobPattern(pattern) {
  return pattern.includes('*') || pattern.includes('?') || pattern.includes('[');
}

function matchGlob(str, pattern) {
  // Convert glob pattern to regex (case-insensitive for security)
  const regexPattern = pattern.toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape special regex chars
    .replace(/\*/g, '.*')                   // * matches anything
    .replace(/\?/g, '.');                   // ? matches single char

  try {
    const regex = new RegExp(`^${regexPattern}$`, 'i');
    return regex.test(str.toLowerCase());
  } catch {
    return false;
  }
}

function matchPath(filePath, pattern) {
  const expandedPattern = pattern.replace(/^~/, os.homedir());
  const normalized = filePath.replace(/^~/, os.homedir());

  if (isGlobPattern(pattern)) {
    // Glob pattern matching (case-insensitive for security)
    const fileBasename = path.basename(normalized);
    if (matchGlob(fileBasename, expandedPattern) || matchGlob(fileBasename, pattern)) {
      return true;
    }
    // Also try full path match
    if (matchGlob(normalized, expandedPattern)) {
      return true;
    }
    return false;
  } else {
    // Prefix matching (original behavior for directories)
    if (normalized.startsWith(expandedPattern) || normalized === expandedPattern.replace(/\/$/, "")) {
      return true;
    }
    return false;
  }
}

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
    return { zeroAccessPaths: [], readOnlyPaths: [] };
  }

  const content = fs.readFileSync(configPath, "utf-8");
  const config = yaml.parse(content) || {};

  return {
    zeroAccessPaths: config.zeroAccessPaths || [],
    readOnlyPaths: config.readOnlyPaths || [],
  };
}

function checkPath(filePath, config) {
  // Check zero-access paths first
  for (const zeroPath of config.zeroAccessPaths) {
    if (matchPath(filePath, zeroPath)) {
      return { blocked: true, reason: `zero-access path ${zeroPath} (no operations allowed)` };
    }
  }

  // Check read-only paths
  for (const readonlyPath of config.readOnlyPaths) {
    if (matchPath(filePath, readonlyPath)) {
      return { blocked: true, reason: `read-only path ${readonlyPath}` };
    }
  }

  return { blocked: false, reason: "" };
}

// =============================================================================
// MAIN - ASYNC STDIN READING (WINDOWS COMPATIBLE)
// =============================================================================

function main() {
  const config = loadConfig();
  let input = "";

  // CRITICAL: Use async stdin reading for Windows compatibility
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
    console.error(`Stdin error: ${err.message}`);
    process.exit(0); // Fail open
  });
}

function processInput(inputText, config) {
  let input;
  try {
    input = JSON.parse(inputText);
  } catch (e) {
    console.error(`Error: Invalid JSON input: ${e}`);
    process.exit(1);
  }

  if (input.tool_name !== "Write") {
    process.exit(0);
  }

  const filePath = input.tool_input?.file_path || "";
  if (!filePath) {
    process.exit(0);
  }

  const { blocked, reason } = checkPath(filePath, config);

  if (blocked) {
    console.error(`SECURITY: Blocked write to ${reason}`);
    console.error(`File: ${filePath}`);
    process.exit(2);
  } else {
    process.exit(0);
  }
}

main();
