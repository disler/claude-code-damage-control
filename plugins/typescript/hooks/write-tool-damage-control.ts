/**
 * Claude Code Write Tool Damage Control
 * ======================================
 *
 * Blocks writes to protected files via PreToolUse hook on Write tool.
 * Loads protectedPaths from patterns.yaml.
 *
 * Features:
 * - Context-aware security (relaxes checks in documentation files)
 * - Audit logging with JSONL format
 * - Fire-and-forget log rotation
 *
 * Requires: bun add yaml
 *
 * Exit codes:
 *   0 = Allow write
 *   2 = Block write (stderr fed back to Claude)
 */

import { existsSync, readFileSync, mkdirSync, appendFileSync } from "fs";
import { dirname, join, basename, normalize, sep } from "path";
import { homedir } from "os";
import { parse as parseYaml } from "yaml";
import { spawn } from "child_process";

// =============================================================================
// TYPES
// =============================================================================

interface Config {
  zeroAccessPaths: string[];
  readOnlyPaths: string[];
  contexts?: {
    documentation?: {
      enabled: boolean;
      detection?: {
        file_extensions?: string[];
      };
      relaxed_checks?: string[];
    };
  };
}

interface HookInput {
  tool_name: string;
  tool_input: {
    file_path?: string;
  };
}

// =============================================================================
// AUDIT LOGGING
// =============================================================================

function getLogPath(): string {
  const logsDir = join(homedir(), ".claude", "logs", "damage-control");
  if (!existsSync(logsDir)) {
    mkdirSync(logsDir, { recursive: true });
  }

  const now = new Date();
  const dateStr = now.toISOString().split("T")[0];
  return join(logsDir, `${dateStr}.log`);
}

function logDecision(
  toolName: string,
  filePath: string,
  decision: string,
  reason: string = "",
  context: string | null = null
): void {
  try {
    const logPath = getLogPath();

    const filePathTruncated = filePath.length > 200 ? filePath.slice(0, 200) + "..." : filePath;

    const logEntry = {
      timestamp: new Date().toISOString(),
      tool: toolName,
      file_path: filePathTruncated,
      decision,
      reason,
      context,
      user: process.env.USER || "unknown",
      cwd: process.cwd(),
      session_id: process.env.CLAUDE_SESSION_ID || "",
    };

    appendFileSync(logPath, JSON.stringify(logEntry) + "\n");
  } catch (e) {
    console.error(`Warning: Failed to write audit log: ${e}`);
  }
}

function spawnLogRotation(): void {
  const rotateScript = join(dirname(Bun.main), "log_rotate.ts");
  if (!existsSync(rotateScript)) {
    return;
  }

  try {
    const child = spawn("bun", ["run", rotateScript], {
      detached: true,
      stdio: "ignore",
    });
    child.unref();
  } catch {
    // Don't crash hook if rotation fails to spawn
  }
}

// =============================================================================
// GLOB PATTERN UTILITIES
// =============================================================================

function isGlobPattern(pattern: string): boolean {
  return pattern.includes("*") || pattern.includes("?") || pattern.includes("[");
}

function matchGlob(str: string, pattern: string): boolean {
  const regexPattern = pattern
    .toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");

  try {
    const regex = new RegExp(`^${regexPattern}$`, "i");
    return regex.test(str.toLowerCase());
  } catch {
    return false;
  }
}

function matchPath(filePath: string, pattern: string): boolean {
  const expandedPattern = pattern.replace(/^~/, homedir());
  const normalized = normalize(filePath).replace(/^~/, homedir());

  if (isGlobPattern(pattern)) {
    const fileBasename = basename(normalized);
    if (matchGlob(fileBasename, expandedPattern) || matchGlob(fileBasename, pattern)) {
      return true;
    }
    if (matchGlob(normalized, expandedPattern)) {
      return true;
    }
    return false;
  } else {
    // Exact match or directory prefix matching
    // .env should NOT match .env.example (different files)
    // ~/.ssh/ SHOULD match ~/.ssh/id_rsa (directory contains file)
    const patternNoSlash = expandedPattern.replace(/\/$/, "");
    if (normalized === expandedPattern || normalized === patternNoSlash) {
      return true;
    }
    // Only prefix match if pattern is a directory (ends with /)
    if (expandedPattern.endsWith("/") && normalized.startsWith(expandedPattern)) {
      return true;
    }
    // Also match if path is inside the directory (pattern without trailing /)
    if (normalized.startsWith(patternNoSlash + "/") || normalized.startsWith(patternNoSlash + sep)) {
      return true;
    }
    return false;
  }
}

// =============================================================================
// CONFIGURATION
// =============================================================================

function getConfigPath(): string {
  const projectDir = process.env.CLAUDE_PROJECT_DIR;
  if (projectDir) {
    const projectConfig = join(projectDir, ".claude", "hooks", "damage-control", "patterns.yaml");
    if (existsSync(projectConfig)) {
      return projectConfig;
    }
  }

  const scriptDir = dirname(Bun.main);
  const localConfig = join(scriptDir, "patterns.yaml");
  if (existsSync(localConfig)) {
    return localConfig;
  }

  const skillRoot = join(scriptDir, "..", "..", "patterns.yaml");
  if (existsSync(skillRoot)) {
    return skillRoot;
  }

  return localConfig;
}

function loadConfig(): Config {
  const configPath = getConfigPath();

  if (!existsSync(configPath)) {
    return { zeroAccessPaths: [], readOnlyPaths: [] };
  }

  const content = readFileSync(configPath, "utf-8");
  const config = parseYaml(content) as Partial<Config>;

  return {
    zeroAccessPaths: config.zeroAccessPaths || [],
    readOnlyPaths: config.readOnlyPaths || [],
    contexts: config.contexts,
  };
}

// =============================================================================
// CONTEXT DETECTION
// =============================================================================

function detectContext(toolName: string, toolInput: { file_path?: string }, config: Config): string | null {
  const contextsConfig = config.contexts || {};

  if (toolName === "Edit" || toolName === "Write") {
    const docCtx = contextsConfig.documentation;
    if (docCtx?.enabled) {
      const filePath = toolInput.file_path || "";
      const extensions = docCtx.detection?.file_extensions || [];
      for (const ext of extensions) {
        if (filePath.endsWith(ext)) {
          return "documentation";
        }
      }
    }
  }

  return null;
}

// =============================================================================
// PATH CHECKING
// =============================================================================

function checkPath(
  filePath: string,
  config: Config,
  context: string | null = null
): { blocked: boolean; reason: string } {
  // Get relaxed checks for context
  const contextConfig = context ? (config.contexts as any)?.[context] : null;
  const relaxedChecks = new Set<string>(contextConfig?.relaxed_checks || []);

  // Check zero-access paths first
  if (!relaxedChecks.has("zeroAccessPaths")) {
    for (const zeroPath of config.zeroAccessPaths) {
      if (matchPath(filePath, zeroPath)) {
        return { blocked: true, reason: `zero-access path ${zeroPath} (no operations allowed)` };
      }
    }
  }

  // Check read-only paths
  if (!relaxedChecks.has("readOnlyPaths")) {
    for (const readonlyPath of config.readOnlyPaths) {
      if (matchPath(filePath, readonlyPath)) {
        return { blocked: true, reason: `read-only path ${readonlyPath}` };
      }
    }
  }

  return { blocked: false, reason: "" };
}

// =============================================================================
// MAIN
// =============================================================================

async function main(): Promise<void> {
  const config = loadConfig();

  let inputText = "";
  for await (const chunk of Bun.stdin.stream()) {
    inputText += new TextDecoder().decode(chunk);
  }

  let input: HookInput;
  try {
    input = JSON.parse(inputText);
  } catch (e) {
    console.error(`Error: Invalid JSON input: ${e}`);
    process.exit(1);
  }

  // Only check Write tool
  if (input.tool_name !== "Write") {
    process.exit(0);
  }

  const filePath = input.tool_input?.file_path || "";
  if (!filePath) {
    process.exit(0);
  }

  // Detect context
  const context = detectContext(input.tool_name, input.tool_input, config);

  // Check if file is blocked
  const { blocked, reason } = checkPath(filePath, config, context);

  // Log decision
  if (blocked) {
    logDecision("Write", filePath, "blocked", reason, context);
  } else {
    logDecision("Write", filePath, "allowed", "", context);
  }

  // Spawn log rotation
  spawnLogRotation();

  if (blocked) {
    console.error(`SECURITY: Blocked write to ${reason}: ${filePath}`);
    process.exit(2);
  }

  process.exit(0);
}

main().catch((e) => {
  console.error(`Hook error: ${e}`);
  process.exit(0);
});
