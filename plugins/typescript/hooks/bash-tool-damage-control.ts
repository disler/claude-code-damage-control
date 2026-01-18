/**
 * Claude Code Security Firewall - Bun/TypeScript Implementation
 * ==============================================================
 *
 * Blocks dangerous commands before execution via PreToolUse hook.
 * Loads patterns from patterns.yaml for easy customization.
 *
 * Features:
 * - Configuration caching with pre-compiled regex patterns
 * - Shell wrapper unwrapping (bash -c, python -c, etc.)
 * - Semantic git analysis (distinguishes safe vs dangerous git operations)
 * - Context-aware security (relaxes checks in documentation/commit contexts)
 * - Audit logging with automatic secret redaction
 * - Fire-and-forget log rotation
 *
 * Requires: bun add yaml
 *
 * Exit codes:
 *   0 = Allow command (or JSON output with permissionDecision)
 *   2 = Block command (stderr fed back to Claude)
 *
 * Environment variables:
 *   CLAUDE_DISABLE_HOOKS - Comma-separated list of hook names to disable
 *                          Use "damage-control" to disable this hook
 *
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │ WARNING FOR AI ASSISTANTS (Claude, Copilot, etc.):                  │
 *   │                                                                     │
 *   │ CLAUDE_DISABLE_HOOKS is for HOOK DEVELOPMENT ONLY.                  │
 *   │                                                                     │
 *   │ You may ONLY use this variable when ALL conditions are met:         │
 *   │   1. You are directly modifying THIS hook's code                    │
 *   │   2. Working directory is ~/.dotfiles OR ~/.claude                  │
 *   │   3. The hook is blocking edits to itself (circular dependency)     │
 *   │                                                                     │
 *   │ NEVER use this to bypass security checks during normal work.        │
 *   │ If a hook blocks an operation, FIX THE ISSUE instead of disabling.  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * JSON output for ask patterns:
 *   {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "..."}}
 */

import { existsSync, readFileSync, mkdirSync, appendFileSync } from "fs";
import { dirname, join } from "path";
import { homedir } from "os";
import { parse as parseYaml } from "yaml";
import { spawn } from "child_process";

const HOOK_NAME = "damage-control";

function isHookDisabled(): boolean {
  const disabledHooks = process.env.CLAUDE_DISABLE_HOOKS || "";
  return disabledHooks.split(",").map(h => h.trim()).includes(HOOK_NAME);
}
// =============================================================================
// TYPES
// =============================================================================

interface Pattern {
  pattern: string;
  reason: string;
  ask?: boolean;
}

interface CompiledPattern {
  pattern: string;
  reason: string;
  ask?: boolean;
  compiled: RegExp;
}

interface PathObject {
  original: string;
  isGlob: boolean;
  globRegex?: RegExp;
  expanded?: string;
  escapedExpanded?: string;
  escapedOriginal?: string;
}

interface Config {
  bashToolPatterns: Pattern[];
  zeroAccessPaths: string[];
  readOnlyPaths: string[];
  noDeletePaths: string[];
  contexts?: {
    documentation?: {
      enabled: boolean;
      detection?: {
        file_extensions?: string[];
      };
      relaxed_checks?: string[];
    };
    commit_message?: {
      enabled: boolean;
      detection?: {
        command_patterns?: string[];
      };
      relaxed_checks?: string[];
    };
  };
}

interface CompiledConfig extends Config {
  bashToolPatterns_compiled: CompiledPattern[];
  zeroAccessPaths_compiled: PathObject[];
  readOnlyPaths_compiled: PathObject[];
  noDeletePaths_compiled: PathObject[];
}

interface HookInput {
  tool_name: string;
  tool_input: {
    command?: string;
    file_path?: string;
    [key: string]: unknown;
  };
}

interface CheckResult {
  blocked: boolean;
  ask: boolean;
  reason: string;
  patternMatched: string;
  wasUnwrapped: boolean;
  semanticMatch: boolean;
}

// =============================================================================
// GLOB PATTERN UTILITIES
// =============================================================================

function isGlobPattern(pattern: string): boolean {
  return pattern.includes("*") || pattern.includes("?") || pattern.includes("[");
}

function globToRegex(globPattern: string): string {
  let result = "";
  for (const char of globPattern) {
    if (char === "*") {
      result += "[^\\s/]*";
    } else if (char === "?") {
      result += "[^\\s/]";
    } else if (".+^${}()|[]\\".includes(char)) {
      result += "\\" + char;
    } else {
      result += char;
    }
  }
  return result;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// =============================================================================
// OPERATION PATTERNS
// =============================================================================

type PatternTuple = [string, string];

const WRITE_PATTERNS: PatternTuple[] = [
  [">\\s*{path}", "write"],
  ["\\btee\\s+(?!.*-a).*{path}", "write"],
];

const APPEND_PATTERNS: PatternTuple[] = [
  [">>\\s*{path}", "append"],
  ["\\btee\\s+-a\\s+.*{path}", "append"],
  ["\\btee\\s+.*-a.*{path}", "append"],
];

const EDIT_PATTERNS: PatternTuple[] = [
  ["\\bsed\\s+-i.*{path}", "edit"],
  ["\\bperl\\s+-[^\\s]*i.*{path}", "edit"],
  ["\\bawk\\s+-i\\s+inplace.*{path}", "edit"],
];

const MOVE_COPY_PATTERNS: PatternTuple[] = [
  ["\\bmv\\s+.*\\s+{path}", "move"],
  ["\\bcp\\s+.*\\s+{path}", "copy"],
];

const DELETE_PATTERNS: PatternTuple[] = [
  ["\\brm\\s+.*{path}", "delete"],
  ["\\bunlink\\s+.*{path}", "delete"],
  ["\\brmdir\\s+.*{path}", "delete"],
  ["\\bshred\\s+.*{path}", "delete"],
];

const PERMISSION_PATTERNS: PatternTuple[] = [
  ["\\bchmod\\s+.*{path}", "chmod"],
  ["\\bchown\\s+.*{path}", "chown"],
  ["\\bchgrp\\s+.*{path}", "chgrp"],
];

const TRUNCATE_PATTERNS: PatternTuple[] = [
  ["\\btruncate\\s+.*{path}", "truncate"],
  [":\\s*>\\s*{path}", "truncate"],
];

const READ_ONLY_BLOCKED: PatternTuple[] = [
  ...WRITE_PATTERNS,
  ...APPEND_PATTERNS,
  ...EDIT_PATTERNS,
  ...MOVE_COPY_PATTERNS,
  ...DELETE_PATTERNS,
  ...PERMISSION_PATTERNS,
  ...TRUNCATE_PATTERNS,
];

const NO_DELETE_BLOCKED: PatternTuple[] = DELETE_PATTERNS;

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

function redactSecrets(command: string): string {
  let redacted = command;

  const patterns: [RegExp, string][] = [
    [/apikey\s*=\s*[\w\-\.]+/gi, "***REDACTED***"],
    [/api_key\s*=\s*[\w\-\.]+/gi, "***REDACTED***"],
    [/token\s*=\s*[\w\-\.]{20,}/gi, "***REDACTED***"],
    [/bearer\s+[\w\-\.]+/gi, "***REDACTED***"],
    [/password\s*=\s*\S+/gi, "***REDACTED***"],
    [/passwd\s*=\s*\S+/gi, "***REDACTED***"],
    [/pwd\s*=\s*\S+/gi, "***REDACTED***"],
    [/-p\S+/g, "***REDACTED***"],
    [/AKIA[0-9A-Z]{16}/g, "***REDACTED***"],
    [/secret\s*=\s*\S+/gi, "***REDACTED***"],
    [/credential\s*=\s*\S+/gi, "***REDACTED***"],
    [/GITHUB_TOKEN\s*=\s*\S+/gi, "***REDACTED***"],
    [/NPM_TOKEN\s*=\s*\S+/gi, "***REDACTED***"],
    [/DOCKER_PASSWORD\s*=\s*\S+/gi, "***REDACTED***"],
  ];

  for (const [pattern] of patterns) {
    redacted = redacted.replace(pattern, "***REDACTED***");
  }

  return redacted;
}

function logDecision(
  toolName: string,
  command: string,
  decision: string,
  reason: string,
  patternMatched: string = "",
  unwrapped: boolean = false,
  semanticMatch: boolean = false,
  context: string | null = null
): void {
  try {
    const logPath = getLogPath();

    const commandTruncated = command.length > 200 ? command.slice(0, 200) + "..." : command;
    const commandRedacted = redactSecrets(command);
    const commandRedactedTruncated =
      commandRedacted.length > 200 ? commandRedacted.slice(0, 200) + "..." : commandRedacted;

    const logEntry = {
      timestamp: new Date().toISOString(),
      tool: toolName,
      command: commandTruncated,
      command_redacted: commandRedactedTruncated,
      decision,
      reason,
      pattern_matched: patternMatched,
      user: process.env.USER || "unknown",
      cwd: process.cwd(),
      session_id: process.env.CLAUDE_SESSION_ID || "",
      unwrapped,
      semantic_match: semanticMatch,
      context,
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
// SHELL WRAPPER UNWRAPPING
// =============================================================================

function extractSystemCall(pythonCode: string): string | null {
  if (!pythonCode) return null;

  const systemPatterns = [
    /os\.system\s*\(\s*["']([^"']+)["']\s*\)/,
    /subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*["']([^"']+)["']\s*\)/,
  ];

  for (const pattern of systemPatterns) {
    const match = pythonCode.match(pattern);
    if (match) {
      return match[1];
    }
  }

  const listPattern = /subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*\[([^\]]+)\]/;
  const match = pythonCode.match(listPattern);
  if (match) {
    const listContents = match[1];
    const parts = listContents.match(/["']([^"']+)["']/g);
    if (parts) {
      return parts.map((p) => p.slice(1, -1)).join(" ");
    }
  }

  return null;
}

function unwrapCommand(command: string, depth: number = 0): [string, boolean] {
  if (depth >= 5) {
    return [command, depth > 0];
  }

  if (!command || !command.trim()) {
    return [command, false];
  }

  command = command.trim();

  // Shell wrappers: bash -c "command", sh -c 'command', etc.
  const shellWrappers = ["bash", "sh", "zsh", "ksh", "dash"];
  for (const shell of shellWrappers) {
    const pattern = new RegExp(`\\b${shell}\\s+-c\\s+(["'])(.+?)\\1`);
    const match = command.match(pattern);
    if (match) {
      return unwrapCommand(match[2], depth + 1);
    }
  }

  // Python wrappers: python -c "code"
  const pythonWrappers = ["python", "python2", "python3"];
  for (const pythonCmd of pythonWrappers) {
    const pattern = new RegExp(`\\b${pythonCmd}\\s+-c\\s+(["'])(.+?)\\1`);
    const match = command.match(pattern);
    if (match) {
      const pythonCode = match[2];
      const extracted = extractSystemCall(pythonCode);
      if (extracted) {
        return unwrapCommand(extracted, depth + 1);
      }
      return unwrapCommand(pythonCode, depth + 1);
    }
  }

  // Env wrappers: env VAR=val command
  const envPattern = /\benv\s+(?:[A-Z_][A-Z0-9_]*=[^\s]+\s+)*(.+)/;
  const envMatch = command.match(envPattern);
  if (envMatch) {
    return unwrapCommand(envMatch[1], depth + 1);
  }

  return [command, depth > 0];
}

// =============================================================================
// GIT SEMANTIC ANALYSIS
// =============================================================================

function analyzeGitCommand(command: string): [boolean, string] {
  if (!command || !command.trim()) {
    return [false, ""];
  }

  command = command.trim();

  if (!command.startsWith("git ")) {
    return [false, ""];
  }

  const parts = command.split(/\s+/);
  if (parts.length < 2) {
    return [false, ""];
  }

  const subcommand = parts[1];
  const args = parts.slice(2);
  const argsStr = args.join(" ");

  // GIT CHECKOUT
  if (subcommand === "checkout") {
    if (args.includes("-b") || args.includes("--branch")) {
      return [false, ""];
    }

    if (args.includes("--")) {
      const dashIdx = args.indexOf("--");
      if (dashIdx < args.length - 1) {
        return [true, "git checkout with -- discards uncommitted changes"];
      }
    }

    if (args.includes("--force") || args.includes("-f")) {
      return [true, "git checkout --force discards uncommitted changes"];
    }

    for (const arg of args) {
      if (arg.startsWith("-") && !arg.startsWith("--") && arg.length > 1) {
        if (arg.slice(1).includes("f")) {
          return [true, "git checkout -f discards uncommitted changes"];
        }
      }
    }
  }

  // GIT PUSH
  if (subcommand === "push") {
    if (argsStr.includes("--force-with-lease")) {
      return [false, ""];
    }

    if (args.includes("--force")) {
      return [true, "git push --force can overwrite remote history without safety checks"];
    }

    if (args.includes("-f")) {
      return [true, "git push -f can overwrite remote history without safety checks"];
    }

    for (const arg of args) {
      if (arg.startsWith("-") && !arg.startsWith("--") && arg.length > 1) {
        if (arg.slice(1).includes("f")) {
          return [true, "git push -f can overwrite remote history without safety checks"];
        }
      }
    }
  }

  // GIT RESET
  if (subcommand === "reset") {
    if (args.includes("--soft") || args.includes("--mixed")) {
      return [false, ""];
    }

    if (args.includes("--hard")) {
      return [true, "git reset --hard permanently discards uncommitted changes"];
    }
  }

  // GIT CLEAN
  if (subcommand === "clean") {
    if (args.includes("-f") || args.includes("-d")) {
      return [true, "git clean removes untracked files permanently"];
    }

    for (const arg of args) {
      if (arg.startsWith("-") && !arg.startsWith("--") && arg.length > 1) {
        if (arg.slice(1).includes("f") || arg.slice(1).includes("d")) {
          return [true, "git clean removes untracked files permanently"];
        }
      }
    }
  }

  return [false, ""];
}

// =============================================================================
// CONFIGURATION
// =============================================================================

let _compiledConfigCache: CompiledConfig | null = null;

function compileRegexPatterns(patterns: Pattern[]): CompiledPattern[] {
  const compiled: CompiledPattern[] = [];

  for (let idx = 0; idx < patterns.length; idx++) {
    const item = patterns[idx];
    const pattern = item.pattern;
    if (!pattern) continue;

    try {
      const compiledRegex = new RegExp(pattern, "i");
      compiled.push({
        ...item,
        compiled: compiledRegex,
      });
    } catch (e) {
      console.error(`Warning: Invalid regex pattern at index ${idx}: ${pattern} - ${e}`);
    }
  }

  return compiled;
}

function preprocessPathList(paths: string[]): PathObject[] {
  const processed: PathObject[] = [];

  for (const path of paths) {
    if (!path) continue;

    const pathObj: PathObject = {
      original: path,
      isGlob: isGlobPattern(path),
    };

    if (pathObj.isGlob) {
      try {
        const globRegexStr = globToRegex(path);
        pathObj.globRegex = new RegExp(globRegexStr, "i");
      } catch (e) {
        console.error(`Warning: Invalid glob pattern: ${path} - ${e}`);
        continue;
      }
    } else {
      try {
        const expanded = path.replace(/^~/, homedir());
        pathObj.expanded = expanded;
        pathObj.escapedExpanded = escapeRegex(expanded);
        pathObj.escapedOriginal = escapeRegex(path);
      } catch (e) {
        console.error(`Warning: Failed to process path: ${path} - ${e}`);
        continue;
      }
    }

    processed.push(pathObj);
  }

  return processed;
}

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
    console.error(`Warning: Config not found at ${configPath}`);
    return {
      bashToolPatterns: [],
      zeroAccessPaths: [],
      readOnlyPaths: [],
      noDeletePaths: [],
    };
  }

  const content = readFileSync(configPath, "utf-8");
  const config = parseYaml(content) as Partial<Config>;

  return {
    bashToolPatterns: config.bashToolPatterns || [],
    zeroAccessPaths: config.zeroAccessPaths || [],
    readOnlyPaths: config.readOnlyPaths || [],
    noDeletePaths: config.noDeletePaths || [],
    contexts: config.contexts,
  };
}

function compileConfig(config: Config): CompiledConfig {
  return {
    ...config,
    bashToolPatterns_compiled: compileRegexPatterns(config.bashToolPatterns),
    zeroAccessPaths_compiled: preprocessPathList(config.zeroAccessPaths),
    readOnlyPaths_compiled: preprocessPathList(config.readOnlyPaths),
    noDeletePaths_compiled: preprocessPathList(config.noDeletePaths),
  };
}

function getCompiledConfig(): CompiledConfig {
  if (_compiledConfigCache === null) {
    const rawConfig = loadConfig();
    _compiledConfigCache = compileConfig(rawConfig);
  }
  return _compiledConfigCache;
}

// =============================================================================
// CONTEXT DETECTION
// =============================================================================

function detectContext(
  toolName: string,
  toolInput: { command?: string; file_path?: string },
  config: Config
): string | null {
  const contextsConfig = config.contexts || {};

  // Documentation context for Edit/Write tools
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

  // Commit message context for Bash tool
  if (toolName === "Bash") {
    const commitCtx = contextsConfig.commit_message;
    if (commitCtx?.enabled) {
      const command = toolInput.command || "";
      const patterns = commitCtx.detection?.command_patterns || [];
      for (const pattern of patterns) {
        try {
          if (new RegExp(pattern, "i").test(command)) {
            return "commit_message";
          }
        } catch {
          continue;
        }
      }
    }
  }

  return null;
}

// =============================================================================
// PATH CHECKING
// =============================================================================

function checkPathPatterns(
  command: string,
  pathObj: PathObject,
  patterns: PatternTuple[],
  pathType: string
): { blocked: boolean; reason: string } {
  const pathStr = pathObj.original;

  if (pathObj.isGlob) {
    const globRegex = pathObj.globRegex;
    if (!globRegex) {
      return { blocked: false, reason: "" };
    }

    const globRegexStr = globRegex.source;

    for (const [patternTemplate, operation] of patterns) {
      try {
        const cmdPrefix = patternTemplate.replace("{path}", "");
        if (cmdPrefix && new RegExp(cmdPrefix + globRegexStr, "i").test(command)) {
          return {
            blocked: true,
            reason: `Blocked: ${operation} operation on ${pathType} ${pathStr}`,
          };
        }
      } catch {
        continue;
      }
    }
  } else {
    const escapedExpanded = pathObj.escapedExpanded || "";
    const escapedOriginal = pathObj.escapedOriginal || "";

    if (!escapedExpanded || !escapedOriginal) {
      return { blocked: false, reason: "" };
    }

    for (const [patternTemplate, operation] of patterns) {
      const patternExpanded = patternTemplate.replace("{path}", escapedExpanded);
      const patternOriginal = patternTemplate.replace("{path}", escapedOriginal);
      try {
        if (new RegExp(patternExpanded).test(command) || new RegExp(patternOriginal).test(command)) {
          return {
            blocked: true,
            reason: `Blocked: ${operation} operation on ${pathType} ${pathStr}`,
          };
        }
      } catch {
        continue;
      }
    }
  }

  return { blocked: false, reason: "" };
}

function checkCommand(command: string, config: CompiledConfig, context: string | null = null): CheckResult {
  // Get relaxed checks for context
  const contextConfig = context ? (config.contexts as any)?.[context] : null;
  const relaxedChecks = new Set<string>(contextConfig?.relaxed_checks || []);

  // Unwrap shell wrappers
  const [unwrappedCmd, wasUnwrapped] = unwrapCommand(command);

  // Semantic git analysis
  if (!relaxedChecks.has("semantic_git")) {
    const [isDangerousGit, gitReason] = analyzeGitCommand(unwrappedCmd);
    if (isDangerousGit) {
      return {
        blocked: false,
        ask: true,
        reason: gitReason,
        patternMatched: "semantic_git",
        wasUnwrapped,
        semanticMatch: true,
      };
    }
  }

  // Check bashToolPatterns
  if (!relaxedChecks.has("bashToolPatterns")) {
    for (let idx = 0; idx < config.bashToolPatterns_compiled.length; idx++) {
      const item = config.bashToolPatterns_compiled[idx];
      try {
        if (item.compiled.test(unwrappedCmd)) {
          const patternId = `yaml_pattern_${idx}`;
          if (item.ask) {
            return {
              blocked: false,
              ask: true,
              reason: item.reason,
              patternMatched: patternId,
              wasUnwrapped,
              semanticMatch: false,
            };
          } else {
            return {
              blocked: true,
              ask: false,
              reason: `Blocked: ${item.reason}`,
              patternMatched: patternId,
              wasUnwrapped,
              semanticMatch: false,
            };
          }
        }
      } catch {
        continue;
      }
    }
  }

  // Check zeroAccessPaths
  if (!relaxedChecks.has("zeroAccessPaths")) {
    for (const pathObj of config.zeroAccessPaths_compiled) {
      if (pathObj.isGlob) {
        const globRegex = pathObj.globRegex;
        if (globRegex) {
          try {
            if (globRegex.test(unwrappedCmd)) {
              return {
                blocked: true,
                ask: false,
                reason: `Blocked: zero-access pattern ${pathObj.original} (no operations allowed)`,
                patternMatched: "zero_access_glob",
                wasUnwrapped,
                semanticMatch: false,
              };
            }
          } catch {
            continue;
          }
        }
      } else {
        const escapedExpanded = pathObj.escapedExpanded || "";
        const escapedOriginal = pathObj.escapedOriginal || "";

        // For file patterns (not ending with /), add suffix check
        // to prevent .env from matching .env.example
        // For directory patterns (ending with /), match directly
        if (pathObj.original.endsWith('/')) {
          // Directory pattern - match directly
          if (
            (escapedExpanded && new RegExp(escapedExpanded).test(unwrappedCmd)) ||
            (escapedOriginal && new RegExp(escapedOriginal).test(unwrappedCmd))
          ) {
            return {
              blocked: true,
              ask: false,
              reason: `Blocked: zero-access path ${pathObj.original} (no operations allowed)`,
              patternMatched: 'zero_access_literal',
              wasUnwrapped,
              semanticMatch: false,
            };
          }
        } else {
          // File pattern - add suffix to prevent partial matches
          const suffix = '(?![a-zA-Z0-9_.-])';
          if (
            (escapedExpanded && new RegExp(escapedExpanded + suffix).test(unwrappedCmd)) ||
            (escapedOriginal && new RegExp(escapedOriginal + suffix).test(unwrappedCmd))
          ) {
            return {
              blocked: true,
              ask: false,
              reason: `Blocked: zero-access path ${pathObj.original} (no operations allowed)`,
              patternMatched: 'zero_access_literal',
              wasUnwrapped,
              semanticMatch: false,
            };
          }
        }
      }
    }
  }

  // Check readOnlyPaths
  if (!relaxedChecks.has("readOnlyPaths")) {
    for (const pathObj of config.readOnlyPaths_compiled) {
      const result = checkPathPatterns(unwrappedCmd, pathObj, READ_ONLY_BLOCKED, "read-only path");
      if (result.blocked) {
        return {
          blocked: true,
          ask: false,
          reason: result.reason,
          patternMatched: "readonly_path",
          wasUnwrapped,
          semanticMatch: false,
        };
      }
    }
  }

  // Check noDeletePaths
  if (!relaxedChecks.has("noDeletePaths")) {
    for (const pathObj of config.noDeletePaths_compiled) {
      const result = checkPathPatterns(unwrappedCmd, pathObj, NO_DELETE_BLOCKED, "no-delete path");
      if (result.blocked) {
        return {
          blocked: true,
          ask: false,
          reason: result.reason,
          patternMatched: "nodelete_path",
          wasUnwrapped,
          semanticMatch: false,
        };
      }
    }
  }

  return {
    blocked: false,
    ask: false,
    reason: "",
    patternMatched: "",
    wasUnwrapped,
    semanticMatch: false,
  };
}

// =============================================================================
// MAIN
// =============================================================================

async function main(): Promise<void> {
  // Check if hook is disabled
  if (isHookDisabled()) {
    process.exit(0);
  }

  const config = getCompiledConfig();

  // Read stdin
  let inputText = "";
  for await (const chunk of Bun.stdin.stream()) {
    inputText += new TextDecoder().decode(chunk);
  }

  // Parse input
  let input: HookInput;
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

  // Detect context
  const context = detectContext(input.tool_name, input.tool_input, config);

  // Check the command
  const result = checkCommand(command, config, context);

  // Log the decision
  const decision = result.blocked ? "blocked" : result.ask ? "ask" : "allowed";
  logDecision(
    input.tool_name,
    command,
    decision,
    result.reason,
    result.patternMatched,
    result.wasUnwrapped,
    result.semanticMatch,
    context
  );

  // Spawn log rotation
  spawnLogRotation();

  if (result.blocked) {
    console.error(`SECURITY: ${result.reason}`);
    console.error(`Command: ${command.slice(0, 100)}${command.length > 100 ? "..." : ""}`);
    process.exit(2);
  } else if (result.ask) {
    const output = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: result.reason,
      },
    };
    console.log(JSON.stringify(output));
    process.exit(0);
  } else {
    process.exit(0);
  }
}

main().catch((e) => {
  console.error(`Hook error: ${e}`);
  process.exit(0); // Fail open
});
