/**
 * Claude Code Write Tool Damage Control
 * ======================================
 *
 * Blocks writes to protected files via PreToolUse hook on Write tool.
 * Loads protectedPaths from patterns.yaml.
 *
 * Requires: bun add yaml
 *
 * Exit codes:
 *   0 = Allow write
 *   2 = Block write (stderr fed back to Claude)
 */

import { existsSync, readFileSync } from "fs";
import { dirname, join } from "path";
import { homedir } from "os";
import { parse as parseYaml } from "yaml";

interface Config {
  zeroAccessPaths: string[];
  readOnlyPaths: string[];
}

interface HookInput {
  tool_name: string;
  tool_input: {
    file_path?: string;
  };
}

function getConfigPath(): string {
  const projectDir = process.env.CLAUDE_PROJECT_DIR;
  if (projectDir) {
    const projectConfig = join(projectDir, ".claude", "hooks", "patterns.yaml");
    if (existsSync(projectConfig)) {
      return projectConfig;
    }
  }

  const scriptDir = dirname(Bun.main);
  return join(scriptDir, "patterns.yaml");
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
  };
}

function checkPath(filePath: string, config: Config): { blocked: boolean; reason: string } {
  const normalized = filePath.replace(/^~/, homedir());

  // Check zero-access paths first
  for (const zeroPath of config.zeroAccessPaths) {
    const expanded = zeroPath.replace(/^~/, homedir());
    if (normalized.startsWith(expanded) || normalized === expanded.replace(/\/$/, "")) {
      return { blocked: true, reason: `zero-access path ${zeroPath} (no operations allowed)` };
    }
  }

  // Check read-only paths
  for (const readonlyPath of config.readOnlyPaths) {
    const expanded = readonlyPath.replace(/^~/, homedir());
    if (normalized.startsWith(expanded) || normalized === expanded.replace(/\/$/, "")) {
      return { blocked: true, reason: `read-only path ${readonlyPath}` };
    }
  }

  return { blocked: false, reason: "" };
}

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

  const { blocked, reason } = checkPath(filePath, config);
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
