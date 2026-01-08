/**
 * Log rotation for damage-control hooks. Run as fire-and-forget subprocess.
 *
 * Archives .log files older than ARCHIVE_DAYS to gzip.
 * Deletes archives older than DELETE_DAYS.
 *
 * Environment Variables:
 *   DAMAGE_CONTROL_LOG_ARCHIVE_DAYS: Days before archiving (default: 30)
 *   DAMAGE_CONTROL_LOG_DELETE_DAYS: Days before deleting archives (default: 90, 0=never)
 *   DAMAGE_CONTROL_LOG_ROTATION: Set to 'disabled' to turn off
 *   DAMAGE_CONTROL_LOG_DRY_RUN: Set to '1' or 'true' for dry-run mode
 */

import {
  existsSync,
  readdirSync,
  statSync,
  unlinkSync,
  appendFileSync,
  createReadStream,
  createWriteStream,
  renameSync,
  lstatSync,
  openSync,
  closeSync,
} from "fs";
import { join, basename } from "path";
import { homedir } from "os";
import { createGzip, createGunzip } from "zlib";
import { pipeline } from "stream/promises";

const ARCHIVE_DAYS = parseInt(process.env.DAMAGE_CONTROL_LOG_ARCHIVE_DAYS || "30", 10);
const DELETE_DAYS = parseInt(process.env.DAMAGE_CONTROL_LOG_DELETE_DAYS || "90", 10);
const DRY_RUN = ["1", "true"].includes((process.env.DAMAGE_CONTROL_LOG_DRY_RUN || "").toLowerCase());
const DISABLED = (process.env.DAMAGE_CONTROL_LOG_ROTATION || "").toLowerCase() === "disabled";

function getLogsDir(): string {
  return join(homedir(), ".claude", "logs", "damage-control");
}

interface LockHandle {
  fd: number;
  path: string;
}

function acquireLock(logsDir: string): LockHandle | null {
  /**
   * Simple lock mechanism using file creation.
   * Note: Bun/Node.js doesn't have native flock, so we use exclusive file open.
   */
  const lockFile = join(logsDir, ".rotation.lock");

  try {
    // Try to open exclusively - will fail if file exists and is locked
    const fd = openSync(lockFile, "wx");
    return { fd, path: lockFile };
  } catch (e: any) {
    if (e.code === "EEXIST") {
      // Check if lock is stale (older than 5 minutes)
      try {
        const stat = statSync(lockFile);
        const age = Date.now() - stat.mtimeMs;
        if (age > 5 * 60 * 1000) {
          // Stale lock, remove and retry
          unlinkSync(lockFile);
          const fd = openSync(lockFile, "wx");
          return { fd, path: lockFile };
        }
      } catch {
        // Lock file doesn't exist or can't be read
      }
    }
    return null;
  }
}

function releaseLock(lock: LockHandle | null): void {
  if (lock === null) return;

  try {
    closeSync(lock.fd);
    unlinkSync(lock.path);
  } catch {
    // Ignore errors during cleanup
  }
}

function validateLogFilename(filename: string, logsDir: string): boolean {
  /**
   * Security: Ensure filename is valid and inside logs directory.
   */
  // Must match YYYY-MM-DD.log pattern
  if (!/^\d{4}-\d{2}-\d{2}\.log$/.test(filename)) {
    return false;
  }

  const fullPath = join(logsDir, filename);

  // Must not be a symlink
  try {
    const stat = lstatSync(fullPath);
    if (stat.isSymbolicLink()) {
      return false;
    }
  } catch {
    return false;
  }

  return true;
}

async function safeArchive(logFile: string, archivePath: string): Promise<boolean> {
  /**
   * Archive with atomic write and verification to prevent data loss.
   */
  const tempArchive = archivePath + ".tmp";

  try {
    // Compress to temp file
    const input = createReadStream(logFile);
    const output = createWriteStream(tempArchive);
    const gzip = createGzip();

    await pipeline(input, gzip, output);

    // Verify archive is readable
    try {
      const verifyInput = createReadStream(tempArchive);
      const gunzip = createGunzip();
      const chunks: Buffer[] = [];

      await new Promise<void>((resolve, reject) => {
        gunzip.on("data", (chunk) => chunks.push(chunk));
        gunzip.on("end", resolve);
        gunzip.on("error", reject);
        verifyInput.pipe(gunzip);
      });

      if (chunks.length === 0) {
        throw new Error("Archive verification failed - empty output");
      }
    } catch (e) {
      throw new Error(`Archive verification failed: ${e}`);
    }

    // Atomic rename
    renameSync(tempArchive, archivePath);
    return true;
  } catch (e) {
    // Clean up temp file on failure
    try {
      if (existsSync(tempArchive)) {
        unlinkSync(tempArchive);
      }
    } catch {
      // Ignore cleanup errors
    }
    return false;
  }
}

function logRotationEvent(logsDir: string, event: object): void {
  /**
   * Log rotation actions to rotation.log for observability.
   */
  const rotationLog = join(logsDir, "rotation.log");
  try {
    appendFileSync(rotationLog, JSON.stringify(event) + "\n");
  } catch {
    // Don't fail rotation if logging fails
  }
}

async function rotateLogs(): Promise<void> {
  const logsDir = getLogsDir();

  // Kill switch: .no-rotation file
  if (existsSync(join(logsDir, ".no-rotation"))) {
    return;
  }

  // Env var disable
  if (DISABLED) {
    return;
  }

  if (!existsSync(logsDir)) {
    return;
  }

  // Acquire lock (exit if another process is rotating)
  const lock = acquireLock(logsDir);
  if (lock === null) {
    return;
  }

  try {
    const now = new Date();
    const archiveCutoff = new Date(now.getTime() - ARCHIVE_DAYS * 24 * 60 * 60 * 1000);
    const deleteCutoff = new Date(now.getTime() - DELETE_DAYS * 24 * 60 * 60 * 1000);
    let archivedCount = 0;
    let deletedCount = 0;
    const errors: string[] = [];

    // Get all files in logs directory
    const files = readdirSync(logsDir);

    // Archive old .log files
    for (const filename of files) {
      if (!filename.endsWith(".log")) continue;
      if (filename === "rotation.log") continue;
      if (!validateLogFilename(filename, logsDir)) continue;

      try {
        // Extract date from filename (YYYY-MM-DD.log)
        const dateStr = filename.slice(0, 10);
        const fileDate = new Date(dateStr);

        if (isNaN(fileDate.getTime())) continue;

        if (fileDate < archiveCutoff) {
          const logFile = join(logsDir, filename);
          const archivePath = logFile + ".gz";

          if (DRY_RUN) {
            console.log(`WOULD archive: ${logFile}`);
            continue;
          }

          if (await safeArchive(logFile, archivePath)) {
            unlinkSync(logFile);
            archivedCount++;
          } else {
            errors.push(`Failed to archive ${logFile}`);
          }
        }
      } catch (e) {
        errors.push(`${filename}: ${e}`);
      }
    }

    // Delete old archives (only if DELETE_DAYS > 0)
    if (DELETE_DAYS > 0) {
      for (const filename of files) {
        if (!filename.endsWith(".log.gz")) continue;

        const fullPath = join(logsDir, filename);

        // Skip symlinks
        try {
          const stat = lstatSync(fullPath);
          if (stat.isSymbolicLink()) continue;
        } catch {
          continue;
        }

        try {
          // Extract date from filename (YYYY-MM-DD.log.gz)
          const dateStr = filename.slice(0, 10);
          const fileDate = new Date(dateStr);

          if (isNaN(fileDate.getTime())) continue;

          if (fileDate < deleteCutoff) {
            if (DRY_RUN) {
              console.log(`WOULD delete: ${fullPath}`);
              continue;
            }

            unlinkSync(fullPath);
            deletedCount++;
          }
        } catch (e) {
          errors.push(`${filename}: ${e}`);
        }
      }
    }

    // Log rotation status (only if something happened or errors occurred)
    if (archivedCount > 0 || deletedCount > 0 || errors.length > 0) {
      logRotationEvent(logsDir, {
        timestamp: now.toISOString(),
        archived: archivedCount,
        deleted: deletedCount,
        errors,
        dry_run: DRY_RUN,
      });
    }
  } finally {
    releaseLock(lock);
  }
}

// Main entry point
rotateLogs().catch((e) => {
  console.error(`Log rotation error: ${e}`);
  process.exit(1);
});
