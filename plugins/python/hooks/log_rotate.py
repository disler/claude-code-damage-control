#!/usr/bin/env python
# /// script
# requires-python = ">=3.8"
# ///
"""
Log rotation for damage-control hooks. Run as fire-and-forget subprocess.

Archives .log files older than ARCHIVE_DAYS to tar.gz.
Deletes archives older than DELETE_DAYS.

Environment Variables:
    DAMAGE_CONTROL_LOG_ARCHIVE_DAYS: Days before archiving (default: 30)
    DAMAGE_CONTROL_LOG_DELETE_DAYS: Days before deleting archives (default: 90, 0=never)
    DAMAGE_CONTROL_LOG_ROTATION: Set to 'disabled' to turn off
    DAMAGE_CONTROL_LOG_DRY_RUN: Set to '1' or 'true' for dry-run mode
"""

import json
import os
import re
import sys
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

ARCHIVE_DAYS = int(os.environ.get("DAMAGE_CONTROL_LOG_ARCHIVE_DAYS", "30"))
DELETE_DAYS = int(os.environ.get("DAMAGE_CONTROL_LOG_DELETE_DAYS", "90"))
DRY_RUN = os.environ.get("DAMAGE_CONTROL_LOG_DRY_RUN", "").lower() in ("1", "true")
DISABLED = os.environ.get("DAMAGE_CONTROL_LOG_ROTATION", "").lower() == "disabled"


def get_logs_dir() -> Path:
    """Get path to damage-control logs directory."""
    return Path.home() / ".claude" / "logs" / "damage-control"


def acquire_lock(logs_dir: Path) -> Optional[object]:
    """Cross-platform file lock. Returns lock handle or None if already locked."""
    lock_file = logs_dir / ".rotation.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        lock_fd = open(lock_file, "w")
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(lock_fd.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_fd
    except (OSError, BlockingIOError):
        return None  # Another process is rotating


def release_lock(lock_fd: Optional[object]) -> None:
    """Release file lock."""
    if lock_fd is None:
        return
    try:
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
    except OSError:
        pass


def validate_log_filename(path: Path, logs_dir: Path) -> bool:
    """Security: Ensure filename is valid and inside logs directory."""
    # Must match YYYY-MM-DD.log pattern
    if not re.match(r"^\d{4}-\d{2}-\d{2}\.log$", path.name):
        return False
    # Must not be a symlink
    if path.is_symlink():
        return False
    # Must be inside logs directory (prevent path traversal)
    try:
        path.resolve().relative_to(logs_dir.resolve())
        return True
    except ValueError:
        return False


def safe_archive(log_file: Path, archive_path: Path) -> bool:
    """Archive with atomic write and verification to prevent data loss."""
    temp_archive = archive_path.with_suffix(".tmp")
    try:
        # Write to temp file first
        with tarfile.open(temp_archive, "w:gz") as tar:
            tar.add(log_file, arcname=log_file.name)

        # Verify archive is readable
        with tarfile.open(temp_archive, "r:gz") as tar:
            tar.getmember(log_file.name)

        # Atomic rename
        temp_archive.rename(archive_path)
        return True
    except Exception:
        # Clean up temp file on failure
        if temp_archive.exists():
            temp_archive.unlink()
        return False


def log_rotation_event(logs_dir: Path, event: dict) -> None:
    """Log rotation actions to rotation.log for observability."""
    rotation_log = logs_dir / "rotation.log"
    try:
        with open(rotation_log, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        pass  # Don't fail rotation if logging fails


def rotate_logs() -> None:
    """Main rotation logic."""
    logs_dir = get_logs_dir()

    # Kill switch: .no-rotation file
    if (logs_dir / ".no-rotation").exists():
        return

    # Env var disable
    if DISABLED:
        return

    if not logs_dir.exists():
        return

    # Acquire lock (exit if another process is rotating)
    lock_fd = acquire_lock(logs_dir)
    if lock_fd is None:
        return  # Another rotation in progress

    try:
        now = datetime.now()
        archive_cutoff = now - timedelta(days=ARCHIVE_DAYS)
        delete_cutoff = now - timedelta(days=DELETE_DAYS)
        archived_count = 0
        deleted_count = 0
        errors = []

        # Archive old .log files
        for log_file in logs_dir.glob("*.log"):
            if log_file.name == "rotation.log":
                continue  # Never rotate the rotation log
            if not validate_log_filename(log_file, logs_dir):
                continue
            try:
                file_date = datetime.strptime(log_file.stem, "%Y-%m-%d")
                if file_date < archive_cutoff:
                    archive_path = log_file.with_suffix(".log.tar.gz")
                    if DRY_RUN:
                        print(f"WOULD archive: {log_file}")
                        continue
                    if safe_archive(log_file, archive_path):
                        log_file.unlink()
                        archived_count += 1
                    else:
                        errors.append(f"Failed to archive {log_file}")
            except (ValueError, OSError) as e:
                errors.append(f"{log_file}: {e}")

        # Delete old archives (only if DELETE_DAYS > 0)
        if DELETE_DAYS > 0:
            for archive in logs_dir.glob("*.log.tar.gz"):
                if archive.is_symlink():
                    continue
                try:
                    # Archive filename: YYYY-MM-DD.log.tar.gz
                    # Extract date from first 10 characters
                    date_str = archive.name[:10]
                    file_date = datetime.strptime(date_str, "%Y-%m-%d")
                    if file_date < delete_cutoff:
                        if DRY_RUN:
                            print(f"WOULD delete: {archive}")
                            continue
                        archive.unlink()
                        deleted_count += 1
                except (ValueError, OSError) as e:
                    errors.append(f"{archive}: {e}")

        # Log rotation status (only if something happened or errors occurred)
        if archived_count > 0 or deleted_count > 0 or errors:
            log_rotation_event(
                logs_dir,
                {
                    "timestamp": now.isoformat(),
                    "archived": archived_count,
                    "deleted": deleted_count,
                    "errors": errors,
                    "dry_run": DRY_RUN,
                },
            )

    finally:
        release_lock(lock_fd)


if __name__ == "__main__":
    rotate_logs()
