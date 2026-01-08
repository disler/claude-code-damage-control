"""Tests for log_rotate.py - damage-control log rotation."""

import json
import os
import sys
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from log_rotate import (
    get_logs_dir,
    acquire_lock,
    release_lock,
    validate_log_filename,
    safe_archive,
    log_rotation_event,
    rotate_logs,
    ARCHIVE_DAYS,
    DELETE_DAYS,
)


@pytest.fixture
def logs_dir(tmp_path, monkeypatch):
    """Create isolated logs directory for testing."""
    log_dir = tmp_path / ".claude" / "logs" / "damage-control"
    log_dir.mkdir(parents=True)

    # Patch Path.home() to return tmp_path
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    return log_dir


@pytest.fixture
def old_log_file(logs_dir):
    """Create a log file older than ARCHIVE_DAYS."""
    old_date = datetime.now() - timedelta(days=ARCHIVE_DAYS + 5)
    filename = old_date.strftime("%Y-%m-%d") + ".log"
    log_file = logs_dir / filename
    log_file.write_text('{"test": "old log entry"}\n')
    return log_file


@pytest.fixture
def recent_log_file(logs_dir):
    """Create a recent log file (should not be archived)."""
    recent_date = datetime.now() - timedelta(days=5)
    filename = recent_date.strftime("%Y-%m-%d") + ".log"
    log_file = logs_dir / filename
    log_file.write_text('{"test": "recent log entry"}\n')
    return log_file


@pytest.fixture
def old_archive(logs_dir):
    """Create an archive older than DELETE_DAYS."""
    old_date = datetime.now() - timedelta(days=DELETE_DAYS + 5)
    filename = old_date.strftime("%Y-%m-%d") + ".log.tar.gz"
    archive_file = logs_dir / filename
    # Create a valid tar.gz file
    with tarfile.open(archive_file, "w:gz") as tar:
        # Add a dummy file
        dummy = logs_dir / "dummy.txt"
        dummy.write_text("dummy content")
        tar.add(dummy, arcname="dummy.txt")
        dummy.unlink()
    return archive_file


class TestValidateLogFilename:
    """Tests for filename validation."""

    def test_valid_date_filename(self, logs_dir):
        """Valid YYYY-MM-DD.log filenames pass validation."""
        log_file = logs_dir / "2026-01-07.log"
        log_file.touch()
        assert validate_log_filename(log_file, logs_dir) is True

    def test_invalid_filename_format(self, logs_dir):
        """Non-date filenames are rejected."""
        log_file = logs_dir / "invalid.log"
        log_file.touch()
        assert validate_log_filename(log_file, logs_dir) is False

    def test_rejects_symlinks(self, logs_dir, tmp_path):
        """Symlinks are rejected for security."""
        target = tmp_path / "target.log"
        target.write_text("target content")
        symlink = logs_dir / "2026-01-07.log"
        try:
            symlink.symlink_to(target)
            assert validate_log_filename(symlink, logs_dir) is False
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

    def test_rejects_path_traversal(self, logs_dir, tmp_path):
        """Files outside logs directory are rejected."""
        outside_file = tmp_path / "2026-01-07.log"
        outside_file.touch()
        assert validate_log_filename(outside_file, logs_dir) is False


class TestSafeArchive:
    """Tests for atomic archive creation."""

    def test_creates_valid_archive(self, logs_dir):
        """Successfully creates and verifies tar.gz archive."""
        log_file = logs_dir / "test.log"
        log_file.write_text("test content\n")
        archive_path = logs_dir / "test.log.tar.gz"

        result = safe_archive(log_file, archive_path)

        assert result is True
        assert archive_path.exists()
        # Verify archive contents
        with tarfile.open(archive_path, "r:gz") as tar:
            member = tar.getmember("test.log")
            assert member is not None

    def test_cleans_up_on_failure(self, logs_dir):
        """Temp file is cleaned up if archiving fails."""
        log_file = logs_dir / "nonexistent.log"
        archive_path = logs_dir / "test.log.tar.gz"

        result = safe_archive(log_file, archive_path)

        assert result is False
        assert not archive_path.exists()
        assert not archive_path.with_suffix(".tmp").exists()


class TestRotateLogs:
    """Tests for main rotation logic."""

    def test_archives_old_logs(self, logs_dir, old_log_file, monkeypatch):
        """Logs older than ARCHIVE_DAYS are archived."""
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_ROTATION", "")

        rotate_logs()

        # Original should be deleted
        assert not old_log_file.exists()
        # Archive should exist
        archive = old_log_file.with_suffix(".log.tar.gz")
        assert archive.exists()

    def test_preserves_recent_logs(self, logs_dir, recent_log_file, monkeypatch):
        """Logs newer than ARCHIVE_DAYS are not touched."""
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_ROTATION", "")

        rotate_logs()

        assert recent_log_file.exists()
        archive = recent_log_file.with_suffix(".log.tar.gz")
        assert not archive.exists()

    def test_deletes_old_archives(self, logs_dir, old_archive, monkeypatch):
        """Archives older than DELETE_DAYS are deleted."""
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_ROTATION", "")

        rotate_logs()

        assert not old_archive.exists()

    def test_delete_days_zero_skips_deletion(self, logs_dir, old_archive, monkeypatch):
        """DELETE_DAYS=0 disables archive deletion."""
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_DELETE_DAYS", "0")

        # Re-import to pick up new env var
        import importlib
        import log_rotate
        importlib.reload(log_rotate)

        log_rotate.rotate_logs()

        assert old_archive.exists()

    def test_no_rotation_kill_switch(self, logs_dir, old_log_file, monkeypatch):
        """Rotation is skipped if .no-rotation file exists."""
        kill_switch = logs_dir / ".no-rotation"
        kill_switch.touch()

        rotate_logs()

        # File should still exist (rotation was skipped)
        assert old_log_file.exists()

    def test_disabled_env_var(self, logs_dir, old_log_file, monkeypatch):
        """Rotation is skipped if DAMAGE_CONTROL_LOG_ROTATION=disabled."""
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_ROTATION", "disabled")

        # Re-import to pick up new env var
        import importlib
        import log_rotate
        importlib.reload(log_rotate)

        log_rotate.rotate_logs()

        assert old_log_file.exists()

    def test_dry_run_mode(self, logs_dir, old_log_file, monkeypatch, capsys):
        """Dry-run mode prints what would happen without acting."""
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_DRY_RUN", "1")

        # Re-import to pick up new env var
        import importlib
        import log_rotate
        importlib.reload(log_rotate)

        log_rotate.rotate_logs()

        # File should still exist
        assert old_log_file.exists()
        # Should have printed what it would do
        captured = capsys.readouterr()
        assert "WOULD archive" in captured.out

    def test_handles_malformed_filenames(self, logs_dir, monkeypatch):
        """Malformed filenames are skipped without error."""
        malformed = logs_dir / "not-a-date.log"
        malformed.write_text("content")

        rotate_logs()

        # File should still exist (was skipped)
        assert malformed.exists()

    def test_rotation_log_written(self, logs_dir, old_log_file, monkeypatch):
        """Rotation status is logged to rotation.log."""
        # Reset env vars that might be set from previous tests
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_ROTATION", "")
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_DRY_RUN", "")
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_ARCHIVE_DAYS", "30")
        monkeypatch.setenv("DAMAGE_CONTROL_LOG_DELETE_DAYS", "90")

        # Re-import to pick up reset env vars
        import importlib
        import log_rotate
        importlib.reload(log_rotate)

        log_rotate.rotate_logs()

        rotation_log = logs_dir / "rotation.log"
        assert rotation_log.exists()
        content = rotation_log.read_text()
        entry = json.loads(content.strip())
        assert "timestamp" in entry
        assert "archived" in entry
        assert entry["archived"] >= 1


class TestFileLocking:
    """Tests for cross-platform file locking."""

    def test_acquire_and_release_lock(self, logs_dir):
        """Lock can be acquired and released."""
        lock_fd = acquire_lock(logs_dir)
        assert lock_fd is not None

        release_lock(lock_fd)
        # Should be able to acquire again after release
        lock_fd2 = acquire_lock(logs_dir)
        assert lock_fd2 is not None
        release_lock(lock_fd2)

    def test_second_lock_fails(self, logs_dir):
        """Cannot acquire lock while another process holds it."""
        lock_fd1 = acquire_lock(logs_dir)
        assert lock_fd1 is not None

        # Second acquisition should fail
        lock_fd2 = acquire_lock(logs_dir)
        assert lock_fd2 is None

        release_lock(lock_fd1)


class TestLogRotationEvent:
    """Tests for rotation event logging."""

    def test_logs_event_to_file(self, logs_dir):
        """Events are logged to rotation.log as JSONL."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "archived": 1,
            "deleted": 0,
            "errors": [],
        }

        log_rotation_event(logs_dir, event)

        rotation_log = logs_dir / "rotation.log"
        assert rotation_log.exists()
        content = rotation_log.read_text()
        logged = json.loads(content.strip())
        assert logged["archived"] == 1

    def test_appends_multiple_events(self, logs_dir):
        """Multiple events are appended to same file."""
        for i in range(3):
            log_rotation_event(logs_dir, {"count": i})

        rotation_log = logs_dir / "rotation.log"
        lines = rotation_log.read_text().strip().split("\n")
        assert len(lines) == 3
