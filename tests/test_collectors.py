"""Tests for the collectors module."""

import pytest
from unittest.mock import patch, MagicMock
from linuxdoctor.collectors import (
    _sanitize_mount_name,
    _run_command,
    _tool_available,
    collect_disk_metrics,
    collect_cpu_metrics,
    collect_memory_metrics,
    collect_io_metrics,
)


class TestSanitizeMountName:
    """Tests for the mount name sanitization helper."""

    def test_root_mount(self):
        assert _sanitize_mount_name("/") == "root"

    def test_boot_mount(self):
        assert _sanitize_mount_name("/boot") == "boot"

    def test_multi_level_mount(self):
        assert _sanitize_mount_name("/mnt/data") == "mnt_data"

    def test_deep_mount(self):
        assert _sanitize_mount_name("/var/lib/docker") == "var_lib_docker"

    def test_hyphenated_mount(self):
        assert _sanitize_mount_name("/bhprodzfs-pool") == "bhprodzfs_pool"


class TestRunCommand:
    """Tests for the _run_command helper."""

    def test_successful_command(self):
        stdout, err = _run_command(["echo", "hello"])
        assert stdout == "hello"
        assert err is None

    def test_command_not_found(self):
        stdout, err = _run_command(["nonexistent_command_xyz"])
        assert err is not None
        assert "not found" in err.lower() or "not found" in err

    def test_command_timeout(self):
        stdout, err = _run_command(["sleep", "5"], timeout=1)
        assert err is not None
        assert "timed out" in err.lower()

    def test_command_error_exit_code(self):
        stdout, err = _run_command(["ls", "/nonexistent_dir_xyz"])
        # ls returns non-zero for nonexistent dirs
        assert err is not None


class TestToolAvailable:
    """Tests for the _tool_available helper."""

    def test_common_tool_exists(self):
        assert _tool_available("ls") is True

    def test_nonexistent_tool(self):
        assert _tool_available("nonexistent_tool_xyz") is False


class TestCollectDiskMetrics:
    """Tests for disk metrics collection."""

    def test_collects_disk_metrics(self):
        """Disk metrics should be collectable on a Linux system."""
        collection = collect_disk_metrics()
        assert collection.category == "disk"
        assert collection.error is None
        # Should have at least root filesystem metrics
        metric_names = [m.name for m in collection.metrics]
        assert any("root" in name for name in metric_names), f"Expected root metrics, got: {metric_names}"

    def test_no_virtual_filesystems(self):
        """Virtual filesystems should be filtered out."""
        collection = collect_disk_metrics()
        metric_names = [m.name for m in collection.metrics]
        # No tmpfs, devtmpfs, or overlay metrics
        for name in metric_names:
            assert "tmpfs" not in name.lower()
            assert "devtmpfs" not in name.lower()
            assert "shm" not in name.lower()


class TestCollectMemoryMetrics:
    """Tests for memory metrics collection."""

    def test_collects_memory_metrics(self):
        """Memory metrics should be collectable on a Linux system."""
        collection = collect_memory_metrics()
        assert collection.category == "memory"
        assert collection.error is None
        metric_names = [m.name for m in collection.metrics]
        assert "mem_total_mb" in metric_names
        assert "mem_used_pct" in metric_names


class TestCollectCpuMetrics:
    """Tests for CPU metrics collection."""

    def test_collects_load_averages(self):
        """Should always be able to read load from /proc/loadavg."""
        collection = collect_cpu_metrics()
        assert collection.category == "cpu"
        metric_names = [m.name for m in collection.metrics]
        assert "load_1m" in metric_names
        assert "cpu_count" in metric_names


class TestCollectIoMetrics:
    """Tests for I/O metrics collection."""

    def test_io_collection_no_loop_devices(self):
        """I/O metrics should not include loop devices."""
        collection = collect_io_metrics()
        metric_names = [m.name for m in collection.metrics]
        for name in metric_names:
            assert not name.startswith("io_loop"), f"Found loop device metric: {name}"