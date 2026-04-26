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
    collect_smart_metrics,
    _parse_smart_attributes,
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


class TestSmartAttributeParser:
    """Tests for SMART attribute parsing."""

    def test_parse_standard_attributes(self):
        """Should parse standard smartctl -A output."""
        smart_output = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.8.0] (local build)
Copyright (C) 2002-23, Bruce Allen, Christian Franke

=== START OF READ SMART DATA SECTION ===
SMART Attributes Data Structure revision number: 16
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
  9 Power_On_Hours           0x0032   087   087   000    Old_age   Always       -       58320
 12 Power_Cycle_Count        0x0032   100   100   000    Old_age   Always       -       1234
194 Temperature_Celsius      0x0022   068   055   000    Old_age   Always       -       32 (Min/Max 18/55)
197 Current_Pending_Sector  0x0032   100   100   000    Old_age   Always       -       0
198 Offline_Uncorrectable   0x0030   100   100   000    Old_age   Always       -       0
"""
        attrs = _parse_smart_attributes(smart_output)
        assert "Reallocated_Sector_Ct" in attrs
        assert attrs["Reallocated_Sector_Ct"]["raw"] == 0
        assert attrs["Reallocated_Sector_Ct"]["value"] == 100
        assert "Power_On_Hours" in attrs
        assert attrs["Power_On_Hours"]["raw"] == 58320
        assert "Temperature_Celsius" in attrs
        assert attrs["Temperature_Celsius"]["raw"] == 32
        assert "Current_Pending_Sector" in attrs
        assert attrs["Current_Pending_Sector"]["raw"] == 0
        assert "Offline_Uncorrectable" in attrs
        assert attrs["Offline_Uncorrectable"]["raw"] == 0

    def test_parse_empty_output(self):
        """Should handle empty smartctl output."""
        attrs = _parse_smart_attributes("")
        assert attrs == {}

    def test_parse_failing_attribute(self):
        """Should detect WHEN_FAILED column."""
        smart_output = """ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   001   001   005    Pre-fail  Always   FAILING_NOW 500
"""
        attrs = _parse_smart_attributes(smart_output)
        assert "Reallocated_Sector_Ct" in attrs
        assert attrs["Reallocated_Sector_Ct"]["when_failed"] == "FAILING_NOW"
        assert attrs["Reallocated_Sector_Ct"]["raw"] == 500


class TestCollectSmartMetrics:
    """Tests for SMART metrics collection."""

    def test_smartctl_missing(self):
        """When smartctl is not available, should report it as missing."""
        with patch("linuxdoctor.collectors._tool_available", return_value=False):
            collection = collect_smart_metrics()
            assert collection.category == "smart"
            assert "smartctl" in collection.missing_tools
            smart_available = [m for m in collection.metrics if m.name == "smart_available"]
            assert len(smart_available) == 1
            assert smart_available[0].value is False

    def test_smart_available_when_installed(self):
        """When smartctl is available, should report smart_available as True."""
        with patch("linuxdoctor.collectors._tool_available", return_value=True), \
             patch("linuxdoctor.collectors._smartctl_scan_devices", return_value=[]), \
             patch("linuxdoctor.collectors._run_command", return_value=("", "No devices")):
            collection = collect_smart_metrics()
            assert collection.category == "smart"
            smart_available = [m for m in collection.metrics if m.name == "smart_available"]
            assert len(smart_available) == 1
            assert smart_available[0].value is True

    def test_smart_health_passed(self):
        """Should detect PASSED SMART health status."""
        scan_output = "/dev/sda -d scsi # /dev/sda, SCSI device\n"
        health_output = "smartctl 7.4\nSMART overall-health self-assessment test result: PASSED\n"
        attrs_output = "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0\n"

        def mock_run_command(cmd, timeout=10):
            if "--scan" in cmd:
                return (scan_output, None)
            elif "-H" in cmd:
                return (health_output, None)
            elif "-A" in cmd:
                return (attrs_output, None)
            return ("", "unknown command")

        with patch("linuxdoctor.collectors._tool_available", return_value=True), \
             patch("linuxdoctor.collectors._smartctl_scan_devices", return_value=["/dev/sda"]), \
             patch("linuxdoctor.collectors._run_command", side_effect=mock_run_command):
            collection = collect_smart_metrics()
            health_metrics = [m for m in collection.metrics if m.name == "smart_sda_health"]
            assert len(health_metrics) == 1
            assert health_metrics[0].value == "passed"

    def test_smart_health_failed(self):
        """Should detect FAILED SMART health status."""
        scan_output = "/dev/sda -d scsi # /dev/sda, SCSI device\n"
        health_output = "smartctl 7.4\nSMART overall-health self-assessment test result: FAILED!\n"
        attrs_output = "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0\n"

        def mock_run_command(cmd, timeout=10):
            if "-H" in cmd:
                return (health_output, None)
            elif "-A" in cmd:
                return (attrs_output, None)
            return ("", "unknown")

        with patch("linuxdoctor.collectors._tool_available", return_value=True), \
             patch("linuxdoctor.collectors._smartctl_scan_devices", return_value=["/dev/sda"]), \
             patch("linuxdoctor.collectors._run_command", side_effect=mock_run_command):
            collection = collect_smart_metrics()
            health_metrics = [m for m in collection.metrics if m.name == "smart_sda_health"]
            assert len(health_metrics) == 1
            assert health_metrics[0].value == "failed"

    def test_smart_collects_key_attributes(self):
        """Should collect key SMART attributes like reallocated sectors."""
        scan_output = "/dev/sda -d scsi # /dev/sda, SCSI device\n"
        health_output = "SMART overall-health self-assessment test result: PASSED\n"
        attrs_output = """ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       5
197 Current_Pending_Sector  0x0032   100   100   000    Old_age   Always       -       2
198 Offline_Uncorrectable   0x0030   100   100   000    Old_age   Always       -       1
194 Temperature_Celsius      0x0022   068   055   000    Old_age   Always       -       45
"""

        def mock_run_command(cmd, timeout=10):
            if "-H" in cmd:
                return (health_output, None)
            elif "-A" in cmd:
                return (attrs_output, None)
            return ("", "unknown")

        with patch("linuxdoctor.collectors._tool_available", return_value=True), \
             patch("linuxdoctor.collectors._smartctl_scan_devices", return_value=["/dev/sda"]), \
             patch("linuxdoctor.collectors._run_command", side_effect=mock_run_command):
            collection = collect_smart_metrics()
            metric_names = [m.name for m in collection.metrics]
            assert "smart_sda_reallocated_sectors" in metric_names
            assert "smart_sda_pending_sectors" in metric_names
            assert "smart_sda_uncorrectable_sectors" in metric_names
            assert "smart_sda_temperature" in metric_names

            # Check actual values
            for m in collection.metrics:
                if m.name == "smart_sda_reallocated_sectors":
                    assert m.value == 5
                elif m.name == "smart_sda_pending_sectors":
                    assert m.value == 2
                elif m.name == "smart_sda_uncorrectable_sectors":
                    assert m.value == 1
                elif m.name == "smart_sda_temperature":
                    assert m.value == 45