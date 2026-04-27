"""Tests for the SSH collector module."""

import pytest
from unittest.mock import patch, MagicMock
from linuxdoctor.ssh_collector import (
    SSHResult,
    ssh_run,
    ssh_test_connection,
    resolve_ssh_connect,
    collect_ssh_metrics,
    check_remote_tools,
)


class TestSSHResult:
    """Tests for SSHResult dataclass."""

    def test_default_values(self):
        result = SSHResult()
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.returncode == -1
        assert result.error is None

    def test_with_values(self):
        result = SSHResult(stdout="ok\n", returncode=0, error=None)
        assert result.stdout == "ok\n"
        assert result.returncode == 0


class TestSSHRun:
    """Tests for ssh_run function."""

    @patch("linuxdoctor.ssh_collector.subprocess.run")
    def test_successful_command(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="output",
            stderr="",
            returncode=0,
        )
        result = ssh_run("user@host", "echo hello")
        assert result.error is None
        assert result.returncode == 0
        assert result.stdout == "output"
        # Verify BatchMode=yes is used (non-interactive)
        call_args = mock_run.call_args[0][0]
        assert "ssh" in call_args
        assert "BatchMode=yes" in call_args

    @patch("linuxdoctor.ssh_collector.subprocess.run")
    def test_failed_command(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="Permission denied",
            returncode=255,
        )
        result = ssh_run("user@host", "echo hello")
        assert result.error is not None
        assert result.returncode == 255

    @patch("linuxdoctor.ssh_collector.subprocess.run")
    def test_interactive_mode(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="ok",
            stderr="",
            returncode=0,
        )
        result = ssh_run("user@host", "echo hello", allow_interactive=True)
        assert result.error is None
        # Verify BatchMode=no is used (interactive)
        call_args = mock_run.call_args[0][0]
        assert "BatchMode=no" in call_args
        assert "StrictHostKeyChecking=no" in call_args

    @patch("linuxdoctor.ssh_collector.subprocess.run")
    def test_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 15)
        result = ssh_run("user@host", "echo hello", timeout=15)
        assert result.error is not None
        assert "timed out" in result.error.lower()

    @patch("linuxdoctor.ssh_collector.subprocess.run")
    def test_ssh_not_found(self, mock_run):
        import subprocess
        mock_run.side_effect = FileNotFoundError("ssh not found")
        result = ssh_run("user@host", "echo hello")
        assert result.error is not None
        assert "not found" in result.error.lower()


class TestSSHTestConnection:
    """Tests for ssh_test_connection function."""

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_successful_connection(self, mock_ssh_run):
        mock_ssh_run.return_value = SSHResult(stdout="ok", returncode=0, error=None)
        reachable, message = ssh_test_connection("user@host")
        assert reachable is True
        assert message == "OK"

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_host_key_failure(self, mock_ssh_run):
        mock_ssh_run.return_value = SSHResult(
            error="Host key verification failed"
        )
        reachable, message = ssh_test_connection("user@host")
        assert reachable is False
        assert "host key" in message.lower()

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_auth_failure(self, mock_ssh_run):
        mock_ssh_run.return_value = SSHResult(
            error="Permission denied (publickey)"
        )
        reachable, message = ssh_test_connection("user@host")
        assert reachable is False
        assert "auth" in message.lower() or "permission" in message.lower()

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_timeout_failure(self, mock_ssh_run):
        mock_ssh_run.return_value = SSHResult(
            error="SSH command timed out after 10s"
        )
        reachable, message = ssh_test_connection("user@host")
        assert reachable is False


class TestResolveSSHConnect:
    """Tests for resolve_ssh_connect function."""

    def test_with_ssh_connect_field(self):
        host_info = {"ssh_connect": "admin@server1", "cpu_cores": 4}
        result = resolve_ssh_connect("server1", host_info)
        assert result == "admin@server1"

    def test_without_ssh_connect_field(self):
        host_info = {"cpu_cores": 4}
        result = resolve_ssh_connect("server1", host_info)
        assert result == "server1"

    def test_with_none_host_info(self):
        result = resolve_ssh_connect("server1", None)
        assert result == "server1"


class TestCollectSSHMetrics:
    """Tests for collect_ssh_metrics function."""

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_empty_metrics_on_all_failures(self, mock_ssh_run):
        """When all SSH commands fail, metrics dict should still be returned."""
        mock_ssh_run.return_value = SSHResult(error="connection failed")
        metrics = collect_ssh_metrics("user@host")
        assert isinstance(metrics, dict)

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_cpu_count_collection(self, mock_ssh_run):
        """Test that nproc output is collected as node_cpu_count."""

        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "nproc" in command:
                return SSHResult(stdout="8", returncode=0, error=None)
            if "mpstat" in command:
                return SSHResult(stdout="Linux ...\nAverage: all 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 95.00", returncode=0, error=None)
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        metrics = collect_ssh_metrics("user@host")
        assert "node_cpu_count" in metrics
        assert metrics["node_cpu_count"] == 8

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_memory_collection(self, mock_ssh_run):
        """Test memory metrics from /proc/meminfo."""

        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "meminfo" in command:
                meminfo = """MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12288000 kB
Buffers:          512000 kB
Cached:          4096000 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB"""
                return SSHResult(stdout=meminfo, returncode=0, error=None)
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        metrics = collect_ssh_metrics("user@host")
        assert "node_memory_MemTotal_bytes" in metrics
        assert "node_memory_MemAvailable_bytes" in metrics

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_load_collection(self, mock_ssh_run):
        """Test load average collection from /proc/loadavg."""

        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "loadavg" in command:
                return SSHResult(stdout="0.50 0.75 1.00 2/128 12345", returncode=0, error=None)
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        metrics = collect_ssh_metrics("user@host")
        assert "node_load1" in metrics
        assert metrics["node_load1"] == 0.50
        assert metrics["node_load5"] == 0.75
        assert metrics["node_load15"] == 1.00

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_context_switches_collection(self, mock_ssh_run):
        """Test context switch collection from /proc/stat."""

        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "ctxt" in command:
                return SSHResult(stdout="ctxt 12345678", returncode=0, error=None)
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        metrics = collect_ssh_metrics("user@host")
        assert "node_context_switches_total" in metrics
        assert metrics["node_context_switches_total"] == 12345678.0

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_collect_ssh_metrics_tracks_missing_tools(self, mock_ssh_run):
        """Test that collect_ssh_metrics populates missing_tools when commands fail."""

        def mock_run_side_effect(ssh_connect, command, **kwargs):
            # mpstat fails — should be tracked as missing
            if "mpstat" in command:
                return SSHResult(error="command not found: mpstat")
            # iostat fails — should be tracked as missing
            if "iostat" in command:
                return SSHResult(error="command not found: iostat")
            # Everything else succeeds
            if "meminfo" in command:
                return SSHResult(stdout="MemTotal:       16384000 kB\nMemAvailable:   14000000 kB\n", returncode=0)
            if "loadavg" in command:
                return SSHResult(stdout="0.50 0.75 1.00 2/128 12345", returncode=0)
            if "grep ctxt" in command:
                return SSHResult(stdout="ctxt 12345678", returncode=0)
            if "nproc" in command:
                return SSHResult(stdout="4", returncode=0)
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        missing_tools = []
        metrics = collect_ssh_metrics("user@host", missing_tools=missing_tools)
        assert "mpstat" in missing_tools
        assert "iostat" in missing_tools
        # Should still have some metrics from /proc
        assert "node_memory_MemTotal_bytes" in metrics


class TestCheckRemoteTools:
    """Tests for check_remote_tools function."""

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_all_tools_available(self, mock_ssh_run):
        """No tools missing should return empty list."""
        mock_ssh_run.return_value = SSHResult(stdout="", returncode=0, error=None)
        result = check_remote_tools("user@host")
        assert result == []

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_some_tools_missing(self, mock_ssh_run):
        """Should report missing tools."""
        mock_ssh_run.return_value = SSHResult(
            stdout="MISSING:iotop\nMISSING:perf\nMISSING:smem",
            returncode=0, error=None
        )
        result = check_remote_tools("user@host")
        assert "iotop" in result
        assert "perf" in result
        assert "smem" in result

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_ssh_connection_failure(self, mock_ssh_run):
        """SSH failure should return empty list (can't determine availability)."""
        mock_ssh_run.return_value = SSHResult(error="Connection refused")
        result = check_remote_tools("user@host")
        assert result == []

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_all_tools_missing(self, mock_ssh_run):
        """All tools missing should return full list."""
        from linuxdoctor.ssh_collector import REMOTE_DIAGNOSTIC_TOOLS
        missing_lines = "\n".join(f"MISSING:{t}" for t in REMOTE_DIAGNOSTIC_TOOLS)
        mock_ssh_run.return_value = SSHResult(stdout=missing_lines, returncode=0, error=None)
        result = check_remote_tools("user@host")
        assert len(result) == len(REMOTE_DIAGNOSTIC_TOOLS)
        for tool in REMOTE_DIAGNOSTIC_TOOLS:
            assert tool in result


class TestCollectSSHSmart:
    """Tests for SMART metric collection via SSH."""

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_smartctl_missing_on_remote(self, mock_ssh_run):
        """When smartctl is not available on remote host, should add to missing_tools."""
        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "smartctl" in command and "command -v" in command:
                return SSHResult(stdout="MISSING", returncode=0, error=None)
            # Other commands fail too
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        missing_tools = []
        metrics = collect_ssh_metrics("user@host", missing_tools=missing_tools)
        assert "smartctl" in missing_tools
        assert "node_smart_devices" not in metrics

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_smart_health_passed(self, mock_ssh_run):
        """Should collect SMART health status when smartctl is available."""
        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "smartctl" in command and "command -v" in command:
                return SSHResult(stdout="FOUND", returncode=0, error=None)
            if "smartctl --scan" in command:
                return SSHResult(stdout="/dev/sda -d scsi # /dev/sda", returncode=0, error=None)
            if "smartctl -H /dev/sda" in command:
                return SSHResult(
                    stdout="SMART overall-health self-assessment test result: PASSED",
                    returncode=0, error=None
                )
            if "smartctl -A /dev/sda" in command:
                return SSHResult(stdout="", returncode=0, error=None)
            # Other commands fail
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        metrics = collect_ssh_metrics("user@host")
        assert "node_smart_devices" in metrics
        devices = metrics["node_smart_devices"]
        assert len(devices) == 1
        assert devices[0]["health"] == "passed"
        assert devices[0]["health_code"] == 0

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_smart_health_failed(self, mock_ssh_run):
        """Should detect SMART health FAILED status."""
        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "smartctl" in command and "command -v" in command:
                return SSHResult(stdout="FOUND", returncode=0, error=None)
            if "smartctl --scan" in command:
                return SSHResult(stdout="/dev/sda -d scsi # /dev/sda", returncode=0, error=None)
            if "smartctl -H /dev/sda" in command:
                return SSHResult(
                    stdout="SMART overall-health self-assessment test result: FAILED!",
                    returncode=0, error=None
                )
            if "smartctl -A /dev/sda" in command:
                return SSHResult(stdout="", returncode=0, error=None)
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        metrics = collect_ssh_metrics("user@host")
        devices = metrics["node_smart_devices"]
        assert devices[0]["health"] == "failed"
        assert devices[0]["health_code"] == 2

    @patch("linuxdoctor.ssh_collector.ssh_run")
    def test_smart_with_attributes(self, mock_ssh_run):
        """Should collect SMART attributes from remote host."""
        smart_attrs_output = """smartctl 7.4
=== START OF READ SMART DATA SECTION ===
SMART Attributes Data Structure revision number: 16
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
  9 Temperature_Celsius     0x0023   064   052   000    Old_age   Always       -       36
197 Current_Pending_Sector  0x0032   100   100   000    Old_age   Always       -       2
"""

        def mock_run_side_effect(ssh_connect, command, **kwargs):
            if "smartctl" in command and "command -v" in command:
                return SSHResult(stdout="FOUND", returncode=0, error=None)
            if "smartctl --scan" in command:
                return SSHResult(stdout="/dev/sda -d scsi # /dev/sda", returncode=0, error=None)
            if "smartctl -H /dev/sda" in command:
                return SSHResult(
                    stdout="SMART overall-health self-assessment test result: PASSED",
                    returncode=0, error=None
                )
            if "smartctl -A /dev/sda" in command:
                return SSHResult(stdout=smart_attrs_output, returncode=0, error=None)
            return SSHResult(error="not available")

        mock_ssh_run.side_effect = mock_run_side_effect
        metrics = collect_ssh_metrics("user@host")
        devices = metrics["node_smart_devices"]
        assert len(devices) == 1
        attrs = devices[0]["attributes"]
        assert "reallocated_sectors" in attrs
        assert attrs["reallocated_sectors"] == 0
        assert "temperature" in attrs
        assert attrs["temperature"] == 36
        assert "pending_sectors" in attrs
        assert attrs["pending_sectors"] == 2


class TestParseSSHSmartAttributes:
    """Tests for _parse_ssh_smart_attributes function."""

    def test_parse_standard_attributes(self):
        """Should parse standard smartctl -A output."""
        from linuxdoctor.ssh_collector import _parse_ssh_smart_attributes
        smart_output = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.8.0]
=== START OF READ SMART DATA SECTION ===
SMART Attributes Data Structure revision number: 16
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
  9 Power_On_Hours          0x0032   093   093   000    Old_age   Always       -       6789
194 Temperature_Celsius     0x0023   064   052   000    Old_age   Always       -       36
"""
        attrs = _parse_ssh_smart_attributes(smart_output)
        assert "Reallocated_Sector_Ct" in attrs
        assert attrs["Reallocated_Sector_Ct"]["raw"] == 0
        assert attrs["Reallocated_Sector_Ct"]["value"] == 100
        assert "Temperature_Celsius" in attrs
        assert attrs["Temperature_Celsius"]["raw"] == 36
        assert "Power_On_Hours" in attrs
        assert attrs["Power_On_Hours"]["raw"] == 6789

    def test_parse_empty_output(self):
        """Should handle empty smartctl output."""
        from linuxdoctor.ssh_collector import _parse_ssh_smart_attributes
        attrs = _parse_ssh_smart_attributes("")
        assert attrs == {}

    def test_parse_failing_attribute(self):
        """Should detect WHEN_FAILED column for failing attributes."""
        from linuxdoctor.ssh_collector import _parse_ssh_smart_attributes
        smart_output = """ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   001   001   010    Pre-fail  Always   FAILING_NOW  100
"""
        attrs = _parse_ssh_smart_attributes(smart_output)
        assert attrs["Reallocated_Sector_Ct"]["when_failed"] == "FAILING_NOW"
        assert attrs["Reallocated_Sector_Ct"]["raw"] == 100