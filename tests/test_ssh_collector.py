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