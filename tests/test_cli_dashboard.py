"""Tests for the CLI dashboard module."""

import json
import pytest
from unittest.mock import patch, MagicMock

from linuxdoctor.cli_dashboard import (
    _health_icon,
    _health_text,
    _render_table,
    _render_json,
    scan_hosts_for_dashboard,
)
from linuxdoctor.web import HostHealth


class TestHealthIcon:
    """Tests for _health_icon helper."""

    def test_healthy(self):
        assert _health_icon("healthy") == "✅"

    def test_warning(self):
        assert _health_icon("warning") == "⚠️ "

    def test_critical(self):
        assert _health_icon("critical") == "🔴"

    def test_unknown(self):
        assert _health_icon("unknown") == "❓"

    def test_invalid(self):
        assert _health_icon("bogus") == "❓"


class TestHealthText:
    """Tests for _health_text helper."""

    def test_healthy(self):
        assert _health_text("healthy") == "OK"

    def test_warning(self):
        assert _health_text("warning") == "WARN"

    def test_critical(self):
        assert _health_text("critical") == "CRIT"

    def test_unknown(self):
        assert _health_text("unknown") == "?"

    def test_invalid(self):
        assert _health_text("bogus") == "??"


class TestRenderTable:
    """Tests for _render_table."""

    def test_empty_results(self):
        output = _render_table([])
        assert "No hosts" in output

    def test_single_healthy_host(self):
        health = HostHealth(
            host="server1",
            reachable=True,
            cpu_health="healthy",
            context_health="healthy",
            io_wait_health="healthy",
            disk_health="healthy",
        )
        output = _render_table([health])
        assert "server1" in output
        assert "OK" in output

    def test_single_unreachable_host(self):
        health = HostHealth(
            host="down1",
            reachable=False,
            error="Cannot connect",
        )
        output = _render_table([health])
        assert "down1" in output
        assert "DOWN" in output
        assert "Cannot connect" in output

    def test_critical_host(self):
        health = HostHealth(
            host="badserver",
            reachable=True,
            cpu_health="critical",
            cpu_detail="CPU idle at 2%",
            cpu_suggestion="Check top consumers",
            context_health="healthy",
            io_wait_health="healthy",
            disk_health="healthy",
        )
        output = _render_table([health])
        assert "badserver" in output
        assert "CRIT" in output

    def test_ssh_host(self):
        health = HostHealth(
            host="remote1",
            reachable=True,
            collection_method="ssh",
            ssh_connect="admin@remote1",
            cpu_health="healthy",
            context_health="healthy",
            io_wait_health="healthy",
            disk_health="healthy",
        )
        output = _render_table([health])
        assert "remote1" in output
        assert "SSH" in output

    def test_multiple_hosts(self):
        hosts = [
            HostHealth(host="s1", reachable=True, cpu_health="healthy",
                       context_health="healthy", io_wait_health="healthy", disk_health="healthy"),
            HostHealth(host="s2", reachable=True, cpu_health="warning",
                       cpu_detail="CPU idle 15%",
                       context_health="healthy", io_wait_health="healthy", disk_health="healthy"),
        ]
        output = _render_table(hosts)
        assert "s1" in output
        assert "s2" in output
        assert "WARN" in output

    def test_warning_detail_section(self):
        health = HostHealth(
            host="warnhost",
            reachable=True,
            cpu_health="warning",
            cpu_detail="CPU idle at 15%",
            cpu_suggestion="Check processes",
            context_health="healthy",
            io_wait_health="healthy",
            disk_health="healthy",
        )
        output = _render_table([health])
        assert "ISSUE DETAILS" in output
        assert "CPU idle at 15%" in output
        assert "Check processes" in output


class TestRenderJson:
    """Tests for _render_json."""

    def test_single_host(self):
        health = HostHealth(
            host="server1",
            reachable=True,
            cpu_health="healthy",
        )
        output = _render_json([health])
        data = json.loads(output)
        assert "hosts" in data
        assert "server1" in data["hosts"]
        assert data["hosts"]["server1"]["cpu_health"] == "healthy"

    def test_timestamp_in_output(self):
        health = HostHealth(host="server1")
        output = _render_json([health])
        data = json.loads(output)
        assert "timestamp" in data

    def test_multiple_hosts(self):
        hosts = [
            HostHealth(host="s1", reachable=True, cpu_health="healthy"),
            HostHealth(host="s2", reachable=False, error="timeout"),
        ]
        output = _render_json(hosts)
        data = json.loads(output)
        assert len(data["hosts"]) == 2
        assert data["hosts"]["s2"]["error"] == "timeout"


class TestScanHostsForDashboard:
    """Tests for scan_hosts_for_dashboard."""

    @patch("linuxdoctor.cli_dashboard.scan_host")
    def test_scan_single_host(self, mock_scan):
        mock_scan.return_value = HostHealth(
            host="server1", reachable=True, cpu_health="healthy",
        )
        results = scan_hosts_for_dashboard(hosts=["server1"], json_output=True)
        assert len(results) == 1
        assert results[0].host == "server1"

    @patch("linuxdoctor.cli_dashboard.scan_host")
    def test_scan_multiple_hosts(self, mock_scan):
        mock_scan.side_effect = [
            HostHealth(host="s1", reachable=True),
            HostHealth(host="s2", reachable=True),
        ]
        results = scan_hosts_for_dashboard(hosts=["s1", "s2"], json_output=True)
        assert len(results) == 2

    @patch("linuxdoctor.cli_dashboard.scan_host")
    def test_scan_with_resample(self, mock_scan):
        """With resample, scan_host is called twice per host."""
        mock_scan.return_value = HostHealth(
            host="server1", reachable=True, cpu_health="healthy",
        )
        results = scan_hosts_for_dashboard(
            hosts=["server1"], resample=True, resample_interval=1,
            json_output=True,
        )
        assert mock_scan.call_count == 2
        assert len(results) == 1

    @patch("linuxdoctor.cli_dashboard.scan_host")
    def test_scan_unreachable_host_skips_resample(self, mock_scan):
        """Unreachable host should not be resampled."""
        mock_scan.return_value = HostHealth(
            host="down1", reachable=False, error="Cannot connect",
        )
        results = scan_hosts_for_dashboard(
            hosts=["down1"], resample=True, resample_interval=1,
            json_output=True,
        )
        # Only one call since host is unreachable
        assert mock_scan.call_count == 1
        assert len(results) == 1
        assert not results[0].reachable

    @patch("linuxdoctor.cli_dashboard.scan_host")
    def test_empty_hosts(self, mock_scan):
        results = scan_hosts_for_dashboard(hosts=[], json_output=True)
        assert mock_scan.call_count == 0
        assert len(results) == 0


class TestDashboardCLICommand:
    """Integration tests for the dashboard CLI command."""

    @patch("linuxdoctor.cli_dashboard.scan_hosts_for_dashboard")
    def test_dashboard_no_hosts(self, mock_scan, tmp_path):
        """Dashboard should inform user when no hosts registered."""
        from click.testing import CliRunner
        from linuxdoctor.cli import cli

        registry_path = str(tmp_path / "empty_hosts.yaml")
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--registry", registry_path])
        assert result.exit_code == 1
        assert "No registered hosts" in result.output

    @patch("linuxdoctor.cli_dashboard.scan_hosts_for_dashboard")
    def test_dashboard_json_output(self, mock_scan, tmp_path):
        """Dashboard should output JSON with --json flag."""
        from click.testing import CliRunner
        from linuxdoctor.cli import cli
        from linuxdoctor.host_registry import register_host

        registry_path = str(tmp_path / "hosts.yaml")
        register_host("server1", cpu_cores=4, path=registry_path)

        mock_scan.return_value = [
            HostHealth(host="server1", reachable=True, cpu_health="healthy",
                       context_health="healthy", io_wait_health="healthy", disk_health="healthy"),
        ]

        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--json", "--registry", registry_path])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "hosts" in data
        assert "server1" in data["hosts"]

    @patch("linuxdoctor.cli_dashboard.scan_hosts_for_dashboard")
    def test_dashboard_table_output(self, mock_scan, tmp_path):
        """Dashboard should output a table by default."""
        from click.testing import CliRunner
        from linuxdoctor.cli import cli
        from linuxdoctor.host_registry import register_host

        registry_path = str(tmp_path / "hosts.yaml")
        register_host("server1", cpu_cores=4, path=registry_path)

        mock_scan.return_value = [
            HostHealth(host="server1", reachable=True, cpu_health="healthy",
                       context_health="healthy", io_wait_health="healthy", disk_health="healthy"),
        ]

        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--registry", registry_path])
        assert result.exit_code == 0
        assert "server1" in result.output
        assert "OK" in result.output

    @patch("linuxdoctor.cli_dashboard.scan_hosts_for_dashboard")
    def test_dashboard_critical_exit_code(self, mock_scan, tmp_path):
        """Dashboard should exit with code 1 if critical issues found."""
        from click.testing import CliRunner
        from linuxdoctor.cli import cli
        from linuxdoctor.host_registry import register_host

        registry_path = str(tmp_path / "hosts.yaml")
        register_host("badhost", cpu_cores=4, path=registry_path)

        mock_scan.return_value = [
            HostHealth(host="badhost", reachable=True,
                       cpu_health="critical", cpu_detail="CPU overloaded",
                       context_health="healthy", io_wait_health="healthy", disk_health="healthy"),
        ]

        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--registry", registry_path])
        assert result.exit_code == 1