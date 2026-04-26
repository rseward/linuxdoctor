"""Tests for the CLI dashboard module."""

import json
import pytest
from unittest.mock import patch, MagicMock

from linuxdoctor.cli_dashboard import (
    _health_icon,
    _health_text,
    _colorize,
    _colorize_health,
    _colorize_status,
    _center_col,
    _render_table,
    _render_json,
    scan_hosts_for_dashboard,
    ANSI_RESET,
    ANSI_GREEN,
    ANSI_YELLOW,
    ANSI_RED,
    ANSI_BOLD_GREEN,
    ANSI_BOLD_RED,
    ANSI_GRAY,
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


# ---------------------------------------------------------------------------
# Tests for color functionality
# ---------------------------------------------------------------------------

class TestColorize:
    """Tests for _colorize helper."""

    def test_colorize_enabled(self):
        result = _colorize("hello", ANSI_RED, use_color=True)
        assert result == f"{ANSI_RED}hello{ANSI_RESET}"

    def test_colorize_disabled(self):
        result = _colorize("hello", ANSI_RED, use_color=False)
        assert result == "hello"

    def test_colorize_preserves_text(self):
        result = _colorize("CRIT", ANSI_RED, use_color=True)
        assert "CRIT" in result
        assert ANSI_RED in result


class TestColorizeHealth:
    """Tests for _colorize_health helper."""

    def test_healthy_green(self):
        result = _colorize_health("OK", "healthy", use_color=True)
        assert result == f"{ANSI_GREEN}OK{ANSI_RESET}"

    def test_warning_yellow(self):
        result = _colorize_health("WARN", "warning", use_color=True)
        assert result == f"{ANSI_YELLOW}WARN{ANSI_RESET}"

    def test_critical_red(self):
        result = _colorize_health("CRIT", "critical", use_color=True)
        assert result == f"{ANSI_RED}CRIT{ANSI_RESET}"

    def test_unknown_gray(self):
        result = _colorize_health("?", "unknown", use_color=True)
        assert result == f"{ANSI_GRAY}?{ANSI_RESET}"

    def test_no_color_returns_plain(self):
        result = _colorize_health("OK", "healthy", use_color=False)
        assert result == "OK"
        assert ANSI_GREEN not in result


class TestColorizeStatus:
    """Tests for _colorize_status helper."""

    def test_up_bold_green(self):
        result = _colorize_status("UP", use_color=True)
        assert result == f"{ANSI_BOLD_GREEN}UP{ANSI_RESET}"

    def test_down_bold_red(self):
        result = _colorize_status("DOWN", use_color=True)
        assert result == f"{ANSI_BOLD_RED}DOWN{ANSI_RESET}"

    def test_no_color_returns_plain(self):
        assert _colorize_status("UP", use_color=False) == "UP"
        assert _colorize_status("DOWN", use_color=False) == "DOWN"


class TestCenterCol:
    """Tests for _center_col helper."""

    def test_center_exact_width(self):
        result = _center_col("OK", 2, 8)
        # 8 - 2 = 6 padding: 3 left, 3 right
        assert result == "   OK   "

    def test_center_narrower(self):
        result = _center_col("CRIT", 4, 8)
        # 8 - 4 = 4 padding: 2 left, 2 right
        assert result == "  CRIT  "

    def test_center_with_ansi(self):
        colored = f"{ANSI_RED}CRIT{ANSI_RESET}"
        result = _center_col(colored, 4, 8)
        # Should have spaces + ANSI-wrapped text + spaces
        assert result.startswith("  ")
        assert result.endswith("  ")
        assert "CRIT" in result
        assert ANSI_RED in result


class TestRenderTableColor:
    """Tests for color output in _render_table."""

    def test_color_enabled_contains_ansi_codes(self):
        health = HostHealth(
            host="server1", reachable=True,
            cpu_health="critical", context_health="warning",
            io_wait_health="healthy", disk_health="healthy",
        )
        output = _render_table([health], use_color=True)
        assert ANSI_RED in output  # CRIT is red
        assert ANSI_YELLOW in output  # WARN is yellow
        assert ANSI_GREEN in output  # OK is green
        assert ANSI_BOLD_GREEN in output  # UP is bold green

    def test_color_disabled_no_ansi_codes(self):
        health = HostHealth(
            host="server1", reachable=True,
            cpu_health="critical", context_health="warning",
            io_wait_health="healthy", disk_health="healthy",
        )
        output = _render_table([health], use_color=False)
        assert ANSI_RED not in output
        assert ANSI_YELLOW not in output
        assert ANSI_GREEN not in output
        assert ANSI_BOLD_GREEN not in output
        assert "CRIT" in output
        assert "WARN" in output
        assert "OK" in output
        assert "UP" in output

    def test_color_down_host_has_red(self):
        health = HostHealth(
            host="down1", reachable=False, error="Cannot connect",
        )
        output = _render_table([health], use_color=True)
        assert ANSI_BOLD_RED in output  # DOWN is bold red

    def test_color_summary_lines(self):
        health = HostHealth(
            host="server1", reachable=True,
            cpu_health="critical", cpu_detail="CPU at 99%",
            context_health="healthy", io_wait_health="healthy", disk_health="healthy",
        )
        output = _render_table([health], use_color=True)
        # Summary line should be red for critical
        assert ANSI_RED in output

    def test_no_color_summary_lines_plain(self):
        health = HostHealth(
            host="server1", reachable=True,
            cpu_health="critical", cpu_detail="CPU at 99%",
            context_health="healthy", io_wait_health="healthy", disk_health="healthy",
        )
        output = _render_table([health], use_color=False)
        # Should contain text but no ANSI codes in summary
        lines = output.split("\n")
        summary_lines = [l for l in lines if "host(s)" in l]
        for line in summary_lines:
            assert ANSI_RED not in line

    def test_table_alignment_with_color(self):
        """Verify table column alignment is preserved when color is enabled."""
        health = HostHealth(
            host="server1", reachable=True,
            cpu_health="healthy", context_health="healthy",
            io_wait_health="healthy", disk_health="healthy",
        )
        output_colored = _render_table([health], use_color=True)
        output_plain = _render_table([health], use_color=False)
        # Both should have the same separator lines (which indicate alignment)
        sep_colored = [l for l in output_colored.split("\n") if l.startswith("+")]
        sep_plain = [l for l in output_plain.split("\n") if l.startswith("+")]
        assert sep_colored == sep_plain


class TestDashboardNoColorOption:
    """Integration tests for --no-color CLI option."""

    @patch("linuxdoctor.cli_dashboard.scan_hosts_for_dashboard")
    def test_no_color_flag(self, mock_scan, tmp_path):
        """--no-color should produce output without ANSI escape codes."""
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
        result = runner.invoke(cli, ["dashboard", "--no-color", "--registry", registry_path])
        assert result.exit_code == 0
        # No ANSI escape sequences in output
        assert "\033[" not in result.output
        assert "OK" in result.output

    @patch("linuxdoctor.cli_dashboard.scan_hosts_for_dashboard")
    def test_default_has_color(self, mock_scan, tmp_path):
        """Default dashboard (without --no-color) should include ANSI codes."""
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
        result = runner.invoke(cli, ["dashboard", "--registry", registry_path], color=True)
        assert result.exit_code == 0
        # Should contain ANSI escape codes
        assert "\033[" in result.output