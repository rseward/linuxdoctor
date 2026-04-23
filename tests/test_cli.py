"""Tests for the CLI module."""

import json
import pytest
from click.testing import CliRunner
from unittest.mock import patch
from linuxdoctor.cli import cli


class TestCli:
    """Tests for the linuxdoctor CLI."""

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "analyze" in result.output
        assert "analyzenode" in result.output
        assert "list-hosts" in result.output

    def test_analyze_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--json-output" in result.output
        assert "--check" in result.output
        assert "--threshold" in result.output

    def test_analyze_command(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze"])
        assert result.exit_code == 0
        assert "linuxdoctor" in result.output
        assert "Host Analysis Report" in result.output

    def test_analyze_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "host" in data
        assert "metrics" in data

    def test_analyze_no_recs(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "--no-recommendations"])
        assert result.exit_code == 0
        assert "RECOMMENDATIONS" not in result.output

    def test_analyze_specific_check(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "-c", "cpu"])
        assert result.exit_code == 0
        assert "CPU" in result.output

    def test_analyze_threshold(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "-t", "strict"])
        assert result.exit_code == 0

    def test_analyzenode_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyzenode", "--help"])
        assert result.exit_code == 0
        assert "NODE_ADDRESS" in result.output
        assert "--port" in result.output
        assert "--threshold" in result.output
        assert "--verbose" in result.output

    def test_analyzenode_nonexistent_host(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyzenode", "192.0.2.1", "--port", "9999"])
        # Should output an error (exit code 0 since we don't auto-exit on error in CLI)
        assert "Error" in result.output or "error" in result.output.lower()

    def test_list_hosts_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["list-hosts", "--help"])
        assert result.exit_code == 0
        assert "PROMETHEUS_URL" in result.output
        assert "--timeout" in result.output

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_registerhost_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["registerhost", "--help"])
        assert result.exit_code == 0
        assert "--cpu-cores" in result.output
        assert "HOST" in result.output

    def test_registerhost_command(self, tmp_path):
        runner = CliRunner()
        registry_path = str(tmp_path / "hosts.yaml")
        result = runner.invoke(cli, ["registerhost", "testhost", "--cpu-cores", "8", "--registry", registry_path])
        assert result.exit_code == 0
        assert "Registered" in result.output
        assert "cpu_cores" in result.output

    def test_registerhost_no_options(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["registerhost", "testhost"])
        assert result.exit_code == 1
        assert "No metadata" in result.output

    def test_list_registered_empty(self, tmp_path):
        runner = CliRunner()
        registry_path = str(tmp_path / "hosts.yaml")
        result = runner.invoke(cli, ["list-registered", "--registry", registry_path])
        assert result.exit_code == 0
        assert "No hosts" in result.output

    def test_unregisterhost_not_found(self, tmp_path):
        runner = CliRunner()
        registry_path = str(tmp_path / "hosts.yaml")
        result = runner.invoke(cli, ["unregisterhost", "nothere", "--registry", registry_path])
        assert result.exit_code == 1

    def test_register_and_list(self, tmp_path):
        runner = CliRunner()
        registry_path = str(tmp_path / "hosts.yaml")
        # Register a host
        result = runner.invoke(cli, ["registerhost", "myserver", "--cpu-cores", "4", "--registry", registry_path])
        assert result.exit_code == 0
        # List registered hosts
        result = runner.invoke(cli, ["list-registered", "--registry", registry_path])
        assert result.exit_code == 0
        assert "myserver" in result.output

    def test_analyzenode_resample_option(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyzenode", "--help"])
        assert result.exit_code == 0
        assert "--resample" in result.output