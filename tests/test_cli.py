"""Tests for the CLI module."""

import pytest
from click.testing import CliRunner
from linuxdoctor.cli import cli


class TestCli:
    """Tests for the linuxdoctor CLI."""

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "analyze" in result.output
        assert "analyzenode" in result.output

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
        import json
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

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output