"""Tests for the analyzenode module."""

import json
import pytest
from unittest.mock import patch, MagicMock
from linuxdoctor.analyzenode import (
    analyze_remote_node,
    analyze_cpu,
    analyze_memory,
    analyze_disk,
    analyze_disk_io,
    analyze_network,
    analyze_context_switching,
    parse_metrics,
    _get_thresholds,
    NodeMetric,
    Recommendation,
)


# ---------------------------------------------------------------------------
# Sample metrics for testing
# ---------------------------------------------------------------------------

SAMPLE_METRICS_TEXT = """# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 1000.0
node_cpu_seconds_total{cpu="0",mode="iowait"} 50.0
node_cpu_seconds_total{cpu="0",mode="system"} 100.0
node_cpu_seconds_total{cpu="1",mode="idle"} 900.0
node_cpu_seconds_total{cpu="1",mode="iowait"} 30.0
node_cpu_seconds_total{cpu="1",mode="system"} 90.0
node_load1 2.5
node_load5 2.0
node_load15 1.5
node_memory_MemTotal_bytes 16777216000
node_memory_MemAvailable_bytes 4294967296
node_filesystem_size_bytes{mountpoint="/"} 500000000000
node_filesystem_avail_bytes{mountpoint="/"} 100000000000
node_context_switches_total 5000000
node_disk_io_time_seconds_total{device="sda"} 500.0
node_network_receive_bytes_total{device="eth0"} 1000000000
node_network_transmit_bytes_total{device="eth0"} 500000000
node_network_receive_errs_total{device="eth0"} 0
node_network_transmit_errs_total{device="eth0"} 0
"""


class TestParseMetrics:
    """Tests for the parse_metrics function."""

    def test_parse_simple_metric(self):
        text = "node_load1 2.5\n"
        result = parse_metrics(text)
        assert "node_load1" in result
        assert result["node_load1"] == 2.5

    def test_parse_labeled_metric(self):
        text = 'node_cpu_seconds_total{cpu="0",mode="idle"} 1000.0\n'
        result = parse_metrics(text)
        assert "node_cpu_seconds_total" in result
        assert isinstance(result["node_cpu_seconds_total"], list)
        assert result["node_cpu_seconds_total"][0]["labels"]["cpu"] == "0"
        assert result["node_cpu_seconds_total"][0]["value"] == 1000.0

    def test_skip_comments(self):
        text = "# HELP foo bar\n# TYPE foo counter\nfoo 42\n"
        result = parse_metrics(text)
        assert result["foo"] == 42

    def test_skip_empty_lines(self):
        text = "node_load1 1.0\n\nnode_load5 0.5\n"
        result = parse_metrics(text)
        assert result["node_load1"] == 1.0
        assert result["node_load5"] == 0.5


class TestThresholds:
    """Tests for threshold profiles."""

    def test_default_thresholds(self):
        t = _get_thresholds("default")
        assert "cpu_idle_warn_pct" in t
        assert t["cpu_idle_warn_pct"] == 20

    def test_strict_thresholds(self):
        t = _get_thresholds("strict")
        assert t["cpu_idle_warn_pct"] == 30
        assert t["mem_used_warn_pct"] == 75

    def test_relaxed_thresholds(self):
        t = _get_thresholds("relaxed")
        assert t["cpu_idle_warn_pct"] == 10

    def test_unknown_profile_returns_default(self):
        t = _get_thresholds("nonexistent")
        assert t == _get_thresholds("default")


class TestAnalyzeCpu:
    """Tests for CPU analysis."""

    def test_healthy_cpu(self):
        metrics = {
            "node_cpu_seconds_total": [
                {"labels": {"cpu": "0", "mode": "idle"}, "value": 800},
                {"labels": {"cpu": "0", "mode": "iowait"}, "value": 10},
                {"labels": {"cpu": "0", "mode": "system"}, "value": 50},
            ],
            "node_load1": 0.5,
            "node_load5": 0.4,
            "node_load15": 0.3,
        }
        thresholds = _get_thresholds("default")
        recs, lines = analyze_cpu(metrics, thresholds)
        assert len(recs) == 0
        assert any("CPU ANALYSIS" in line for line in lines)

    def test_low_idle_cpu(self):
        metrics = {
            "node_cpu_seconds_total": [
                {"labels": {"cpu": "0", "mode": "idle"}, "value": 50},
                {"labels": {"cpu": "0", "mode": "iowait"}, "value": 10},
                {"labels": {"cpu": "0", "mode": "system"}, "value": 100},
            ],
            "node_load1": 5.0,
            "node_load5": 4.0,
            "node_load15": 3.0,
        }
        thresholds = _get_thresholds("default")
        recs, lines = analyze_cpu(metrics, thresholds)
        # Should warn about low idle and high load
        assert any(r.category == "cpu" for r in recs)

    def test_no_cpu_metrics(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        recs, lines = analyze_cpu(metrics, thresholds)
        assert len(recs) == 0
        assert any("not found" in line for line in lines)


class TestAnalyzeMemory:
    """Tests for memory analysis."""

    def test_healthy_memory(self):
        metrics = {
            "node_memory_MemTotal_bytes": 16e9,
            "node_memory_MemAvailable_bytes": 10e9,
        }
        thresholds = _get_thresholds("default")
        recs, lines = analyze_memory(metrics, thresholds)
        assert len(recs) == 0

    def test_high_memory_usage(self):
        metrics = {
            "node_memory_MemTotal_bytes": 16e9,
            "node_memory_MemAvailable_bytes": 1e9,  # ~94% used
        }
        thresholds = _get_thresholds("default")
        recs, lines = analyze_memory(metrics, thresholds)
        assert len(recs) >= 1
        assert recs[0].category == "memory"

    def test_no_memory_metrics(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        recs, lines = analyze_memory(metrics, thresholds)
        assert any("not found" in line for line in lines)


class TestAnalyzeDisk:
    """Tests for disk analysis."""

    def test_healthy_disk(self):
        metrics = {
            "node_filesystem_size_bytes": [
                {"labels": {"mountpoint": "/"}, "value": 500e9},
            ],
            "node_filesystem_avail_bytes": [
                {"labels": {"mountpoint": "/"}, "value": 300e9},
            ],
        }
        thresholds = _get_thresholds("default")
        recs, lines = analyze_disk(metrics, thresholds)
        assert len(recs) == 0

    def test_critical_disk_usage(self):
        metrics = {
            "node_filesystem_size_bytes": [
                {"labels": {"mountpoint": "/"}, "value": 500e9},
            ],
            "node_filesystem_avail_bytes": [
                {"labels": {"mountpoint": "/"}, "value": 10e9},  # 98% used
            ],
        }
        thresholds = _get_thresholds("default")
        recs, lines = analyze_disk(metrics, thresholds)
        assert len(recs) >= 1
        assert recs[0].severity == "critical"

    def test_no_disk_metrics(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        recs, lines = analyze_disk(metrics, thresholds)
        assert any("not found" in line for line in lines)


class TestAnalyzeContextSwitching:
    """Tests for context switching analysis."""

    def test_normal_context_switches(self):
        metrics = {"node_context_switches_total": 1000.0}
        thresholds = _get_thresholds("default")
        recs, lines = analyze_context_switching(metrics, thresholds)
        assert len(recs) == 0

    def test_high_context_switches(self):
        metrics = {"node_context_switches_total": 50000000.0}
        thresholds = _get_thresholds("default")
        recs, lines = analyze_context_switching(metrics, thresholds)
        assert len(recs) >= 1
        assert recs[0].category == "context_switching"

    def test_missing_context_switches(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        recs, lines = analyze_context_switching(metrics, thresholds)
        assert any("not found" in line for line in lines)


class TestAnalyzeRemoteNode:
    """Tests for the main analyze_remote_node function."""

    @patch("linuxdoctor.analyzenode.fetch_metrics_text")
    def test_human_readable_output(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_METRICS_TEXT
        result = analyze_remote_node("localhost", port=9100)
        assert "localhost" in result
        assert "CPU ANALYSIS" in result
        assert "MEMORY ANALYSIS" in result

    @patch("linuxdoctor.analyzenode.fetch_metrics_text")
    def test_json_output(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_METRICS_TEXT
        result = analyze_remote_node("localhost", port=9100, json_output=True)
        data = json.loads(result)
        assert "metrics" in data
        assert "node" in data

    @patch("linuxdoctor.analyzenode.fetch_metrics_text")
    def test_no_recommendations(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_METRICS_TEXT
        result = analyze_remote_node("localhost", port=9100, include_recommendations=False)
        # When recommendations are disabled, the summary section should show healthy
        # (individual analysis sections still appear, but no recommendation details)
        assert "⚠️  RECOMMENDATIONS" not in result

    def test_connection_failure(self):
        result = analyze_remote_node("192.0.2.1", port=9100, json_output=True)
        data = json.loads(result)
        assert "error" in data

    @patch("linuxdoctor.analyzenode.fetch_metrics_text")
    def test_threshold_profiles(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_METRICS_TEXT
        for profile in ["default", "strict", "relaxed"]:
            result = analyze_remote_node("localhost", port=9100, threshold_profile=profile)
            assert "CPU ANALYSIS" in result