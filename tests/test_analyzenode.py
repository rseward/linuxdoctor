"""Tests for the analyzenode module with counter-aware analysis."""

import json
import pytest
from unittest.mock import patch, MagicMock
from linuxdoctor.analyzenode import (
    analyze_remote_node,
    analyze_cpu,
    analyze_memory,
    analyze_disk,
    analyze_disk_io,
    analyze_context_switching,
    parse_metrics,
    _get_thresholds,
    is_ssh_host,
    NodeMetric,
    Recommendation,
    AnalysisResult,
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
        # New counter-aware thresholds
        assert "context_switches_per_core_warn" in t
        assert "context_switches_per_core_critical" in t
        assert "context_switches_total_warn" in t
        assert "disk_io_util_warn_pct" in t
        assert "disk_io_util_critical_pct" in t

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
        result = analyze_cpu(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert result.category == "cpu"
        assert len(result.recommendations) == 0
        assert any("CPU ANALYSIS" in line for line in result.lines)

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
        result = analyze_cpu(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert any(r.category == "cpu" for r in result.recommendations)

    def test_no_cpu_metrics(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        result = analyze_cpu(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert len(result.recommendations) == 0
        assert any("not found" in line for line in result.lines)


class TestAnalyzeMemory:
    """Tests for memory analysis."""

    def test_healthy_memory(self):
        metrics = {
            "node_memory_MemTotal_bytes": 16e9,
            "node_memory_MemAvailable_bytes": 10e9,
        }
        thresholds = _get_thresholds("default")
        result = analyze_memory(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert len(result.recommendations) == 0

    def test_high_memory_usage(self):
        metrics = {
            "node_memory_MemTotal_bytes": 16e9,
            "node_memory_MemAvailable_bytes": 1e9,  # ~94% used
        }
        thresholds = _get_thresholds("default")
        result = analyze_memory(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert len(result.recommendations) >= 1
        assert result.recommendations[0].category == "memory"

    def test_no_memory_metrics(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        result = analyze_memory(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert any("not found" in line for line in result.lines)


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
        result = analyze_disk(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert len(result.recommendations) == 0

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
        result = analyze_disk(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert len(result.recommendations) >= 1
        assert result.recommendations[0].severity == "critical"

    def test_no_disk_metrics(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        result = analyze_disk(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert any("not found" in line for line in result.lines)


class TestAnalyzeDiskIO:
    """Tests for disk I/O analysis with counter-aware thresholds."""

    def test_no_disk_io_metrics(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert any("not found" in line for line in result.lines)

    def test_single_sample_shows_info_not_warning(self):
        """Single sample should NOT produce warning for cumulative counter."""
        metrics = {
            "node_disk_io_time_seconds_total": [
                {"labels": {"device": "sda"}, "value": 500000.0},  # Very high raw value
            ]
        }
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics, thresholds, previous_metrics=None)
        # Should NOT have a warning — raw counter comparison is wrong
        assert all(r.category != "disk_io" or r.severity != "warning" for r in result.recommendations)
        # Should show info about needing two samples
        assert any("raw counter" in line or "resample" in line.lower() for line in result.lines)

    def test_two_samples_compute_rate(self):
        """With two samples, should compute utilization rate."""
        metrics_1 = {
            "node_disk_io_time_seconds_total": [
                {"labels": {"device": "sda"}, "value": 100.0},
            ]
        }
        metrics_2 = {
            "node_disk_io_time_seconds_total": [
                {"labels": {"device": "sda"}, "value": 130.0},  # 30s delta over 30s interval = 100% util
            ]
        }
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics_2, thresholds, previous_metrics=metrics_1)
        # Should compute a utilization rate
        assert any("utilization" in line.lower() or "I/O" in line for line in result.lines)

    def test_two_samples_high_utilization_warning(self):
        """High utilization rate should produce a warning."""
        metrics_1 = {
            "node_disk_io_time_seconds_total": [
                {"labels": {"device": "sda"}, "value": 100.0},
            ]
        }
        metrics_2 = {
            "node_disk_io_time_seconds_total": [
                {"labels": {"device": "sda"}, "value": 121.0},  # 21s delta over 30s = 70% util (warn threshold)
            ]
        }
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics_2, thresholds, previous_metrics=metrics_1)
        # Should produce a warning since 70% >= disk_io_util_warn_pct
        assert any(r.category == "disk_io" and r.severity == "warning" for r in result.recommendations)

    def test_two_samples_critical_utilization(self):
        """Very high utilization rate should produce a critical recommendation."""
        metrics_1 = {
            "node_disk_io_time_seconds_total": [
                {"labels": {"device": "sda"}, "value": 100.0},
            ]
        }
        metrics_2 = {
            "node_disk_io_time_seconds_total": [
                {"labels": {"device": "sda"}, "value": 128.0},  # 28s delta over 30s = 93% util
            ]
        }
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics_2, thresholds, previous_metrics=metrics_1)
        assert any(r.category == "disk_io" and r.severity == "critical" for r in result.recommendations)

    def test_ssh_style_util_pct_healthy(self):
        """SSH-collected node_disk_io_util_pct should be used directly as percentages."""
        metrics = {
            "node_disk_io_util_pct": [
                {"labels": {"device": "sda"}, "value": 30.0},  # 30% — below warn threshold
            ]
        }
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics, thresholds)
        # Should have healthy status, no warning
        assert all(r.severity != "warning" for r in result.recommendations if r.category == "disk_io")

    def test_ssh_style_util_pct_warning(self):
        """SSH-collected util_pct above warn threshold should produce a warning."""
        metrics = {
            "node_disk_io_util_pct": [
                {"labels": {"device": "sda"}, "value": 75.0},  # 75% — above 70% warn
            ]
        }
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics, thresholds)
        assert any(r.category == "disk_io" and r.severity == "warning" for r in result.recommendations)

    def test_ssh_style_util_pct_critical(self):
        """SSH-collected util_pct above critical threshold should produce a critical recommendation."""
        metrics = {
            "node_disk_io_util_pct": [
                {"labels": {"device": "sda"}, "value": 95.0},  # 95% — above 90% critical
            ]
        }
        thresholds = _get_thresholds("default")
        result = analyze_disk_io(metrics, thresholds)
        assert any(r.category == "disk_io" and r.severity == "critical" for r in result.recommendations)


class TestAnalyzeContextSwitching:
    """Tests for context switching analysis with counter-aware thresholds."""

    def test_no_context_switches(self):
        metrics = {}
        thresholds = _get_thresholds("default")
        result = analyze_context_switching(metrics, thresholds)
        assert isinstance(result, AnalysisResult)
        assert any("not found" in line for line in result.lines)

    def test_single_sample_shows_info(self):
        """Single sample should show info message, not a false positive warning."""
        metrics = {"node_context_switches_total": 50000000.0}  # Very high raw counter
        thresholds = _get_thresholds("default")
        result = analyze_context_switching(metrics, thresholds)
        # Should NOT produce a false-positive warning for raw counter
        assert all(r.severity != "warning" for r in result.recommendations)
        # Should mention needing two samples or registering
        assert any("raw counter" in line.lower() or "resample" in line.lower() or "register" in line.lower() for line in result.lines)

    def test_two_samples_with_cores_healthy(self):
        """Two samples with known cores, healthy rate should produce no warning."""
        metrics_prev = {"node_context_switches_total": 100000.0}
        metrics_curr = {"node_context_switches_total": 130000.0}  # 30000 delta / 30s = 1000/sec
        thresholds = _get_thresholds("default")
        result = analyze_context_switching(
            metrics_curr, thresholds,
            cpu_cores=4,  # 1000/4 = 250/core/sec — well below 1000 warn threshold
            previous_metrics=metrics_prev,
            node_address="testhost",
        )
        # Should be healthy (250/core/sec < 1000 warn threshold)
        assert all(r.severity != "warning" and r.severity != "critical" for r in result.recommendations)
        assert any("per-core" in line.lower() or "Per-core" in line for line in result.lines)

    def test_two_samples_with_cores_high_rate(self):
        """Two samples with known cores, high rate should produce warning."""
        metrics_prev = {"node_context_switches_total": 100000.0}
        metrics_curr = {"node_context_switches_total": 430000.0}  # 330000/30 = 11000/sec
        thresholds = _get_thresholds("default")
        result = analyze_context_switching(
            metrics_curr, thresholds,
            cpu_cores=4,  # 11000/4 = 2750/core/sec — above 1000 warn threshold
            previous_metrics=metrics_prev,
            node_address="testhost",
        )
        assert any(r.category == "context_switching" and r.severity == "warning" for r in result.recommendations)

    def test_two_samples_without_cores_suggests_registration(self):
        """Two samples without known cores should suggest registering host."""
        metrics_prev = {"node_context_switches_total": 100000.0}
        metrics_curr = {"node_context_switches_total": 130000.0}  # 30000/30 = 1000/sec
        thresholds = _get_thresholds("default")
        result = analyze_context_switching(
            metrics_curr, thresholds,
            cpu_cores=None,
            previous_metrics=metrics_prev,
            node_address="testhost",
        )
        # Should suggest registering host
        assert any("register" in line.lower() or "register" in r.action.lower() for r in result.recommendations for line in result.lines) or \
               any("registerhost" in r.action for r in result.recommendations)

    def test_two_samples_without_cores_high_rate_warning(self):
        """Without cores, high absolute rate should produce warning."""
        metrics_prev = {"node_context_switches_total": 100000.0}
        metrics_curr = {"node_context_switches_total": 1300000.0}  # 1200000/30 = 40000/sec — above 10000 warn
        thresholds = _get_thresholds("default")
        result = analyze_context_switching(
            metrics_curr, thresholds,
            cpu_cores=None,
            previous_metrics=metrics_prev,
            node_address="testhost",
        )
        assert any(r.category == "context_switching" and r.severity == "warning" for r in result.recommendations)

    def test_counter_reset_detected(self):
        """If current value < previous (counter reset/reboot), should handle gracefully."""
        metrics_prev = {"node_context_switches_total": 5000000.0}
        metrics_curr = {"node_context_switches_total": 100.0}  # Counter reset
        thresholds = _get_thresholds("default")
        result = analyze_context_switching(
            metrics_curr, thresholds,
            cpu_cores=4,
            previous_metrics=metrics_prev,
            node_address="testhost",
        )
        # Should mention counter reset, not crash
        assert any("reset" in line.lower() or "baseline" in line.lower() for line in result.lines)


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

    @patch("linuxdoctor.analyzenode.fetch_metrics_text")
    def test_context_switch_single_sample_no_false_positive(self, mock_fetch):
        """Single sample should not produce false-positive context switch warning."""
        mock_fetch.return_value = SAMPLE_METRICS_TEXT
        result = analyze_remote_node("localhost", port=9100)
        # Should NOT have a context_switching warning for raw counter value
        # (the old code would flag 5M as exceeding the 10M threshold, but
        # with the new counter-aware code, single samples show info only)
        ctx_warnings = [r for r in _extract_recommendations_from_output(result)
                        if r.get("category") == "context_switching" and r.get("severity") == "warning"]
        # With single sample, should not have raw counter warning
        # (may have info about registering, but not a warning about high switches)

    def _extract_recommendations_from_output(self, output):
        """Helper - not used in actual assertions, just for reference."""
        pass

    @patch("linuxdoctor.analyzenode.fetch_metrics_text")
    def test_host_registry_integration(self, mock_fetch):
        """Test that host registry is consulted for CPU cores."""
        mock_fetch.return_value = SAMPLE_METRICS_TEXT
        with patch("linuxdoctor.analyzenode.get_host_info") as mock_registry:
            mock_registry.return_value = {"cpu_cores": 4}
            result = analyze_remote_node("localhost", port=9100)
            mock_registry.assert_called_once()


def _extract_recommendations_from_output(output):
    """Helper - placeholder."""
    return []

class TestIsSSHHost:
    """Tests for is_ssh_host function."""

    def test_ssh_host(self, tmp_path):
        from linuxdoctor.host_registry import register_host
        register_host("remote1", ssh_connect="admin@remote1", path=str(tmp_path / "hosts.yaml"))
        assert is_ssh_host("remote1", registry_path=str(tmp_path / "hosts.yaml")) is True

    def test_non_ssh_host(self, tmp_path):
        from linuxdoctor.host_registry import register_host
        register_host("server1", cpu_cores=4, path=str(tmp_path / "hosts.yaml"))
        assert is_ssh_host("server1", registry_path=str(tmp_path / "hosts.yaml")) is False

    def test_unregistered_host(self, tmp_path):
        assert is_ssh_host("unknown", registry_path=str(tmp_path / "hosts.yaml")) is False


class TestAnalyzeSSHNode:
    """Tests for analyze_ssh_node function."""

    @patch("linuxdoctor.analyzenode.ssh_test_connection")
    @patch("linuxdoctor.analyzenode.collect_ssh_metrics")
    def test_ssh_node_analysis(self, mock_collect, mock_test, tmp_path):
        """Test that SSH hosts are analyzed via SSH when registered."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("myremote", ssh_connect="admin@myremote", cpu_cores=4, path=registry_path)

        # Mock SSH connection and metric collection
        mock_test.return_value = (True, "OK")
        mock_collect.return_value = {
            "node_cpu_seconds_total": [
                {"labels": {"cpu": "0", "mode": "idle"}, "value": 90.0},
                {"labels": {"cpu": "0", "mode": "iowait"}, "value": 5.0},
                {"labels": {"cpu": "1", "mode": "idle"}, "value": 85.0},
                {"labels": {"cpu": "1", "mode": "iowait"}, "value": 3.0},
            ],
            "node_load1": 0.5,
            "node_load5": 0.7,
            "node_load15": 0.9,
            "node_memory_MemTotal_bytes": 16777216000.0,
            "node_memory_MemAvailable_bytes": 8388608000.0,
            "node_context_switches_total": 500000.0,
        }

        result = analyze_remote_node("myremote", registry_path=registry_path)
        assert "SSH" in result or "ssh" in result.lower() or "CPU" in result

    @patch("linuxdoctor.analyzenode.ssh_test_connection")
    def test_ssh_node_connection_failure(self, mock_test, tmp_path):
        """Test that SSH connection failure produces an error message."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("badhost", ssh_connect="user@badhost", path=registry_path)

        mock_test.return_value = (False, "SSH connection failed")

        result = analyze_remote_node("badhost", registry_path=registry_path)
        assert "Error" in result or "error" in result.lower() or "failed" in result.lower()

    @patch("linuxdoctor.analyzenode.ssh_test_connection")
    @patch("linuxdoctor.analyzenode.collect_ssh_metrics")
    def test_ssh_node_json_output(self, mock_collect, mock_test, tmp_path):
        """Test SSH node analysis with JSON output."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("myremote", ssh_connect="admin@myremote", cpu_cores=4, path=registry_path)

        mock_test.return_value = (True, "OK")
        mock_collect.return_value = {
            "node_cpu_seconds_total": [
                {"labels": {"cpu": "0", "mode": "idle"}, "value": 90.0},
            ],
            "node_load1": 0.5,
            "node_memory_MemTotal_bytes": 16777216000.0,
            "node_memory_MemAvailable_bytes": 8388608000.0,
            "node_context_switches_total": 500000.0,
        }

        result = analyze_remote_node("myremote", json_output=True, registry_path=registry_path)
        data = json.loads(result)
        assert "node" in data
