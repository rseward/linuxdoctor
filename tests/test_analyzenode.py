"""Tests for the analyzenode command."""

import pytest
from unittest.mock import patch
from linuxdoctor.analyzenode import (
    analyze_remote_node,
    NodeMetric,
    _get_metric,
)


class TestNodeMetric:
    def test_basic_metric(self):
        m = NodeMetric(name="node_load1", value=1.5)
        assert m.name == "node_load1"
        assert m.value == 1.5
        assert m.labels == {}

    def test_metric_with_labels(self):
        m = NodeMetric(name="node_cpu_seconds_total", value=100.0,
                       labels={"cpu": "0", "mode": "idle"})
        assert m.labels["cpu"] == "0"


class TestGetMetric:
    def test_find_metric(self):
        metrics = [
            NodeMetric(name="node_load1", value=1.5),
            NodeMetric(name="node_load5", value=1.2),
        ]
        assert _get_metric(metrics, "node_load1") == 1.5

    def test_missing_metric(self):
        metrics = [NodeMetric(name="node_load1", value=1.5)]
        assert _get_metric(metrics, "node_load999") is None


class TestAnalyzeRemoteNode:
    @patch("linuxdoctor.analyzenode.fetch_node_metrics")
    def test_human_output(self, mock_fetch):
        mock_fetch.return_value = [
            NodeMetric(name="node_memory_MemTotal_bytes", value=16e9),
            NodeMetric(name="node_memory_MemAvailable_bytes", value=4e9),
            NodeMetric(name="node_load1", value=2.5),
            NodeMetric(name="node_load5", value=2.0),
            NodeMetric(name="node_load15", value=1.5),
        ]
        result = analyze_remote_node("localhost", port=9100)
        assert "localhost" in result
        assert "Memory" in result

    @patch("linuxdoctor.analyzenode.fetch_node_metrics")
    def test_json_output(self, mock_fetch):
        mock_fetch.return_value = [
            NodeMetric(name="node_memory_MemTotal_bytes", value=16e9),
            NodeMetric(name="node_memory_MemAvailable_bytes", value=4e9),
        ]
        result = analyze_remote_node("localhost", port=9100, json_output=True)
        import json
        data = json.loads(result)
        assert "metrics" in data
        assert "node" in data

    def test_connection_failure(self):
        result = analyze_remote_node("192.0.2.1", port=9100, json_output=True)
        import json
        data = json.loads(result)
        assert "error" in data