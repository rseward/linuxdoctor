"""Tests for the web dashboard module, focusing on SSH host handling."""

import json
import pytest
from unittest.mock import patch, MagicMock
from linuxdoctor.web import (
    HostHealth,
    HealthStore,
    scan_host,
    scan_ssh_host,
    scan_all_hosts,
    _worst_severity,
    _category_detail,
)
from linuxdoctor.analyzenode import AnalysisResult, Recommendation


class TestHostHealth:
    """Tests for HostHealth dataclass."""

    def test_default_values(self):
        h = HostHealth(host="test")
        assert h.host == "test"
        assert h.reachable is False
        assert h.collection_method == "node_exporter"
        assert h.ssh_connect == ""
        assert h.cpu_health == "unknown"

    def test_ssh_host(self):
        h = HostHealth(host="remote1", collection_method="ssh", ssh_connect="admin@remote1")
        assert h.collection_method == "ssh"
        assert h.ssh_connect == "admin@remote1"


class TestHealthStore:
    """Tests for HealthStore."""

    def test_empty_store(self):
        store = HealthStore()
        assert store.to_json() == "{}"

    def test_update_and_get(self):
        store = HealthStore()
        h = HostHealth(host="test", reachable=True, cpu_health="healthy")
        store.update("test", h)
        got = store.get("test")
        assert got is not None
        assert got.host == "test"
        assert got.reachable is True

    def test_get_all(self):
        store = HealthStore()
        store.update("a", HostHealth(host="a"))
        store.update("b", HostHealth(host="b"))
        all_hosts = store.get_all()
        assert len(all_hosts) == 2

    def test_to_json(self):
        store = HealthStore()
        store.update("test", HostHealth(host="test", reachable=True, cpu_health="healthy"))
        data = json.loads(store.to_json())
        assert "test" in data
        assert data["test"]["cpu_health"] == "healthy"


class TestWorstSeverity:
    """Tests for _worst_severity helper."""

    def test_healthy_category(self):
        results = [AnalysisResult(category="cpu", lines=["ok"], recommendations=[])]
        assert _worst_severity(results, "cpu") == "healthy"

    def test_warning_category(self):
        results = [AnalysisResult(
            category="cpu",
            lines=["warn"],
            recommendations=[Recommendation(category="cpu", severity="warning", message="test")],
        )]
        assert _worst_severity(results, "cpu") == "warning"

    def test_critical_over_warning(self):
        results = [AnalysisResult(
            category="cpu",
            lines=["warn"],
            recommendations=[
                Recommendation(category="cpu", severity="warning", message="test"),
                Recommendation(category="cpu", severity="critical", message="test2"),
            ],
        )]
        assert _worst_severity(results, "cpu") == "critical"

    def test_unknown_category(self):
        results = [AnalysisResult(category="cpu", lines=["ok"], recommendations=[])]
        assert _worst_severity(results, "memory") == "unknown"

    def test_info_severity(self):
        """Info severity maps to 'healthy' in the dashboard (info is not a problem)."""
        results = [AnalysisResult(
            category="cpu",
            lines=["info"],
            recommendations=[Recommendation(category="cpu", severity="info", message="test")],
        )]
        # Info severity is treated as healthy in the dashboard
        assert _worst_severity(results, "cpu") == "healthy"


class TestCategoryDetail:
    """Tests for _category_detail helper."""

    def test_no_recommendations(self):
        results = [AnalysisResult(category="cpu", lines=["ok"], recommendations=[])]
        detail, suggestion = _category_detail(results, "cpu")
        assert detail == ""
        assert suggestion == ""

    def test_with_recommendation(self):
        results = [AnalysisResult(
            category="cpu",
            lines=["warn"],
            recommendations=[Recommendation(
                category="cpu", severity="warning",
                message="CPU is high", action="Check processes",
            )],
        )]
        detail, suggestion = _category_detail(results, "cpu")
        assert "CPU is high" in detail
        assert "Check processes" in suggestion


class TestScanHost:
    """Tests for scan_host function."""

    @patch("linuxdoctor.web.fetch_metrics_text")
    def test_node_exporter_host(self, mock_fetch, tmp_path):
        """Test scanning a node_exporter host."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("server1", cpu_cores=4, path=registry_path)

        # Return minimal metrics
        mock_fetch.return_value = """node_cpu_seconds_total{cpu="0",mode="idle"} 1000.0
node_cpu_seconds_total{cpu="0",mode="iowait"} 10.0
node_load1 0.5
node_load5 0.4
node_load15 0.3
node_memory_MemTotal_bytes 16777216000
node_memory_MemAvailable_bytes 8388608000
node_filesystem_size_bytes{mountpoint="/"} 500000000000
node_filesystem_avail_bytes{mountpoint="/"} 300000000000
node_context_switches_total 5000000
node_disk_io_time_seconds_total{device="sda"} 100.0
node_network_receive_bytes_total{device="eth0"} 1000000000
node_network_transmit_bytes_total{device="eth0"} 500000000
"""

        health = scan_host("server1", registry_path=registry_path)
        assert health.host == "server1"
        assert health.reachable is True
        assert health.collection_method == "node_exporter"

    @patch("linuxdoctor.web.fetch_metrics_text")
    def test_node_exporter_unreachable(self, mock_fetch, tmp_path):
        """Test unreachable node_exporter host."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("down1", cpu_cores=4, path=registry_path)

        mock_fetch.side_effect = RuntimeError("Cannot connect")

        health = scan_host("down1", registry_path=registry_path)
        assert health.host == "down1"
        assert health.reachable is False
        assert "Cannot connect" in health.error

    def test_ssh_host_detected(self, tmp_path):
        """Test that SSH hosts are routed to scan_ssh_host."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("remote1", ssh_connect="admin@remote1", cpu_cores=4, path=registry_path)

        with patch("linuxdoctor.web.scan_ssh_host") as mock_ssh:
            mock_ssh.return_value = HostHealth(
                host="remote1",
                reachable=True,
                collection_method="ssh",
                ssh_connect="admin@remote1",
                cpu_health="healthy",
            )
            health = scan_host("remote1", registry_path=registry_path)
            mock_ssh.assert_called_once()
            assert health.collection_method == "ssh"
            assert health.ssh_connect == "admin@remote1"


class TestScanSSHHost:
    """Tests for scan_ssh_host function."""

    @patch("linuxdoctor.web.collect_ssh_metrics")
    @patch("linuxdoctor.web.ssh_test_connection")
    def test_ssh_host_healthy(self, mock_test, mock_collect, tmp_path):
        """Test healthy SSH host scanning."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("myremote", ssh_connect="admin@myremote", cpu_cores=4, path=registry_path)

        mock_test.return_value = (True, "OK")
        mock_collect.return_value = {
            "node_cpu_seconds_total": [
                {"labels": {"cpu": "0", "mode": "idle"}, "value": 900.0},
                {"labels": {"cpu": "0", "mode": "iowait"}, "value": 10.0},
                {"labels": {"cpu": "1", "mode": "idle"}, "value": 850.0},
                {"labels": {"cpu": "1", "mode": "iowait"}, "value": 5.0},
            ],
            "node_load1": 0.5,
            "node_load5": 0.6,
            "node_load15": 0.7,
            "node_memory_MemTotal_bytes": 16777216000.0,
            "node_memory_MemAvailable_bytes": 8388608000.0,
            "node_filesystem_size_bytes": [
                {"labels": {"mountpoint": "/", "device": "/dev/sda1"}, "value": 500000000000.0},
            ],
            "node_filesystem_avail_bytes": [
                {"labels": {"mountpoint": "/", "device": "/dev/sda1"}, "value": 300000000000.0},
            ],
            "node_context_switches_total": 500000.0,
        }

        host_info = {"ssh_connect": "admin@myremote", "cpu_cores": 4}
        health = scan_ssh_host("myremote", host_info=host_info)

        assert health.host == "myremote"
        assert health.reachable is True
        assert health.collection_method == "ssh"
        assert health.ssh_connect == "admin@myremote"
        assert health.cpu_health == "healthy"
        assert "ssh" in health.full_analysis.get("collection_method", "")

    @patch("linuxdoctor.web.ssh_test_connection")
    def test_ssh_host_key_failure(self, mock_test, tmp_path):
        """Test SSH host with unaccepted host key."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("myremote", ssh_connect="admin@myremote", path=registry_path)

        mock_test.return_value = (False, "SSH host key verification failed for admin@myremote. Accept the key first: ssh admin@myremote")

        host_info = {"ssh_connect": "admin@myremote"}
        health = scan_ssh_host("myremote", host_info=host_info)

        assert health.reachable is False
        assert "host key" in health.error.lower()
        assert health.collection_method == "ssh"

    @patch("linuxdoctor.web.ssh_test_connection")
    def test_ssh_auth_failure(self, mock_test, tmp_path):
        """Test SSH host with auth failure."""
        mock_test.return_value = (False, "SSH authentication failed for admin@myremote. Set up passwordless auth.")

        host_info = {"ssh_connect": "admin@myremote"}
        health = scan_ssh_host("myremote", host_info=host_info)

        assert health.reachable is False
        assert "auth" in health.error.lower()

    @patch("linuxdoctor.web.ssh_test_connection")
    def test_ssh_timeout_failure(self, mock_test, tmp_path):
        """Test SSH host that times out."""
        mock_test.return_value = (False, "Cannot connect to admin@myremote: SSH command timed out after 10s")

        host_info = {"ssh_connect": "admin@myremote"}
        health = scan_ssh_host("myremote", host_info=host_info)

        assert health.reachable is False
        assert "timed out" in health.error.lower() or "Cannot connect" in health.error

    @patch("linuxdoctor.web.collect_ssh_metrics")
    @patch("linuxdoctor.web.ssh_test_connection")
    def test_ssh_host_with_disk_warning(self, mock_test, mock_collect):
        """Test SSH host with high disk usage."""
        mock_test.return_value = (True, "OK")
        mock_collect.return_value = {
            "node_cpu_seconds_total": [
                {"labels": {"cpu": "0", "mode": "idle"}, "value": 900.0},
                {"labels": {"cpu": "0", "mode": "iowait"}, "value": 5.0},
            ],
            "node_load1": 0.5,
            "node_load5": 0.4,
            "node_load15": 0.3,
            "node_memory_MemTotal_bytes": 16777216000.0,
            "node_memory_MemAvailable_bytes": 8388608000.0,
            "node_filesystem_size_bytes": [
                {"labels": {"mountpoint": "/", "device": "/dev/sda1"}, "value": 500000000000.0},
            ],
            "node_filesystem_avail_bytes": [
                {"labels": {"mountpoint": "/", "device": "/dev/sda1"}, "value": 20000000000.0},  # 96% used
            ],
            "node_context_switches_total": 500000.0,
        }

        host_info = {"ssh_connect": "admin@myremote", "cpu_cores": 2}
        health = scan_ssh_host("myremote", host_info=host_info)

        assert health.reachable is True
        assert health.disk_health == "critical"

    @patch("linuxdoctor.web.collect_ssh_metrics")
    @patch("linuxdoctor.web.ssh_test_connection")
    def test_ssh_host_full_analysis_dict(self, mock_test, mock_collect):
        """Test that full_analysis dict includes SSH collection method."""
        mock_test.return_value = (True, "OK")
        mock_collect.return_value = {
            "node_cpu_seconds_total": [
                {"labels": {"cpu": "0", "mode": "idle"}, "value": 900.0},
                {"labels": {"cpu": "0", "mode": "iowait"}, "value": 5.0},
            ],
            "node_load1": 0.5,
            "node_load5": 0.4,
            "node_load15": 0.3,
            "node_memory_MemTotal_bytes": 16777216000.0,
            "node_memory_MemAvailable_bytes": 8388608000.0,
            "node_filesystem_size_bytes": [
                {"labels": {"mountpoint": "/", "device": "/dev/sda1"}, "value": 500000000000.0},
            ],
            "node_filesystem_avail_bytes": [
                {"labels": {"mountpoint": "/", "device": "/dev/sda1"}, "value": 300000000000.0},
            ],
            "node_context_switches_total": 500000.0,
        }

        host_info = {"ssh_connect": "admin@myremote", "cpu_cores": 2}
        health = scan_ssh_host("myremote", host_info=host_info)

        assert health.full_analysis["collection_method"] == "ssh"
        assert health.full_analysis["ssh_connect"] == "admin@myremote"
        assert "categories" in health.full_analysis


class TestScanAllHosts:
    """Tests for scan_all_hosts function."""

    @patch("linuxdoctor.web.scan_host")
    def test_scan_empty_registry(self, mock_scan, tmp_path):
        """Scanning with no hosts should not call scan_host."""
        registry_path = str(tmp_path / "hosts.yaml")
        scan_all_hosts(registry_path=registry_path)
        mock_scan.assert_not_called()

    @patch("linuxdoctor.web.scan_host")
    def test_scan_multiple_hosts(self, mock_scan, tmp_path):
        """Test scanning multiple registered hosts."""
        from linuxdoctor.host_registry import register_host
        registry_path = str(tmp_path / "hosts.yaml")
        register_host("server1", cpu_cores=4, path=registry_path)
        register_host("server2", cpu_cores=8, path=registry_path)

        mock_scan.return_value = HostHealth(host="test", reachable=True, cpu_health="healthy")

        scan_all_hosts(registry_path=registry_path)
        assert mock_scan.call_count == 2