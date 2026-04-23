"""Tests for the prometheus host discovery module."""

import json
import pytest
from unittest.mock import patch, MagicMock
from linuxdoctor.prometheus import list_hosts_from_prometheus, HostInfo


SAMPLE_PROMETHEUS_RESPONSE = {
    "status": "success",
    "data": {
        "activeTargets": [
            {
                "labels": {"instance": "server1:9100", "job": "node"},
                "health": "up",
            },
            {
                "labels": {"instance": "server2:9100", "job": "node"},
                "health": "down",
            },
        ]
    }
}


class TestHostInfo:
    """Tests for HostInfo dataclass."""

    def test_basic_host_info(self):
        h = HostInfo(instance="server1:9100", host="server1", job="node", health="up")
        assert h.instance == "server1:9100"
        assert h.host == "server1"
        assert h.job == "node"
        assert h.health == "up"


class TestListHostsFromPrometheus:
    """Tests for the list_hosts_from_prometheus function."""

    @patch("linuxdoctor.prometheus.httpx.get")
    def test_successful_discovery(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_PROMETHEUS_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        hosts = list_hosts_from_prometheus("http://localhost:9090")
        assert len(hosts) == 2
        assert hosts[0].host == "server1"
        assert hosts[0].health == "up"
        assert hosts[1].host == "server2"
        assert hosts[1].health == "down"

    @patch("linuxdoctor.prometheus.httpx.get")
    def test_connection_failure(self, mock_get):
        import httpx
        mock_get.side_effect = httpx.ConnectError("Connection refused")

        with pytest.raises(RuntimeError, match="Cannot connect"):
            list_hosts_from_prometheus("http://localhost:9090")

    @patch("linuxdoctor.prometheus.httpx.get")
    def test_http_error(self, mock_get):
        import httpx
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=mock_response
        )
        mock_get.return_value = mock_response

        with pytest.raises(RuntimeError, match="HTTP"):
            list_hosts_from_prometheus("http://localhost:9090")

    @patch("linuxdoctor.prometheus.httpx.get")
    def test_empty_targets(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {"activeTargets": []}
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        hosts = list_hosts_from_prometheus("http://localhost:9090")
        assert len(hosts) == 0

    @patch("linuxdoctor.prometheus.httpx.get")
    def test_url_normalization(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_PROMETHEUS_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # Trailing slash should be stripped
        list_hosts_from_prometheus("http://localhost:9090/")
        called_url = mock_get.call_args[0][0]
        assert called_url == "http://localhost:9090/api/v1/targets"