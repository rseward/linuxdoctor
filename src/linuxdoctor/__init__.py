"""linuxdoctor - Analyze performance metrics and recommend actions."""

__version__ = "0.1.0"

from linuxdoctor.analyze import analyze_host
from linuxdoctor.analyzenode import analyze_remote_node, AnalysisResult, is_ssh_host, analyze_ssh_node
from linuxdoctor.prometheus import list_hosts_from_prometheus
from linuxdoctor.web import run_dashboard
from linuxdoctor.ssh_collector import collect_ssh_metrics, ssh_test_connection, resolve_ssh_connect

__all__ = [
    "analyze_host",
    "analyze_remote_node",
    "analyze_ssh_node",
    "is_ssh_host",
    "list_hosts_from_prometheus",
    "AnalysisResult",
    "run_dashboard",
    "collect_ssh_metrics",
    "ssh_test_connection",
    "resolve_ssh_connect",
]