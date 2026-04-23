"""linuxdoctor - Analyze performance metrics and recommend actions."""

__version__ = "0.1.0"

from linuxdoctor.analyze import analyze_host
from linuxdoctor.analyzenode import analyze_remote_node
from linuxdoctor.prometheus import list_hosts_from_prometheus

__all__ = ["analyze_host", "analyze_remote_node", "list_hosts_from_prometheus"]