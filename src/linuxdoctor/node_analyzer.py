"""Re-export of analyzenode for CLI compatibility."""

from linuxdoctor.analyzenode import (
    analyze_remote_node,
    analyze_ssh_node,
    is_ssh_host,
    fetch_node_metrics,
    fetch_metrics_text,
    NodeMetric,
    Recommendation,
    AnalysisResult,
)

__all__ = [
    "analyze_remote_node",
    "analyze_ssh_node",
    "is_ssh_host",
    "fetch_node_metrics",
    "fetch_metrics_text",
    "NodeMetric",
    "Recommendation",
    "AnalysisResult",
]