"""Re-export of analyzenode for CLI compatibility."""

from linuxdoctor.analyzenode import analyze_remote_node, fetch_node_metrics, NodeMetric, Recommendation

__all__ = ["analyze_remote_node", "fetch_node_metrics", "NodeMetric", "Recommendation"]