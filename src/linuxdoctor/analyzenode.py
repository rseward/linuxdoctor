"""Analyze a remote node using node_exporter metrics.

This is the renamed version of the original 'analyze' command,
now called 'analyzenode' to distinguish from the new local-host
'analyze' command that uses sar, perf, etc.
"""

import json
import platform
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError


@dataclass
class NodeMetric:
    """A metric from node_exporter."""
    name: str
    value: float
    labels: dict = None

    def __post_init__(self):
        if self.labels is None:
            self.labels = {}


def fetch_node_metrics(node_address: str, port: int = 9100) -> list[NodeMetric]:
    """Fetch metrics from a node_exporter endpoint.

    Args:
        node_address: Hostname or IP of the target node.
        port: Node exporter port (default 9100).

    Returns:
        List of NodeMetric objects.
    """
    url = f"http://{node_address}:{port}/metrics"
    metrics = []

    try:
        req = Request(url, headers={"User-Agent": "linuxdoctor/0.1.0"})
        with urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status} from {url}")
            data = resp.read().decode("utf-8")
    except URLError as e:
        raise RuntimeError(f"Cannot connect to {url}: {e}")

    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Parse: metric_name{label1="val1",label2="val2"} 123.45
        try:
            # Split on last space for value
            parts = line.rsplit(" ", 1)
            if len(parts) != 2:
                continue

            metric_part = parts[0]
            value = float(parts[1])

            # Extract name and labels
            if "{" in metric_part:
                name = metric_part[:metric_part.index("{")]
                label_str = metric_part[metric_part.index("{") + 1:metric_part.rindex("}")]
                labels = {}
                for pair in label_str.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        labels[k.strip()] = v.strip('"')
            else:
                name = metric_part
                labels = {}

            metrics.append(NodeMetric(name=name, value=value, labels=labels))
        except (ValueError, IndexError):
            continue

    return metrics


def _get_metric(metrics: list[NodeMetric], name: str, labels: dict = None) -> Optional[float]:
    """Get the value of a specific metric."""
    for m in metrics:
        if m.name == name:
            if labels is None or m.labels == labels:
                return m.value
    return None


def _get_all_metrics(metrics: list[NodeMetric], name: str) -> list[NodeMetric]:
    """Get all metrics with a specific name."""
    return [m for m in metrics if m.name == name]


def analyze_remote_node(
    node_address: str,
    port: int = 9100,
    json_output: bool = False,
    include_recommendations: bool = True,
) -> str:
    """Analyze a remote node using node_exporter metrics.

    Args:
        node_address: Hostname or IP of the target node.
        port: Node exporter port (default 9100).
        json_output: If True, output JSON format.
        include_recommendations: If True, generate recommendations.

    Returns:
        Formatted analysis string.
    """
    try:
        metrics = fetch_node_metrics(node_address, port)
    except RuntimeError as e:
        if json_output:
            return json.dumps({"error": str(e), "node": node_address}, indent=2)
        return f"Error: {e}"

    # Extract key metrics
    cpu_count = _get_metric(metrics, "node_cpu_seconds_total")
    mem_total = _get_metric(metrics, "node_memory_MemTotal_bytes")
    mem_available = _get_metric(metrics, "node_memory_MemAvailable_bytes")
    mem_used_pct = None
    if mem_total and mem_available and mem_total > 0:
        mem_used_pct = round((1 - mem_available / mem_total) * 100, 1)

    load_1 = _get_metric(metrics, "node_load1")
    load_5 = _get_metric(metrics, "node_load5")
    load_15 = _get_metric(metrics, "node_load15")

    disk_metrics = _get_all_metrics(metrics, "node_filesystem_avail_bytes")
    disk_used = _get_all_metrics(metrics, "node_filesystem_size_bytes")

    # Build recommendations
    recs = []
    if mem_used_pct and mem_used_pct > 85:
        recs.append({
            "severity": "critical",
            "message": f"Memory usage is {mem_used_pct}%",
            "action": "Add RAM or reduce memory consumption",
        })
    elif mem_used_pct and mem_used_pct > 75:
        recs.append({
            "severity": "warning",
            "message": f"Memory usage is {mem_used_pct}%",
            "action": "Monitor memory usage",
        })

    if json_output:
        return json.dumps({
            "node": node_address,
            "timestamp": datetime.now().isoformat(),
            "metrics": {
                "mem_total_bytes": mem_total,
                "mem_available_bytes": mem_available,
                "mem_used_pct": mem_used_pct,
                "load_1m": load_1,
                "load_5m": load_5,
                "load_15m": load_15,
            },
            "recommendations": recs if include_recommendations else [],
        }, indent=2)

    # Human-readable output
    lines = []
    lines.append("=" * 60)
    lines.append(f"  linuxdoctor analyzenode — {node_address}:{port}")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append(f"  Memory: {mem_used_pct}% used" if mem_used_pct else "  Memory: N/A")
    lines.append(f"  Load: {load_1} / {load_5} / {load_15}" if load_1 else "  Load: N/A")
    if recs:
        lines.append()
        lines.append("  Recommendations:")
        for r in recs:
            icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(r["severity"], "⚪")
            lines.append(f"  {icon} {r['message']}")
            if "action" in r:
                lines.append(f"     → {r['action']}")
    lines.append("=" * 60)
    return "\n".join(lines)