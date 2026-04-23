"""Analyze a remote node using node_exporter metrics.

This module provides detailed analysis of remote Linux hosts by querying
their Prometheus node_exporter /metrics endpoint. It covers CPU, memory,
disk, disk I/O, network, and context switching metrics with per-resource
breakdowns and threshold-based recommendations.
"""

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NodeMetric:
    """A metric from node_exporter."""
    name: str
    value: float
    labels: dict = field(default_factory=dict)


@dataclass
class Recommendation:
    """A single recommendation from analysis."""
    category: str
    severity: str  # critical, warning, info
    message: str
    detail: str = ""
    action: str = ""


# ---------------------------------------------------------------------------
# Threshold profiles
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "default": {
        "cpu_idle_warn_pct": 20,
        "cpu_iowait_warn_pct": 20,
        "mem_used_warn_pct": 85,
        "disk_used_warn_pct": 85,
        "disk_used_critical_pct": 95,
        "disk_io_time_warn_seconds": 10000,
        "context_switches_warn_count": 10000000,
    },
    "strict": {
        "cpu_idle_warn_pct": 30,
        "cpu_iowait_warn_pct": 10,
        "mem_used_warn_pct": 75,
        "disk_used_warn_pct": 70,
        "disk_used_critical_pct": 85,
        "disk_io_time_warn_seconds": 5000,
        "context_switches_warn_count": 5000000,
    },
    "relaxed": {
        "cpu_idle_warn_pct": 10,
        "cpu_iowait_warn_pct": 40,
        "mem_used_warn_pct": 95,
        "disk_used_warn_pct": 90,
        "disk_used_critical_pct": 98,
        "disk_io_time_warn_seconds": 20000,
        "context_switches_warn_count": 20000000,
    },
}


def _get_thresholds(profile: str) -> dict:
    """Get threshold values for a given profile."""
    return THRESHOLDS.get(profile, THRESHOLDS["default"])


# ---------------------------------------------------------------------------
# Metric fetching and parsing
# ---------------------------------------------------------------------------

def fetch_node_metrics(node_address: str, port: int = 9100, timeout: int = 10) -> list[NodeMetric]:
    """Fetch metrics from a node_exporter endpoint.

    Args:
        node_address: Hostname or IP of the target node.
        port: Node exporter port (default 9100).
        timeout: Request timeout in seconds.

    Returns:
        List of NodeMetric objects.

    Raises:
        RuntimeError: If the request fails.
    """
    url = f"http://{node_address}:{port}/metrics"
    metrics = []

    try:
        response = httpx.get(url, timeout=timeout, headers={"User-Agent": "linuxdoctor/0.1.0"})
        response.raise_for_status()
    except httpx.RequestError as exc:
        raise RuntimeError(f"Cannot connect to {url}: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(f"HTTP {exc.response.status_code} from {url}") from exc

    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

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


def parse_metrics(metrics_text: str) -> dict:
    """Parse Prometheus metrics text into a structured dictionary.

    Args:
        metrics_text: Raw text from /metrics endpoint.

    Returns:
        Dict mapping metric names to either float values or lists of
        {labels, value} dicts for metrics with labels.
    """
    metrics = {}
    for line in metrics_text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if not parts:
            continue
        metric_name = parts[0]
        value = parts[-1]
        try:
            float_val = float(value)
        except ValueError:
            continue

        if "{" in metric_name:
            name_parts = metric_name.split("{")
            metric_name = name_parts[0]
            labels_str = name_parts[1][:-1]
            labels = {}
            for item in labels_str.split(","):
                if "=" in item:
                    key, val = item.split("=", 1)
                    labels[key] = val.strip('"')
            if metric_name not in metrics:
                metrics[metric_name] = []
            metrics[metric_name].append({"labels": labels, "value": float_val})
        else:
            metrics[metric_name] = float_val
    return metrics


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _get_metric(metrics: list[NodeMetric], name: str, labels: dict = None) -> Optional[float]:
    """Get the value of a specific metric (first match)."""
    for m in metrics:
        if m.name == name:
            if labels is None or m.labels == labels:
                return m.value
    return None


def _get_all_metrics(metrics: list[NodeMetric], name: str) -> list[NodeMetric]:
    """Get all metrics with a specific name."""
    return [m for m in metrics if m.name == name]


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def _severity_icon(severity: str) -> str:
    """Return an icon for severity level."""
    return {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(severity, "⚪")


def analyze_cpu(metrics: dict, thresholds: dict) -> list[Recommendation]:
    """Analyze CPU usage and provide recommendations."""
    recommendations = []
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("CPU ANALYSIS")
    lines.append("=" * 50)

    cpu_idle_warn = thresholds["cpu_idle_warn_pct"]
    cpu_iowait_warn = thresholds["cpu_iowait_warn_pct"]

    cpu_seconds = metrics.get("node_cpu_seconds_total", [])
    if not cpu_seconds:
        lines.append("❌ CPU metrics not found.")
        return recommendations, lines

    num_cpus = len(set(
        entry["labels"]["cpu"] for entry in cpu_seconds if "cpu" in entry["labels"]
    ))
    lines.append(f"Number of CPUs: {num_cpus}")

    idle_time = 0
    total_time = 0
    iowait_time = 0

    for entry in cpu_seconds:
        total_time += entry["value"]
        if "mode" in entry["labels"]:
            if entry["labels"]["mode"] == "idle":
                idle_time += entry["value"]
            if entry["labels"]["mode"] == "iowait":
                iowait_time += entry["value"]

    if total_time > 0:
        idle_percent = (idle_time / total_time) * 100
        iowait_percent = (iowait_time / total_time) * 100

        cpu_status = "✅" if idle_percent >= cpu_idle_warn else "⚠️"
        lines.append(f"{cpu_status} CPU Idle: {idle_percent:.2f}% [warning below {cpu_idle_warn}%]")

        iowait_status = "✅" if iowait_percent <= cpu_iowait_warn else "⚠️"
        lines.append(f"{iowait_status} CPU I/O Wait: {iowait_percent:.2f}% [warning above {cpu_iowait_warn}%]")

        if idle_percent < cpu_idle_warn:
            recommendations.append(Recommendation(
                category="cpu", severity="warning",
                message=f"CPU idle time is {idle_percent:.0f}%, below the {cpu_idle_warn}% warning threshold. The server might be under heavy load.",
                action="Identify top CPU consumers with `top` or `ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head`."
            ))
        if iowait_percent > cpu_iowait_warn:
            recommendations.append(Recommendation(
                category="cpu", severity="warning",
                message=f"CPU I/O wait is {iowait_percent:.0f}%, above the {cpu_iowait_warn}% warning threshold. The server might be experiencing a disk bottleneck.",
                action="Identify I/O-heavy processes: `iotop` or `pidstat -d 1`."
            ))

    load1 = metrics.get("node_load1", 0)
    load5 = metrics.get("node_load5", 0)
    load15 = metrics.get("node_load15", 0)

    load_status = "✅" if load1 <= num_cpus else "⚠️"
    lines.append(f"{load_status} Load Average (1m/5m/15m): {load1:.2f}, {load5:.2f}, {load15:.2f} [warning when 1-min load exceeds {num_cpus} CPUs]")

    if load1 > num_cpus:
        recommendations.append(Recommendation(
            category="cpu", severity="warning",
            message=f"1-minute load average ({load1:.2f}) exceeds the number of CPUs ({num_cpus}), indicating high load.",
            action="Review running processes with `ps aux --sort=-%cpu | head -20`."
        ))

    return recommendations, lines


def analyze_memory(metrics: dict, thresholds: dict) -> list[Recommendation]:
    """Analyze memory usage and provide recommendations."""
    recommendations = []
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("MEMORY ANALYSIS")
    lines.append("=" * 50)

    mem_warn = thresholds["mem_used_warn_pct"]

    mem_total_bytes = metrics.get("node_memory_MemTotal_bytes")
    mem_available_bytes = metrics.get("node_memory_MemAvailable_bytes")

    if mem_total_bytes is not None and mem_available_bytes is not None:
        mem_total_gb = mem_total_bytes / (1024**3)
        mem_available_gb = mem_available_bytes / (1024**3)
        mem_used_gb = mem_total_gb - mem_available_gb
        mem_used_percent = (mem_used_gb / mem_total_gb) * 100

        mem_status = "✅" if mem_used_percent <= mem_warn else "⚠️"

        lines.append(f"Total Memory: {mem_total_gb:.2f} GB")
        lines.append(f"{mem_status} Used Memory: {mem_used_gb:.2f} GB ({mem_used_percent:.2f}%) [warning above {mem_warn}%]")
        lines.append(f"Available Memory: {mem_available_gb:.2f} GB")

        if mem_used_percent > mem_warn:
            recommendations.append(Recommendation(
                category="memory", severity="warning",
                message=f"Memory usage is {mem_used_percent:.0f}%, above the {mem_warn}% warning threshold. Consider adding more RAM or optimizing memory usage.",
                action="Check top consumers: `ps aux --sort=-%mem | head -20`."
            ))
    else:
        lines.append("❌ Memory metrics not found.")

    return recommendations, lines


def analyze_disk(metrics: dict, thresholds: dict) -> list[Recommendation]:
    """Analyze disk usage and provide recommendations."""
    recommendations = []
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("DISK ANALYSIS")
    lines.append("=" * 50)

    disk_warn = thresholds["disk_used_warn_pct"]
    disk_critical = thresholds["disk_used_critical_pct"]

    disk_size_bytes = metrics.get("node_filesystem_size_bytes", [])
    disk_avail_bytes = metrics.get("node_filesystem_avail_bytes", [])

    if not disk_size_bytes:
        lines.append("❌ Disk metrics not found.")
        return recommendations, lines

    for size_entry in disk_size_bytes:
        if "mountpoint" in size_entry["labels"]:
            mountpoint = size_entry["labels"]["mountpoint"]
            for avail_entry in disk_avail_bytes:
                if "mountpoint" in avail_entry["labels"] and avail_entry["labels"]["mountpoint"] == mountpoint:
                    disk_size_gb = size_entry["value"] / (1024**3)
                    disk_avail_gb = avail_entry["value"] / (1024**3)
                    disk_used_gb = disk_size_gb - disk_avail_gb
                    if disk_size_gb > 0:
                        disk_used_percent = (disk_used_gb / disk_size_gb) * 100
                        if disk_used_percent >= disk_critical:
                            disk_status = "🔴"
                            severity = "critical"
                        elif disk_used_percent > disk_warn:
                            disk_status = "⚠️"
                            severity = "warning"
                        else:
                            disk_status = "✅"
                            severity = None

                        lines.append(f"Mountpoint: {mountpoint}")
                        lines.append(f"  Total Size: {disk_size_gb:.2f} GB")
                        lines.append(f"  {disk_status} Used Space: {disk_used_gb:.2f} GB ({disk_used_percent:.2f}%) [warning at {disk_warn}%, critical at {disk_critical}%]")
                        lines.append(f"  Available Space: {disk_avail_gb:.2f} GB")

                        if severity:
                            recommendations.append(Recommendation(
                                category="disk", severity=severity,
                                message=f"Disk usage for {mountpoint} is {disk_used_percent:.0f}%, which exceeds the {disk_critical if severity == 'critical' else disk_warn}% {'critical' if severity == 'critical' else 'warning'} threshold. Consider cleaning up disk space or expanding the filesystem.",
                                action=f"Review large files: `du -sh {mountpoint}/* | sort -rh | head`."
                            ))
                    break

    return recommendations, lines


def analyze_disk_io(metrics: dict, thresholds: dict) -> list[Recommendation]:
    """Analyze disk I/O and provide recommendations."""
    recommendations = []
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("DISK I/O ANALYSIS")
    lines.append("=" * 50)

    io_warn = thresholds["disk_io_time_warn_seconds"]

    io_time = metrics.get("node_disk_io_time_seconds_total", [])
    if not io_time:
        lines.append("❌ Disk I/O metrics not found.")
        return recommendations, lines

    for entry in io_time:
        if "device" in entry["labels"]:
            device = entry["labels"]["device"]
            io_status = "✅" if entry["value"] <= io_warn else "⚠️"
            lines.append(f"{io_status} Device {device}: I/O time {entry['value']:.0f}s [warning above {io_warn}s]")
            if entry["value"] > io_warn:
                recommendations.append(Recommendation(
                    category="disk_io", severity="warning",
                    message=f"Device {device} I/O time is {entry['value']:.0f}s, above the {io_warn}s warning threshold. This could be a bottleneck.",
                    action="Check I/O queue: `iostat -x 1 5` and `iotop`."
                ))

    return recommendations, lines


def analyze_network(metrics: dict, thresholds: dict) -> list[Recommendation]:
    """Analyze network usage and provide recommendations."""
    recommendations = []
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("NETWORK ANALYSIS")
    lines.append("=" * 50)

    receive_bytes = metrics.get("node_network_receive_bytes_total", [])
    transmit_bytes = metrics.get("node_network_transmit_bytes_total", [])
    receive_errs = metrics.get("node_network_receive_errs_total", [])
    transmit_errs = metrics.get("node_network_transmit_errs_total", [])

    if not receive_bytes:
        lines.append("❌ Network metrics not found.")
        return recommendations, lines

    for i, rx_entry in enumerate(receive_bytes):
        if "device" in rx_entry["labels"]:
            device = rx_entry["labels"]["device"]
            lines.append(f"Device: {device}")
            lines.append(f"  Received: {rx_entry['value'] / (1024**2):.2f} MB")

            if i < len(transmit_bytes):
                lines.append(f"  Transmitted: {transmit_bytes[i]['value'] / (1024**2):.2f} MB")

            if i < len(receive_errs) and receive_errs[i]["value"] > 0:
                lines.append(f"  ⚠️ Receive Errors: {receive_errs[i]['value']}")
                recommendations.append(Recommendation(
                    category="network", severity="warning",
                    message=f"High number of received errors on device {device}: {receive_errs[i]['value']}.",
                    action=f"Check interface details: `ethtool {device}` and `ip -s link show {device}`."
                ))
            else:
                lines.append(f"  ✅ No receive errors")

            if i < len(transmit_errs) and transmit_errs[i]["value"] > 0:
                lines.append(f"  ⚠️ Transmit Errors: {transmit_errs[i]['value']}")
                recommendations.append(Recommendation(
                    category="network", severity="warning",
                    message=f"High number of transmitted errors on device {device}: {transmit_errs[i]['value']}.",
                    action=f"Check interface details: `ethtool {device}` and `ip -s link show {device}`."
                ))
            else:
                lines.append(f"  ✅ No transmit errors")

    return recommendations, lines


def analyze_context_switching(metrics: dict, thresholds: dict) -> list[Recommendation]:
    """Analyze context switching and provide recommendations."""
    recommendations = []
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("CONTEXT SWITCHING ANALYSIS")
    lines.append("=" * 50)

    cs_warn = thresholds["context_switches_warn_count"]

    context_switches = metrics.get("node_context_switches_total")
    if context_switches is None:
        lines.append("❌ Context switching metrics not found.")
        return recommendations, lines

    cs_status = "✅" if context_switches <= cs_warn else "⚠️"
    lines.append(f"{cs_status} Total Context Switches: {context_switches:,} [warning above {cs_warn:,}]")

    if context_switches > cs_warn:
        recommendations.append(Recommendation(
            category="context_switching", severity="warning",
            message=f"Context switches ({context_switches:,}) exceed the {cs_warn:,} warning threshold. This could indicate that the system is thrashing.",
            action="Review process count and scheduling: `vmstat 1 5` and `ps -ef | wc -l`."
        ))

    return recommendations, lines


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _format_recommendations(url: str, recommendations: list[Recommendation]) -> list[str]:
    """Format the recommendations summary."""
    lines = []
    lines.append("")
    lines.append("=" * 50)
    if recommendations:
        lines.append(f"⚠️  RECOMMENDATIONS FOR {url}")
        lines.append("=" * 50)
        for i, rec in enumerate(recommendations, 1):
            icon = _severity_icon(rec.severity)
            lines.append(f"{i}. {icon} [{rec.severity.upper()}] {rec.message}")
            if rec.action:
                lines.append(f"   → {rec.action}")
    else:
        lines.append(f"✅ NO RECOMMENDATIONS - {url} LOOKS HEALTHY!")
    lines.append("=" * 50)
    return lines


def _format_json(url: str, port: int, metrics: dict,
                 recommendations: list[Recommendation],
                 include_recommendations: bool) -> str:
    """Format results as JSON."""
    output = {
        "node": url,
        "port": port,
        "timestamp": datetime.now().isoformat(),
        "metrics": {},
        "recommendations": [],
    }

    # Extract key metrics for JSON output
    cpu_seconds = metrics.get("node_cpu_seconds_total", [])
    num_cpus = len(set(
        e["labels"]["cpu"] for e in cpu_seconds if "cpu" in e["labels"]
    )) if cpu_seconds else 0

    idle_time = sum(e["value"] for e in cpu_seconds if e.get("labels", {}).get("mode") == "idle")
    total_time = sum(e["value"] for e in cpu_seconds)
    iowait_time = sum(e["value"] for e in cpu_seconds if e.get("labels", {}).get("mode") == "iowait")

    output["metrics"]["cpu"] = {
        "count": num_cpus,
        "idle_pct": round(idle_time / total_time * 100, 2) if total_time > 0 else None,
        "iowait_pct": round(iowait_time / total_time * 100, 2) if total_time > 0 else None,
    }

    mem_total = metrics.get("node_memory_MemTotal_bytes")
    mem_available = metrics.get("node_memory_MemAvailable_bytes")
    output["metrics"]["memory"] = {
        "total_bytes": mem_total,
        "available_bytes": mem_available,
        "used_pct": round((1 - mem_available / mem_total) * 100, 1) if mem_total and mem_available and mem_total > 0 else None,
    }

    load_1 = metrics.get("node_load1", 0)
    load_5 = metrics.get("node_load5", 0)
    load_15 = metrics.get("node_load15", 0)
    output["metrics"]["load"] = {
        "1m": load_1,
        "5m": load_5,
        "15m": load_15,
    }

    if include_recommendations:
        for rec in recommendations:
            output["recommendations"].append({
                "severity": rec.severity,
                "category": rec.category,
                "message": rec.message,
                "action": rec.action,
            })

    return json.dumps(output, indent=2)


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_remote_node(
    node_address: str,
    port: int = 9100,
    json_output: bool = False,
    include_recommendations: bool = True,
    threshold_profile: str = "default",
    verbose: bool = False,
) -> str:
    """Analyze a remote node using node_exporter metrics.

    Args:
        node_address: Hostname or IP of the target node.
        port: Node exporter port (default 9100).
        json_output: If True, output JSON format.
        include_recommendations: If True, generate recommendations.
        threshold_profile: Threshold profile: default, strict, or relaxed.
        verbose: If True, show detailed metric output.

    Returns:
        Formatted analysis string.
    """
    url = f"http://{node_address}:{port}/metrics"
    thresholds = _get_thresholds(threshold_profile)

    try:
        metrics_text = fetch_metrics_text(node_address, port)
        metrics = parse_metrics(metrics_text)
    except RuntimeError as e:
        if json_output:
            return json.dumps({"error": str(e), "node": node_address}, indent=2)
        return f"Error: {e}"

    # Run all analysis functions
    all_recommendations = []
    all_lines = []

    # Header
    all_lines.append("🔍 Linux Doctor v0.1.0")
    all_lines.append(f"📊 Analyzing prometheus node exporter at {url}")
    all_lines.append("=" * 50)

    cpu_recs, cpu_lines = analyze_cpu(metrics, thresholds)
    all_recommendations.extend(cpu_recs)
    all_lines.extend(cpu_lines)

    mem_recs, mem_lines = analyze_memory(metrics, thresholds)
    all_recommendations.extend(mem_recs)
    all_lines.extend(mem_lines)

    disk_recs, disk_lines = analyze_disk(metrics, thresholds)
    all_recommendations.extend(disk_recs)
    all_lines.extend(disk_lines)

    io_recs, io_lines = analyze_disk_io(metrics, thresholds)
    all_recommendations.extend(io_recs)
    all_lines.extend(io_lines)

    net_recs, net_lines = analyze_network(metrics, thresholds)
    all_recommendations.extend(net_recs)
    all_lines.extend(net_lines)

    cs_recs, cs_lines = analyze_context_switching(metrics, thresholds)
    all_recommendations.extend(cs_recs)
    all_lines.extend(cs_lines)

    # Sort by severity
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    all_recommendations.sort(key=lambda r: severity_order.get(r.severity, 3))

    if json_output:
        return _format_json(url, port, metrics,
                            all_recommendations if include_recommendations else [],
                            include_recommendations)

    # Recommendations summary
    if include_recommendations:
        all_lines.extend(_format_recommendations(url, all_recommendations))

    return "\n".join(all_lines)


def fetch_metrics_text(node_address: str, port: int = 9100, timeout: int = 10) -> str:
    """Fetch raw metrics text from a node_exporter endpoint.

    Args:
        node_address: Hostname or IP of the target node.
        port: Node exporter port (default 9100).
        timeout: Request timeout in seconds.

    Returns:
        Raw metrics text string.

    Raises:
        RuntimeError: If the request fails.
    """
    url = f"http://{node_address}:{port}/metrics"

    try:
        response = httpx.get(url, timeout=timeout, headers={"User-Agent": "linuxdoctor/0.1.0"})
        response.raise_for_status()
        return response.text
    except httpx.RequestError as exc:
        raise RuntimeError(f"Cannot connect to {url}: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(f"HTTP {exc.response.status_code} from {url}") from exc