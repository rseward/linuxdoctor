"""Analyze a remote node using node_exporter metrics.

This module provides detailed analysis of remote Linux hosts by querying
their Prometheus node_exporter /metrics endpoint. It covers CPU, memory,
disk, disk I/O, network, and context switching metrics with per-resource
breakdowns and threshold-based recommendations.

IMPORTANT: Many node_exporter metrics are cumulative counters (monotonically
increasing since boot), not instantaneous gauges. This includes:
  - node_cpu_seconds_total (counter)
  - node_context_switches_total (counter)
  - node_disk_io_time_seconds_total (counter)

Comparing these raw values against static thresholds produces false positives
on long-running systems. This module handles counters in two ways:
  1. For CPU iowait: the percentage-of-total approach (iowait/total) is valid
     because both numerator and denominator are cumulative counters with the
     same time base.
  2. For context switches and disk I/O time: we take two samples spaced
     apart and compute rates, falling back to a warning if only one sample
     is available.

The analysis functions return structured AnalysisResult objects, keeping
data gathering separate from presentation. Formatting is handled by
_format_human() and _format_json().
"""

import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from linuxdoctor.host_registry import get_host_info, DEFAULT_REGISTRY_PATH
from linuxdoctor.ssh_collector import (
    collect_ssh_metrics,
    check_remote_tools,
    resolve_ssh_connect,
    ssh_test_connection,
)
from linuxdoctor.recommendations import generate_install_suggestions


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


@dataclass
class AnalysisResult:
    """Result from a single analysis category."""
    category: str
    lines: list[str] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)  # tool names that were unavailable


# ---------------------------------------------------------------------------
# Threshold profiles
# ---------------------------------------------------------------------------
# Context switch thresholds are now expressed as rates (per second) and
# per-core rates (per core per second) rather than raw cumulative counts.
# Disk I/O time thresholds are now expressed as percentages (utilization)
# rather than cumulative seconds.
#
# Two-pass sampling is used for counter metrics: we take two samples
# spaced RESAMPLE_INTERVAL_SECONDS apart and compute the rate between them.

RESAMPLE_INTERVAL_SECONDS = 30  # Time between two counter samples

THRESHOLDS = {
    "default": {
        "cpu_idle_warn_pct": 20,
        "cpu_iowait_warn_pct": 20,        # % of CPU time in iowait (percentage-of-total)
        "mem_used_warn_pct": 85,
        "disk_used_warn_pct": 85,
        "disk_used_critical_pct": 95,
        "disk_io_util_warn_pct": 70,       # disk I/O utilization % (rate-based)
        "disk_io_util_critical_pct": 90,    # disk I/O utilization % critical
        "context_switches_per_core_warn": 1000,   # switches/core/sec warning
        "context_switches_per_core_critical": 5000, # switches/core/sec critical
        "context_switches_total_warn": 10000,      # total switches/sec absolute warning
    },
    "strict": {
        "cpu_idle_warn_pct": 30,
        "cpu_iowait_warn_pct": 10,
        "mem_used_warn_pct": 75,
        "disk_used_warn_pct": 70,
        "disk_used_critical_pct": 85,
        "disk_io_util_warn_pct": 50,
        "disk_io_util_critical_pct": 70,
        "context_switches_per_core_warn": 500,
        "context_switches_per_core_critical": 2000,
        "context_switches_total_warn": 5000,
    },
    "relaxed": {
        "cpu_idle_warn_pct": 10,
        "cpu_iowait_warn_pct": 40,
        "mem_used_warn_pct": 95,
        "disk_used_warn_pct": 90,
        "disk_used_critical_pct": 98,
        "disk_io_util_warn_pct": 85,
        "disk_io_util_critical_pct": 95,
        "context_switches_per_core_warn": 2000,
        "context_switches_per_core_critical": 10000,
        "context_switches_total_warn": 20000,
    },
}


def _get_thresholds(profile: str) -> dict:
    """Get threshold values for a given profile."""
    return THRESHOLDS.get(profile, THRESHOLDS["default"])


def click_echo_safe(msg: str) -> None:
    """Print a message to stderr (for verbose output during analysis)."""
    try:
        import click
        click.echo(msg, err=True)
    except Exception:
        print(msg, file=sys.stderr)


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
# Analysis functions — return AnalysisResult, not formatted text
# ---------------------------------------------------------------------------

def analyze_cpu(metrics: dict, thresholds: dict) -> AnalysisResult:
    """Analyze CPU usage and provide recommendations."""
    result = AnalysisResult(category="cpu")
    recommendations = []
    lines = result.lines

    lines.append("")
    lines.append("=" * 50)
    lines.append("CPU ANALYSIS")
    lines.append("=" * 50)

    cpu_idle_warn = thresholds["cpu_idle_warn_pct"]
    cpu_iowait_warn = thresholds["cpu_iowait_warn_pct"]

    cpu_seconds = metrics.get("node_cpu_seconds_total", [])
    if not cpu_seconds:
        lines.append("❌ CPU metrics not found.")
        return result

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

    result.recommendations = recommendations
    return result


def analyze_memory(metrics: dict, thresholds: dict) -> AnalysisResult:
    """Analyze memory usage and provide recommendations."""
    result = AnalysisResult(category="memory")
    recommendations = []
    lines = result.lines

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

    result.recommendations = recommendations
    return result


def analyze_disk(metrics: dict, thresholds: dict) -> AnalysisResult:
    """Analyze disk usage and provide recommendations."""
    result = AnalysisResult(category="disk")
    recommendations = []
    lines = result.lines

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
        return result

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

    result.recommendations = recommendations
    return result


def analyze_disk_io(metrics: dict, thresholds: dict, previous_metrics: dict = None) -> AnalysisResult:
    """Analyze disk I/O and provide recommendations.

    node_disk_io_time_seconds_total is a cumulative counter, so comparing its
    raw value to a threshold is meaningless on a long-running system. We
    compute a utilization rate when two samples are available, or show an
    info notice when only a single sample is present.

    For SSH-collected metrics, node_disk_io_util_pct provides instantaneous
    utilization percentages from iostat, which are directly comparable to
    thresholds.
    """
    result = AnalysisResult(category="disk_io")
    recommendations = []
    lines = result.lines

    lines.append("")
    lines.append("=" * 50)
    lines.append("DISK I/O ANALYSIS")
    lines.append("=" * 50)

    io_warn_pct = thresholds["disk_io_util_warn_pct"]
    io_critical_pct = thresholds["disk_io_util_critical_pct"]

    # Check for SSH-style instantaneous utilization percentages first
    io_util_pct = metrics.get("node_disk_io_util_pct", [])
    if io_util_pct:
        for entry in io_util_pct:
            if "device" not in entry.get("labels", {}):
                continue
            device = entry["labels"]["device"]
            util_pct = entry["value"]

            if util_pct >= io_critical_pct:
                lines.append(f"  🔴 Device {device}: I/O utilization {util_pct:.1f}% [critical above {io_critical_pct}%]")
                recommendations.append(Recommendation(
                    category="disk_io", severity="critical",
                    message=f"Device {device} I/O utilization is {util_pct:.1f}%, above the {io_critical_pct}% critical threshold.",
                    action="Check I/O queue: `iostat -x 1 5` and `iotop`. Consider faster storage or workload distribution."
                ))
            elif util_pct >= io_warn_pct:
                lines.append(f"  ⚠️ Device {device}: I/O utilization {util_pct:.1f}% [warning above {io_warn_pct}%]")
                recommendations.append(Recommendation(
                    category="disk_io", severity="warning",
                    message=f"Device {device} I/O utilization is {util_pct:.1f}%, above the {io_warn_pct}% warning threshold.",
                    action="Check I/O queue: `iostat -x 1 5` and `iotop`."
                ))
            else:
                lines.append(f"  ✅ Device {device}: I/O utilization {util_pct:.1f}% [warning above {io_warn_pct}%]")

        result.recommendations = recommendations
        return result

    io_time = metrics.get("node_disk_io_time_seconds_total", [])
    if not io_time:
        lines.append("❌ Disk I/O metrics not found.")
        return result

    # Try to compute rate if we have previous metrics
    previous_io_time = None
    if previous_metrics:
        previous_io_time = previous_metrics.get("node_disk_io_time_seconds_total", [])

    for entry in io_time:
        if "device" not in entry["labels"]:
            continue
        device = entry["labels"]["device"]
        current_val = entry["value"]

        if previous_io_time:
            # Find matching device in previous sample
            prev_val = None
            for prev_entry in previous_io_time:
                if prev_entry.get("labels", {}).get("device") == device:
                    prev_val = prev_entry["value"]
                    break

            if prev_val is not None and current_val >= prev_val:
                delta = current_val - prev_val
                interval = RESAMPLE_INTERVAL_SECONDS
                util_pct = (delta / interval) * 100
                lines.append(f"  Device {device}: I/O utilization {util_pct:.1f}% (rate over {interval}s)")

                if util_pct >= io_critical_pct:
                    lines.append(f"  🔴 Device {device}: I/O utilization {util_pct:.1f}% [critical above {io_critical_pct}%]")
                    recommendations.append(Recommendation(
                        category="disk_io", severity="critical",
                        message=f"Device {device} I/O utilization is {util_pct:.1f}%, above the {io_critical_pct}% critical threshold.",
                        action="Check I/O queue: `iostat -x 1 5` and `iotop`. Consider faster storage or workload distribution."
                    ))
                elif util_pct >= io_warn_pct:
                    lines.append(f"  ⚠️ Device {device}: I/O utilization {util_pct:.1f}% [warning above {io_warn_pct}%]")
                    recommendations.append(Recommendation(
                        category="disk_io", severity="warning",
                        message=f"Device {device} I/O utilization is {util_pct:.1f}%, above the {io_warn_pct}% warning threshold.",
                        action="Check I/O queue: `iostat -x 1 5` and `iotop`."
                    ))
                else:
                    lines.append(f"  ✅ Device {device}: I/O utilization {util_pct:.1f}% [warning above {io_warn_pct}%]")
            else:
                # Counter may have reset (reboot) or no match
                lines.append(f"  ℹ️  Device {device}: cumulative I/O time {current_val:.0f}s (insufficient data for rate — counter may have reset)")
        else:
            # Only one sample available — raw counter value is not meaningful for threshold comparison
            lines.append(f"  ℹ️  Device {device}: cumulative I/O time {current_val:.0f}s (raw counter, not a rate)")
            lines.append(f"  💡 Tip: Two-sample analysis needed for rate-based I/O thresholds. Consider using --resample flag.")

    result.recommendations = recommendations
    return result


def analyze_network(metrics: dict, thresholds: dict) -> AnalysisResult:
    """Analyze network usage and provide recommendations."""
    result = AnalysisResult(category="network")
    recommendations = []
    lines = result.lines

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
        return result

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

    result.recommendations = recommendations
    return result


def analyze_context_switching(
    metrics: dict, thresholds: dict, cpu_cores: Optional[int] = None,
    previous_metrics: dict = None, node_address: str = "",
) -> AnalysisResult:
    """Analyze context switching and provide recommendations.

    node_context_switches_total is a cumulative counter since boot. Comparing
    its raw value to a threshold is meaningless on long-running systems.

    We compute a per-second rate when two samples are available, then
    normalize by CPU core count if known. When the core count is unknown, we
    fall back to absolute rate thresholds and suggest the user register the
    host with `linuxdoctor registerhost`.
    """
    result = AnalysisResult(category="context_switching")
    recommendations = []
    lines = result.lines

    lines.append("")
    lines.append("=" * 50)
    lines.append("CONTEXT SWITCHING ANALYSIS")
    lines.append("=" * 50)

    cs_per_core_warn = thresholds["context_switches_per_core_warn"]
    cs_per_core_critical = thresholds["context_switches_per_core_critical"]
    cs_total_warn = thresholds["context_switches_total_warn"]

    context_switches = metrics.get("node_context_switches_total")
    if context_switches is None:
        lines.append("❌ Context switching metrics not found.")
        return result

    # Try rate computation from two samples
    previous_cs = None
    if previous_metrics:
        previous_cs = previous_metrics.get("node_context_switches_total")

    if previous_cs is not None and context_switches >= previous_cs:
        # We have two samples — compute the rate
        delta = context_switches - previous_cs
        interval = RESAMPLE_INTERVAL_SECONDS
        rate_per_sec = delta / interval

        lines.append(f"  Context switch rate: {rate_per_sec:,.0f} switches/sec (over {interval}s window)")

        if cpu_cores and cpu_cores > 0:
            per_core = rate_per_sec / cpu_cores
            lines.append(f"  CPU cores: {cpu_cores} (from host registry)")
            lines.append(f"  Per-core rate: {per_core:,.0f} switches/core/sec")

            if per_core >= cs_per_core_critical:
                lines.append(f"  🔴 Per-core rate {per_core:,.0f}/core/sec [critical above {cs_per_core_critical}/core/sec]")
                recommendations.append(Recommendation(
                    category="context_switching", severity="critical",
                    message=f"Context switch rate is {per_core:,.0f} per core per second (critical threshold: {cs_per_core_critical}/core/sec). This indicates severe scheduling issues.",
                    action="Review process count and scheduling: `vmstat 1 5` and `ps -ef | wc -l`."
                ))
            elif per_core >= cs_per_core_warn:
                lines.append(f"  ⚠️ Per-core rate {per_core:,.0f}/core/sec [warning above {cs_per_core_warn}/core/sec]")
                recommendations.append(Recommendation(
                    category="context_switching", severity="warning",
                    message=f"Context switch rate is {per_core:,.0f} per core per second (warning threshold: {cs_per_core_warn}/core/sec). This could indicate contention.",
                    action="Review process count and scheduling: `vmstat 1 5` and `ps -ef | wc -l`."
                ))
            else:
                lines.append(f"  ✅ Per-core rate {per_core:,.0f}/core/sec [warning above {cs_per_core_warn}/core/sec]")
        else:
            # No core count — use absolute thresholds
            lines.append(f"  ⚠️  CPU core count unknown — using absolute thresholds (less accurate)")
            if rate_per_sec >= cs_total_warn:
                lines.append(f"  ⚠️ Total rate {rate_per_sec:,.0f}/sec [warning above {cs_total_warn}/sec]")
                recommendations.append(Recommendation(
                    category="context_switching", severity="warning",
                    message=f"Context switch rate is {rate_per_sec:,.0f}/sec (absolute warning threshold: {cs_total_warn}/sec). Accuracy improves with known CPU core count.",
                    action="Register this host's CPU core count for better accuracy: `linuxdoctor registerhost {node_address} --cpu-cores N`"
                ))
            else:
                lines.append(f"  ✅ Total rate {rate_per_sec:,.0f}/sec [warning above {cs_total_warn}/sec]")
                # Even when healthy, suggest registration if cores are unknown
                recommendations.append(Recommendation(
                    category="context_switching", severity="info",
                    message=f"CPU core count is not registered for {node_address}. Context switch analysis is more accurate when normalized per core.",
                    action=f"Register: `linuxdoctor registerhost {node_address} --cpu-cores N`"
                ))
    elif previous_cs is not None and context_switches < previous_cs:
        # Counter reset (reboot)
        lines.append(f"  ℹ️  Counter may have reset (current: {context_switches:,}, previous: {previous_cs:,}). Using current value as baseline.")
    else:
        # Only one sample — can't compute rate
        lines.append(f"  ℹ️  Cumulative context switches: {context_switches:,} (raw counter since boot)")
        lines.append(f"  💡 Two-sample analysis needed for rate-based thresholds. Consider using --resample flag.")
        lines.append(f"  💡 Register CPU cores for better accuracy: `linuxdoctor registerhost {node_address} --cpu-cores N`")

    result.recommendations = recommendations
    return result


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _severity_icon(severity: str) -> str:
    """Return an icon for severity level."""
    return {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(severity, "⚪")


def _format_human(url: str, results: list[AnalysisResult],
                  include_recommendations: bool = True,
                  node_address: str = "",
                  cpu_cores: Optional[int] = None,
                  install_suggestions: list | None = None) -> str:
    """Format analysis results for human-readable output.

    Separates data gathering from presentation, preserving the clean
    section-based layout from the original linuxdoctor.py.
    """
    all_recommendations = []
    for r in results:
        all_recommendations.extend(r.recommendations)

    lines = []
    lines.append("🔍 Linux Doctor v0.1.0")
    lines.append(f"📊 Analyzing prometheus node exporter at {url}")
    lines.append("=" * 50)

    # Emit each analysis section
    for r in results:
        lines.extend(r.lines)

    # Sort recommendations by severity
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    all_recommendations.sort(key=lambda r: severity_order.get(r.severity, 3))

    # Recommendations summary
    lines.append("")
    lines.append("=" * 50)
    if include_recommendations and all_recommendations:
        lines.append(f"⚠️  RECOMMENDATIONS FOR {url}")
        lines.append("=" * 50)
        for i, rec in enumerate(all_recommendations, 1):
            icon = _severity_icon(rec.severity)
            lines.append(f"{i}. {icon} [{rec.severity.upper()}] {rec.message}")
            if rec.action:
                lines.append(f"   → {rec.action}")
    else:
        lines.append(f"✅ NO RECOMMENDATIONS - {url} LOOKS HEALTHY!")

    # Install suggestions for missing metric tools
    install_suggestions = install_suggestions or []
    if install_suggestions:
        lines.append("")
        lines.append("=" * 50)
        lines.append("📦 MISSING TOOL SUGGESTIONS")
        lines.append("=" * 50)
        lines.append("")
        lines.append("The following metric tools were not found on the remote host.")
        lines.append("Install them for richer data collection:")
        lines.append("")
        for sug in install_suggestions:
            lines.append(f"  🔧 {sug.message}")
            if sug.detail:
                lines.append(f"     {sug.detail}")
            if sug.action:
                lines.append(f"     → {sug.action}")
            lines.append("")

    lines.append("=" * 50)

    return "\n".join(lines)


def _format_json(url: str, port: int, metrics: dict,
                 results: list[AnalysisResult],
                 include_recommendations: bool = True,
                 cpu_cores: Optional[int] = None,
                 install_suggestions: list | None = None) -> str:
    """Format results as JSON."""
    all_recommendations = []
    for r in results:
        all_recommendations.extend(r.recommendations)

    # Extract key metrics for JSON output
    cpu_seconds = metrics.get("node_cpu_seconds_total", [])
    num_cpus = len(set(
        e["labels"]["cpu"] for e in cpu_seconds if "cpu" in e["labels"]
    )) if cpu_seconds else 0

    idle_time = sum(e["value"] for e in cpu_seconds if e.get("labels", {}).get("mode") == "idle")
    total_time = sum(e["value"] for e in cpu_seconds)
    iowait_time = sum(e["value"] for e in cpu_seconds if e.get("labels", {}).get("mode") == "iowait")

    output = {
        "node": url,
        "port": port,
        "timestamp": datetime.now().isoformat(),
        "cpu_cores_registered": cpu_cores,
        "metrics": {
            "cpu": {
                "count": num_cpus,
                "idle_pct": round(idle_time / total_time * 100, 2) if total_time > 0 else None,
                "iowait_pct": round(iowait_time / total_time * 100, 2) if total_time > 0 else None,
            },
            "memory": {
                "total_bytes": metrics.get("node_memory_MemTotal_bytes"),
                "available_bytes": metrics.get("node_memory_MemAvailable_bytes"),
            },
            "load": {
                "1m": metrics.get("node_load1", 0),
                "5m": metrics.get("node_load5", 0),
                "15m": metrics.get("node_load15", 0),
            },
        },
        "recommendations": [],
        "install_suggestions": [],
        "missing_tools": [],
    }

    # Collect missing tools from results
    all_missing_tools = []
    for r in results:
        all_missing_tools.extend(r.missing_tools)
    output["missing_tools"] = all_missing_tools

    # Add memory used_pct
    mem_total = metrics.get("node_memory_MemTotal_bytes")
    mem_available = metrics.get("node_memory_MemAvailable_bytes")
    if mem_total and mem_available and mem_total > 0:
        output["metrics"]["memory"]["used_pct"] = round((1 - mem_available / mem_total) * 100, 1)
    else:
        output["metrics"]["memory"]["used_pct"] = None

    if include_recommendations:
        for rec in all_recommendations:
            output["recommendations"].append({
                "severity": rec.severity,
                "category": rec.category,
                "message": rec.message,
                "action": rec.action,
            })

    # Install suggestions
    install_suggestions = install_suggestions or []
    for sug in install_suggestions:
        output["install_suggestions"].append({
            "tool": sug.metric,
            "category": sug.category,
            "message": sug.message,
            "detail": sug.detail,
            "action": sug.action,
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
    resample: bool = False,
    resample_interval: int = None,
    registry_path: str = DEFAULT_REGISTRY_PATH,
) -> str:
    """Analyze a remote node using node_exporter or SSH metrics.

    If the host is registered with an ssh_connect field, metrics are gathered
    via SSH using traditional perf tools. Otherwise, node_exporter is used.

    Args:
        node_address: Hostname or IP of the target node.
        port: Node exporter port (default 9100).
        json_output: If True, output JSON format.
        include_recommendations: If True, generate recommendations.
        threshold_profile: Threshold profile: default, strict, or relaxed.
        verbose: If True, show detailed metric output.
        resample: If True, take two samples spaced apart to compute rates for counter metrics.
        resample_interval: Seconds between samples (default: RESAMPLE_INTERVAL_SECONDS).
        registry_path: Path to the host registry YAML file.

    Returns:
        Formatted analysis string.
    """
    # Check if this host uses SSH for metric collection
    host_info = get_host_info(node_address, path=registry_path)
    if host_info and "ssh_connect" in host_info:
        return analyze_ssh_node(
            node_address=node_address,
            json_output=json_output,
            include_recommendations=include_recommendations,
            threshold_profile=threshold_profile,
            verbose=verbose,
            resample=resample,
            resample_interval=resample_interval,
            registry_path=registry_path,
        )

    # --- node_exporter path ---
    url = f"http://{node_address}:{port}/metrics"
    thresholds = _get_thresholds(threshold_profile)

    # Look up host metadata from registry
    cpu_cores = host_info.get("cpu_cores") if host_info else None

    if verbose and host_info:
        click_echo_safe(f"📋 Host registry: {node_address} -> {host_info}")
    elif verbose and not host_info:
        click_echo_safe(f"📋 Host registry: {node_address} not registered. Use `linuxdoctor registerhost` for better context switch analysis.")

    try:
        metrics_text = fetch_metrics_text(node_address, port)
        metrics = parse_metrics(metrics_text)
    except RuntimeError as e:
        if json_output:
            return json.dumps({"error": str(e), "node": node_address}, indent=2)
        return f"Error: {e}"

    # Try to determine CPU cores from metrics if not in registry
    if cpu_cores is None:
        cpu_seconds = metrics.get("node_cpu_seconds_total", [])
        if cpu_seconds:
            cpu_cores = len(set(
                e["labels"]["cpu"] for e in cpu_seconds if "cpu" in e["labels"]
            ))

    # Optional second sample for rate-based analysis of counters
    previous_metrics = None
    if resample:
        interval = resample_interval or RESAMPLE_INTERVAL_SECONDS
        time.sleep(interval)
        try:
            metrics_text_2 = fetch_metrics_text(node_address, port)
            previous_metrics = metrics
            metrics = parse_metrics(metrics_text_2)
        except RuntimeError:
            pass

    # Run all analysis functions
    results = [
        analyze_cpu(metrics, thresholds),
        analyze_memory(metrics, thresholds),
        analyze_disk(metrics, thresholds),
        analyze_disk_io(metrics, thresholds, previous_metrics=previous_metrics),
        analyze_network(metrics, thresholds),
        analyze_context_switching(
            metrics, thresholds,
            cpu_cores=cpu_cores,
            previous_metrics=previous_metrics,
            node_address=node_address,
        ),
    ]

    # Detect missing tools from absent metric groups (node_exporter path)
    # When node_exporter doesn't expose certain metrics, it often means the
    # underlying tool isn't available on the remote host.
    missing_tools = []
    if not metrics.get("node_cpu_seconds_total") and not metrics.get("node_cpu_idle_pct"):
        missing_tools.append("node_exporter_cpu")
    # Note: node_exporter typically provides CPU stats from kernel, not mpstat,
    # so we don't map to mpstat here. Instead, we note the absence of data.

    # Generate install suggestions from missing tools detected during analysis
    from linuxdoctor.collectors import MetricCollection
    missing_collections = []
    if missing_tools:
        mc = MetricCollection(category="node_exporter", missing_tools=missing_tools)
        missing_collections.append(mc)

    # Also check for tools referenced in recommendation actions
    all_recommendations = []
    for r in results:
        all_recommendations.extend(r.recommendations)

    install_suggestions = generate_install_suggestions(
        missing_collections,
        recommendations=all_recommendations if include_recommendations else None,
    )

    if json_output:
        return _format_json(url, port, metrics, results, include_recommendations, cpu_cores=cpu_cores, install_suggestions=install_suggestions)

    return _format_human(url, results, include_recommendations, node_address=node_address, cpu_cores=cpu_cores, install_suggestions=install_suggestions)


def analyze_ssh_node(
    node_address: str,
    json_output: bool = False,
    include_recommendations: bool = True,
    threshold_profile: str = "default",
    verbose: bool = False,
    resample: bool = False,
    resample_interval: int = None,
    registry_path: str = DEFAULT_REGISTRY_PATH,
) -> str:
    """Analyze a remote node via SSH using traditional perf tools.

    This is used when a host is registered with --sshconnect, indicating
    that metrics should be gathered via SSH rather than node_exporter.

    Args:
        node_address: Hostname or IP of the target node.
        json_output: If True, output JSON format.
        include_recommendations: If True, generate recommendations.
        threshold_profile: Threshold profile: default, strict, or relaxed.
        verbose: If True, show detailed metric output.
        resample: If True, take two samples for rate-based counter analysis.
        resample_interval: Seconds between samples.
        registry_path: Path to the host registry YAML file.

    Returns:
        Formatted analysis string.
    """
    host_info = get_host_info(node_address, path=registry_path)
    ssh_connect = resolve_ssh_connect(node_address, host_info)
    cpu_cores = host_info.get("cpu_cores") if host_info else None
    thresholds = _get_thresholds(threshold_profile)

    if verbose:
        click_echo_safe(f"📋 SSH host: {node_address} -> {ssh_connect}")
        if host_info:
            click_echo_safe(f"📋 Host registry: {node_address} -> {host_info}")

    # Test SSH connectivity first
    reachable, message = ssh_test_connection(ssh_connect, allow_interactive=True)
    if not reachable:
        if json_output:
            return json.dumps({"error": f"SSH connection failed: {message}", "node": node_address, "ssh_connect": ssh_connect}, indent=2)
        return f"Error: SSH connection to {ssh_connect} failed: {message}"

    # Collect metrics via SSH (tracking missing tools)
    ssh_missing_tools: list[str] = []
    try:
        metrics = collect_ssh_metrics(ssh_connect, allow_interactive=True, missing_tools=ssh_missing_tools)
    except Exception as e:
        if json_output:
            return json.dumps({"error": f"SSH metric collection failed: {e}", "node": node_address}, indent=2)
        return f"Error: SSH metric collection from {ssh_connect} failed: {e}"

    # Determine CPU cores
    if cpu_cores is None:
        cpu_count_val = metrics.get("node_cpu_count")
        if cpu_count_val is not None:
            try:
                cpu_cores = int(cpu_count_val)
            except (ValueError, TypeError):
                pass
        if cpu_cores is None:
            cpu_seconds = metrics.get("node_cpu_seconds_total", [])
            if cpu_seconds:
                cpu_cores = len(set(
                    e["labels"]["cpu"] for e in cpu_seconds if "cpu" in e["labels"]
                ))

    # Optional second sample for rate-based analysis
    previous_metrics = None
    if resample:
        interval = resample_interval or RESAMPLE_INTERVAL_SECONDS
        time.sleep(interval)
        try:
            previous_metrics = metrics
            metrics = collect_ssh_metrics(ssh_connect, allow_interactive=True, missing_tools=ssh_missing_tools)
        except Exception:
            pass

    # Run all analysis functions
    results = [
        analyze_cpu(metrics, thresholds),
        analyze_memory(metrics, thresholds),
        analyze_disk(metrics, thresholds),
        analyze_disk_io(metrics, thresholds, previous_metrics=previous_metrics),
        analyze_network(metrics, thresholds),
        analyze_context_switching(
            metrics, thresholds,
            cpu_cores=cpu_cores,
            previous_metrics=previous_metrics,
            node_address=node_address,
        ),
    ]

    # Generate install suggestions from missing tools detected during SSH collection
    all_recommendations = []
    for r in results:
        all_recommendations.extend(r.recommendations)

    # Also check which diagnostic tools are unavailable on the remote host.
    # This catches tools like iotop, perf, ethtool, etc. that aren't used by
    # the SSH collector directly but are referenced in recommendation actions.
    remote_missing = check_remote_tools(ssh_connect, allow_interactive=True)

    # Merge: collection failures + remote availability check
    all_missing = list(set(ssh_missing_tools + remote_missing))

    from linuxdoctor.collectors import MetricCollection
    missing_collections = []
    if all_missing:
        mc = MetricCollection(category="ssh_collection", missing_tools=all_missing)
        missing_collections.append(mc)

    install_suggestions = generate_install_suggestions(
        missing_collections,
        recommendations=all_recommendations if include_recommendations else None,
    )

    url = f"ssh://{ssh_connect}"

    if json_output:
        return _format_json(url, port=22, metrics=metrics, results=results,
                            include_recommendations=include_recommendations, cpu_cores=cpu_cores,
                            install_suggestions=install_suggestions)

    # Use SSH-specific header in human output
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    all_recommendations.sort(key=lambda r: severity_order.get(r.severity, 3))

    return _format_human(url, results, include_recommendations, node_address=node_address,
                         cpu_cores=cpu_cores, install_suggestions=install_suggestions)


def is_ssh_host(host: str, registry_path: str = DEFAULT_REGISTRY_PATH) -> bool:
    """Check if a host is registered as an SSH host."""
    host_info = get_host_info(host, path=registry_path)
    return host_info is not None and "ssh_connect" in host_info


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