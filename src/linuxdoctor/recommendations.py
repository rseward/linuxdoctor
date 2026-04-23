"""Recommendation engine for linuxdoctor.

Analyzes collected metrics and generates actionable recommendations,
analogous to node_exporter best-practice alerts but for local host analysis.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Recommendation:
    """A single recommendation with severity and details."""
    category: str
    severity: str  # critical, warning, info
    metric: str
    message: str
    detail: str = ""
    action: str = ""


# ---------------------------------------------------------------------------
# Threshold profiles
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "default": {
        "cpu_usage_pct": 85,
        "cpu_iowait_pct": 20,
        "mem_used_pct": 85,
        "swap_used_pct": 25,
        "disk_used_pct": 80,
        "disk_used_pct_critical": 95,
        "load_per_cpu": 4.0,
        "load_per_cpu_warning": 2.0,
        "io_await_ms": 50,
        "io_util_pct": 90,
        "process_blocked": 5,
        "hugepages_waste_pct": 50,
    },
    "strict": {
        "cpu_usage_pct": 70,
        "cpu_iowait_pct": 10,
        "mem_used_pct": 75,
        "swap_used_pct": 10,
        "disk_used_pct": 70,
        "disk_used_pct_critical": 85,
        "load_per_cpu": 2.0,
        "load_per_cpu_warning": 1.0,
        "io_await_ms": 30,
        "io_util_pct": 75,
        "process_blocked": 2,
        "hugepages_waste_pct": 30,
    },
    "relaxed": {
        "cpu_usage_pct": 95,
        "cpu_iowait_pct": 40,
        "mem_used_pct": 95,
        "swap_used_pct": 50,
        "disk_used_pct": 90,
        "disk_used_pct_critical": 98,
        "load_per_cpu": 8.0,
        "load_per_cpu_warning": 4.0,
        "io_await_ms": 100,
        "io_util_pct": 98,
        "process_blocked": 10,
        "hugepages_waste_pct": 70,
    },
}


def _get_thresholds(profile: str) -> dict:
    """Get threshold values for a given profile."""
    return THRESHOLDS.get(profile, THRESHOLDS["default"])


# ---------------------------------------------------------------------------
# Metric extraction helpers
# ---------------------------------------------------------------------------

def _find_metric(collections: list, category: str, name: str) -> Optional[object]:
    """Find a specific metric value from collections."""
    for coll in collections:
        if coll.category == category:
            for m in coll.metrics:
                if m.name == name and m.error is None:
                    return m.value
    return None


def _find_metrics_matching(collections: list, category: str, prefix: str) -> dict[str, object]:
    """Find all metrics matching a prefix in a category."""
    result = {}
    for coll in collections:
        if coll.category == category:
            for m in coll.metrics:
                if m.name.startswith(prefix) and m.error is None:
                    result[m.name] = m.value
    return result


# ---------------------------------------------------------------------------
# Recommendation generators by category
# ---------------------------------------------------------------------------

def recommend_cpu(collections: list, thresholds: dict) -> list[Recommendation]:
    """Generate CPU recommendations."""
    recs = []

    cpu_usage = _find_metric(collections, "cpu", "cpu_usage")
    if cpu_usage is not None:
        if cpu_usage > thresholds["cpu_usage_pct"]:
            recs.append(Recommendation(
                category="cpu", severity="critical",
                metric="cpu_usage",
                message=f"CPU usage is {cpu_usage}% (threshold: {thresholds['cpu_usage_pct']}%)",
                detail="Sustained high CPU usage can cause performance degradation. "
                       "Consider scaling vertically (more CPUs) or horizontally (distributing load).",
                action="Identify top CPU consumers with `top` or `ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head`."
            ))

    cpu_idle = _find_metric(collections, "cpu", "cpu_idle")
    if cpu_idle is not None and cpu_idle < 10:
        recs.append(Recommendation(
            category="cpu", severity="warning",
            metric="cpu_idle",
            message=f"CPU idle is only {cpu_idle}% — system is heavily loaded",
            detail="When CPU idle approaches 0%, processes are competing for CPU time.",
            action="Check for runaway processes with `top -o %CPU`."
        ))

    # Load average check
    load_1m = _find_metric(collections, "cpu", "load_1m")
    cpu_count = _find_metric(collections, "cpu", "cpu_count")
    if load_1m is not None and cpu_count is not None and cpu_count > 0:
        load_per_cpu = load_1m / cpu_count
        if load_per_cpu > thresholds["load_per_cpu"]:
            recs.append(Recommendation(
                category="cpu", severity="critical",
                metric="load_1m",
                message=f"Load average {load_1m} is {load_per_cpu:.1f}x CPU count ({cpu_count} CPUs)",
                detail="High load per CPU indicates the system is oversubscribed. "
                       "This leads to scheduling delays and poor responsiveness.",
                action="Review running processes with `ps aux --sort=-%cpu | head -20`."
            ))
        elif load_per_cpu > thresholds["load_per_cpu_warning"]:
            recs.append(Recommendation(
                category="cpu", severity="warning",
                metric="load_1m",
                message=f"Load average {load_1m} is elevated ({load_per_cpu:.1f}x CPU count)",
                detail="Moderate load elevation. Monitor for sustained increases.",
                action="Monitor with `uptime` or `sar -q`."
            ))

    return recs


def recommend_memory(collections: list, thresholds: dict) -> list[Recommendation]:
    """Generate memory recommendations."""
    recs = []

    mem_used_pct = _find_metric(collections, "memory", "mem_used_pct")
    if mem_used_pct is not None:
        if mem_used_pct > thresholds["mem_used_pct"]:
            recs.append(Recommendation(
                category="memory", severity="critical",
                metric="mem_used_pct",
                message=f"Memory usage is {mem_used_pct}% (threshold: {thresholds['mem_used_pct']}%)",
                detail="High memory usage leads to OOM kills and swapping. "
                       "Consider adding RAM or reducing memory consumption.",
                action="Check top consumers: `ps aux --sort=-%mem | head -20`. "
                       "Consider tuning vm.swappiness or adding swap."
            ))
        elif mem_used_pct > thresholds["mem_used_pct"] - 10:
            recs.append(Recommendation(
                category="memory", severity="warning",
                metric="mem_used_pct",
                message=f"Memory usage is {mem_used_pct}% — approaching threshold",
                detail="Memory pressure is building. Plan capacity accordingly.",
                action="Monitor with `free -h` and `vmstat -s`."
            ))

    swap_used_pct = _find_metric(collections, "memory", "swap_used_pct")
    if swap_used_pct is not None and swap_used_pct > thresholds["swap_used_pct"]:
        recs.append(Recommendation(
            category="memory", severity="warning",
            metric="swap_used_pct",
            message=f"Swap usage is {swap_used_pct}% (threshold: {thresholds['swap_used_pct']}%)",
            detail="Active swapping degrades performance significantly. "
                   "This typically indicates memory pressure.",
            action="Consider: 1) Adding physical RAM, 2) Tuning vm.swappiness, "
                   "3) Identifying memory-heavy processes with `smem` or `ps --sort=-rss`."
        ))

    # Huge pages check
    hugepages_total = _find_metric(collections, "memory", "hugepages_total")
    hugepages_free = _find_metric(collections, "memory", "hugepages_free")
    if hugepages_total is not None and hugepages_total > 0 and hugepages_free is not None:
        waste_pct = (hugepages_free / hugepages_total) * 100
        if waste_pct > thresholds["hugepages_waste_pct"]:
            recs.append(Recommendation(
                category="memory", severity="info",
                metric="hugepages_free",
                message=f"{waste_pct:.0f}% of HugePages are unused ({hugepages_free}/{hugepages_total})",
                detail="Unused HugePages consume memory that could be available to other processes.",
                action=f"Consider reducing HugePages: edit /etc/sysctl.conf vm.nr_hugepages "
                       f"and run `sysctl -p`."
            ))

    return recs


DISK_METRIC_SUFFIXES = ("total_mb", "used_mb", "avail_mb", "used_pct")


def _mount_key_to_path(mount_key: str) -> str:
    """Convert a metric mount key like 'disk_root' or 'disk_boot' back to a path."""
    # Remove 'disk_' prefix
    name = mount_key
    if name.startswith("disk_"):
        name = name[5:]
    if name == "root" or not name:
        return "/"
    # underscores represent slashes/hyphens that were sanitized
    return "/" + name.replace("_", "/")


def recommend_disk(collections: list, thresholds: dict) -> list[Recommendation]:
    """Generate disk usage recommendations."""
    recs = []

    disk_metrics = _find_metrics_matching(collections, "disk", "disk_")
    # Group by mount point using known metric suffixes
    mounts = {}
    for name, value in disk_metrics.items():
        # Try to match known suffixes: disk_{mount}_{suffix}
        # e.g., disk___used_pct (root /), disk__boot_used_pct (/boot)
        matched = False
        for suffix in DISK_METRIC_SUFFIXES:
            if name.endswith("_" + suffix):
                mount_key = name[:-(len(suffix) + 1)]  # strip _suffix
                metric_type = suffix
                if mount_key not in mounts:
                    mounts[mount_key] = {}
                mounts[mount_key][metric_type] = value
                matched = True
                break
        if not matched:
            # Fallback: try last part as metric type
            parts = name.rsplit("_", 1)
            if len(parts) == 2:
                mount_key = parts[0]
                metric_type = parts[1]
                if mount_key not in mounts:
                    mounts[mount_key] = {}
                mounts[mount_key][metric_type] = value

    for mount_key, metrics in mounts.items():
        # Reconstruct mount path using the sanitizer logic
        mount_path = _mount_key_to_path(mount_key)

        used_pct = metrics.get("used_pct")
        if used_pct is not None:
            if used_pct >= thresholds["disk_used_pct_critical"]:
                recs.append(Recommendation(
                    category="disk", severity="critical",
                    metric=f"{mount_key}_used_pct",
                    message=f"Disk {mount_path} is {used_pct}% full (critical: {thresholds['disk_used_pct_critical']}%)",
                    detail="Critically low disk space can cause data corruption, failed writes, and system instability.",
                    action=f"Clean up disk {mount_path}: `du -sh {mount_path}/* | sort -rh | head` "
                           f"and `find {mount_path} -type f -size +100M -exec ls -lh {{}} \\;`."
                ))
            elif used_pct >= thresholds["disk_used_pct"]:
                recs.append(Recommendation(
                    category="disk", severity="warning",
                    metric=f"{mount_key}_used_pct",
                    message=f"Disk {mount_path} is {used_pct}% full (threshold: {thresholds['disk_used_pct']}%)",
                    detail="Approaching disk capacity. Plan for expansion or cleanup.",
                    action=f"Review large files: `ncdu {mount_path}` or `du -sh {mount_path}/* | sort -rh`."
                ))

    return recs


def recommend_io(collections: list, thresholds: dict) -> list[Recommendation]:
    """Generate I/O recommendations."""
    recs = []

    io_metrics = _find_metrics_matching(collections, "io", "io_")
    # Check await times and util for each device
    devices = {}
    for name, value in io_metrics.items():
        # io_sda_await_ms -> sda
        parts = name.split("_", 2)  # io, device, metric
        if len(parts) >= 3:
            device = parts[1]
            metric = parts[2]
            if device not in devices:
                devices[device] = {}
            devices[device][metric] = value

    for device, metrics in devices.items():
        await_ms = metrics.get("await_ms")
        if await_ms is not None and await_ms > thresholds["io_await_ms"]:
            recs.append(Recommendation(
                category="io", severity="warning",
                metric=f"io_{device}_await_ms",
                message=f"Device {device} I/O await is {await_ms}ms (threshold: {thresholds['io_await_ms']}ms)",
                detail="High I/O await times indicate the storage subsystem is saturated. "
                       "This causes application latency.",
                action=f"Check I/O queue: `iostat -x 1 5` and `iotop`. "
                       f"Consider faster storage (NVMe/SSD) or workload distribution."
            ))

        util_pct = metrics.get("util_pct")
        if util_pct is not None and util_pct > thresholds["io_util_pct"]:
            recs.append(Recommendation(
                category="io", severity="critical",
                metric=f"io_{device}_util_pct",
                message=f"Device {device} I/O utilization is {util_pct}% (threshold: {thresholds['io_util_pct']}%)",
                detail="Near-100% I/O utilization means the storage device is fully saturated. "
                       "This is a critical bottleneck.",
                action=f"Offload I/O, add faster storage, or optimize I/O patterns. "
                       f"Check: `iostat -x 1` and `blktrace`."
            ))

    # IO wait from vmstat
    io_wait = _find_metric(collections, "io", "io_wait_pct")
    if io_wait is not None and io_wait > thresholds["cpu_iowait_pct"]:
        recs.append(Recommendation(
            category="io", severity="warning",
            metric="io_wait_pct",
            message=f"I/O wait is {io_wait}% (threshold: {thresholds['cpu_iowait_pct']}%)",
            detail="High I/O wait means CPUs are blocked waiting for disk I/O. "
                   "This wastes CPU time and degrades performance.",
            action="Identify I/O-heavy processes: `iotop` or `pidstat -d 1`."
        ))

    return recs


def recommend_network(collections: list, thresholds: dict) -> list[Recommendation]:
    """Generate network recommendations."""
    recs = []

    # Check for interface errors
    net_metrics = _find_metrics_matching(collections, "network", "net_")
    interfaces = {}
    for name, value in net_metrics.items():
        # net_eth0_rx_errors -> eth0
        parts = name.split("_", 2)  # net, iface, metric
        if len(parts) >= 3:
            iface = parts[1]
            metric = parts[2]
            if iface not in interfaces:
                interfaces[iface] = {}
            interfaces[iface][metric] = value

    for iface, metrics in interfaces.items():
        rx_errors = metrics.get("rx_errors")
        tx_errors = metrics.get("tx_errors")
        if (rx_errors is not None and rx_errors > 0) or (tx_errors is not None and tx_errors > 0):
            total_errors = (rx_errors or 0) + (tx_errors or 0)
            recs.append(Recommendation(
                category="network", severity="warning",
                metric=f"net_{iface}_errors",
                message=f"Interface {iface} has {total_errors} errors (rx: {rx_errors}, tx: {tx_errors})",
                detail="Network errors can indicate duplex mismatches, bad cabling, or driver issues.",
                action=f"Check interface details: `ethtool {iface}` and `ip -s link show {iface}`."
            ))

    # TCP connections
    tcp_estab = _find_metric(collections, "network", "tcp_established")
    tcp_timewait = _find_metric(collections, "network", "tcp_timewait")
    if tcp_estab is not None and tcp_timewait is not None:
        if tcp_estab > 0 and tcp_timewait > tcp_estab * 2:
            recs.append(Recommendation(
                category="network", severity="info",
                metric="tcp_timewait",
                message=f"High TIME_WAIT ratio: {tcp_timewait} TIME_WAIT vs {tcp_estab} ESTABLISHED",
                detail="Excessive TIME_WAIT sockets can exhaust ephemeral ports. "
                       "This is common with short-lived HTTP connections.",
                action="Consider tuning: `net.ipv4.tcp_tw_reuse=1` and `net.ipv4.tcp_fin_timeout=15`."
            ))

    return recs


def recommend_load(collections: list, thresholds: dict) -> list[Recommendation]:
    """Generate load/process recommendations."""
    recs = []

    procs_blocked = _find_metric(collections, "load", "procs_blocked")
    if procs_blocked is not None and procs_blocked > thresholds["process_blocked"]:
        recs.append(Recommendation(
            category="load", severity="warning",
            metric="procs_blocked",
            message=f"{procs_blocked} processes are blocked (threshold: {thresholds['process_blocked']})",
            detail="Blocked processes are waiting for I/O or locks. "
                   "This can indicate storage bottlenecks or kernel lock contention.",
            action="Check blocked processes: `ps aux | awk '$8 ~ /D/'` and `iotop`."
        ))

    process_count = _find_metric(collections, "load", "process_count")
    if process_count is not None and process_count > 500:
        recs.append(Recommendation(
            category="load", severity="info",
            metric="process_count",
            message=f"High process count: {process_count}",
            detail="A large number of processes increases scheduling overhead.",
            action="Review process tree: `ps auxf | less` or `pstree`."
        ))

    uptime_days = _find_metric(collections, "load", "uptime_days")
    if uptime_days is not None and uptime_days < 1:
        recs.append(Recommendation(
            category="load", severity="info",
            metric="uptime_days",
            message=f"System recently rebooted (uptime: {uptime_days} days)",
            detail="A recent reboot may indicate instability or maintenance. "
                   "Check for crash indicators in logs.",
            action="Review boot logs: `journalctl -b -1` and `dmesg | tail -50`."
        ))

    return recs


# ---------------------------------------------------------------------------
# Main recommendation engine
# ---------------------------------------------------------------------------

RECOMMENDATION_GENERATORS = {
    "cpu": recommend_cpu,
    "memory": recommend_memory,
    "disk": recommend_disk,
    "io": recommend_io,
    "network": recommend_network,
    "load": recommend_load,
}


def generate_recommendations(collections: list, threshold_profile: str = "default") -> list[Recommendation]:
    """Generate recommendations from collected metrics.

    Args:
        collections: List of MetricCollection objects from collectors.
        threshold_profile: One of 'default', 'strict', or 'relaxed'.

    Returns:
        List of Recommendation objects, sorted by severity.
    """
    thresholds = _get_thresholds(threshold_profile)
    all_recs = []

    for name, generator in RECOMMENDATION_GENERATORS.items():
        try:
            recs = generator(collections, thresholds)
            all_recs.extend(recs)
        except Exception as e:
            all_recs.append(Recommendation(
                category=name, severity="critical",
                metric="error",
                message=f"Failed to generate {name} recommendations: {e}"
            ))

    # Sort by severity
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    all_recs.sort(key=lambda r: severity_order.get(r.severity, 3))

    return all_recs