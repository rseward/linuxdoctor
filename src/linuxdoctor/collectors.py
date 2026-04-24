"""Collectors for local host performance metrics."""

import json
import shutil
import subprocess
import platform
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class MetricResult:
    """A single metric collection result."""
    name: str
    value: object
    unit: str = ""
    source: str = ""
    raw_output: str = ""
    error: Optional[str] = None


@dataclass
class MetricCollection:
    """Collection of metrics from a single check category."""
    category: str
    metrics: list = field(default_factory=list)
    error: Optional[str] = None
    missing_tools: list = field(default_factory=list)  # tool names that were unavailable during collection


def _run_command(cmd: list[str], timeout: int = 10) -> tuple[str, Optional[str]]:
    """Run a shell command and return (stdout, stderr_or_None)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return result.stdout.strip(), (result.stderr.strip() or f"exit code {result.returncode}")
        return result.stdout.strip(), None
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s"
    except Exception as e:
        return "", str(e)


def _tool_available(name: str) -> bool:
    """Check if a command-line tool is available on PATH."""
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# Package mapping for missing tools
# ---------------------------------------------------------------------------

# Maps command-line tool names to their dnf (Fedora/RHEL) and apt-get (Debian/Ubuntu)
# package names. Used to provide install suggestions when a tool is unavailable.
TOOL_PACKAGES: dict[str, dict[str, str]] = {
    # CPU / system stat tools
    "mpstat": {
        "dnf": "sysstat", "apt_get": "sysstat",
        "description": "Per-CPU and aggregate CPU utilization statistics",
        "categories": ["cpu"],
        "metrics": ["cpu_idle", "cpu_usage"],
    },
    "sar": {
        "dnf": "sysstat", "apt_get": "sysstat",
        "description": "Historical and real-time system activity reporter",
        "categories": ["cpu", "network", "sar_history"],
        "metrics": ["cpu_idle_sar", "tcp_sockets_total", "sar_mem_used_pct", "sar_swap_per_sec", "sar_net_*"],
    },
    "iostat": {
        "dnf": "sysstat", "apt_get": "sysstat",
        "description": "Device I/O utilization, await times, and service times",
        "categories": ["io"],
        "metrics": ["io_*_await_ms", "io_*_svctm_ms", "io_*_util_pct"],
    },
    "pidstat": {
        "dnf": "sysstat", "apt_get": "sysstat",
        "description": "Per-process CPU, memory, and I/O statistics",
        "categories": ["cpu", "io", "memory"],
        "metrics": ["per-process CPU/memory/IO stats"],
    },
    "perf": {
        "dnf": "perf", "apt_get": "linux-tools-common",
        "description": "Kernel performance events (context switches, cache misses, etc.)",
        "categories": ["cpu"],
        "metrics": ["context_switches_per_sec"],
    },
    "vmstat": {
        "dnf": "procps-ng", "apt_get": "procps",
        "description": "Virtual memory stats: blocks in/out, I/O wait, process queues",
        "categories": ["io", "load"],
        "metrics": ["io_blocks_in_per_sec", "io_blocks_out_per_sec", "io_wait_pct", "procs_running", "procs_blocked"],
    },
    "uptime": {
        "dnf": "procps-ng", "apt_get": "procps",
        "description": "System uptime and load averages",
        "categories": ["load"],
        "metrics": ["uptime_raw"],
    },
    "ss": {
        "dnf": "iproute", "apt_get": "iproute2",
        "description": "Socket statistics (TCP connections, TIME_WAIT, etc.)",
        "categories": ["network"],
        "metrics": ["tcp_established", "tcp_timewait"],
    },
    # I/O tools
    "iotop": {
        "dnf": "iotop", "apt_get": "iotop",
        "description": "Per-process I/O usage (identifies I/O-heavy processes)",
        "categories": ["io"],
        "metrics": ["per-process IO stats"],
    },
    "blktrace": {
        "dnf": "blktrace", "apt_get": "blktrace",
        "description": "Block device tracing for detailed I/O analysis",
        "categories": ["io"],
        "metrics": ["block IO trace data"],
    },
    # Disk tools
    "ncdu": {
        "dnf": "ncdu", "apt_get": "ncdu",
        "description": "Interactive disk usage analyzer (recommended for disk cleanup)",
        "categories": ["disk"],
        "metrics": ["interactive disk usage analysis"],
    },
    "df": {
        "dnf": "coreutils", "apt_get": "coreutils",
        "description": "Disk filesystem usage statistics",
        "categories": ["disk"],
        "metrics": ["disk_*_total_mb", "disk_*_used_mb", "disk_*_avail_mb", "disk_*_used_pct"],
    },
    # Network tools
    "ethtool": {
        "dnf": "ethtool", "apt_get": "ethtool",
        "description": "Network interface driver and link diagnostics",
        "categories": ["network"],
        "metrics": ["interface link details"],
    },
    "ip": {
        "dnf": "iproute", "apt_get": "iproute2",
        "description": "Network interface and routing statistics",
        "categories": ["network"],
        "metrics": ["interface link stats"],
    },
    # Memory tools
    "smem": {
        "dnf": "smem", "apt_get": "smem",
        "description": "Per-process memory reporting with proportional set size",
        "categories": ["memory"],
        "metrics": ["per-process memory breakdown"],
    },
    "free": {
        "dnf": "procps-ng", "apt_get": "procps",
        "description": "Memory and swap usage summary",
        "categories": ["memory"],
        "metrics": ["memory usage summary"],
    },
    # Process tools
    "ps": {
        "dnf": "procps-ng", "apt_get": "procps",
        "description": "Process listing and resource usage",
        "categories": ["cpu", "memory"],
        "metrics": ["process resource usage"],
    },
    "pstree": {
        "dnf": "psmisc", "apt_get": "psmisc",
        "description": "Process tree visualization",
        "categories": ["load"],
        "metrics": ["process hierarchy"],
    },
    "top": {
        "dnf": "procps-ng", "apt_get": "procps",
        "description": "Real-time process monitor",
        "categories": ["cpu", "memory"],
        "metrics": ["live process stats"],
    },
    # Logging
    "journalctl": {
        "dnf": "systemd", "apt_get": "systemd",
        "description": "System journal logs for boot and crash analysis",
        "categories": ["load"],
        "metrics": ["boot/crash logs"],
    },
    "dmesg": {
        "dnf": "util-linux", "apt_get": "util-linux",
        "description": "Kernel ring buffer messages",
        "categories": ["io", "load"],
        "metrics": ["kernel messages"],
    },
}


# ---------------------------------------------------------------------------
# CPU Collectors
# ---------------------------------------------------------------------------

def collect_cpu_metrics() -> MetricCollection:
    """Collect CPU-related metrics using mpstat, sar, and /proc."""
    collection = MetricCollection(category="cpu")

    # mpstat
    if _tool_available("mpstat"):
        stdout, err = _run_command(["mpstat", "1", "1"])
        if err:
            collection.metrics.append(MetricResult(
                name="cpu_idle", value=None, unit="%", source="mpstat", error=err
            ))
        else:
            # Parse: average: all ... %idle
            lines = stdout.strip().splitlines()
            for line in lines:
                if "all" in line.lower() or "Average" in line:
                    parts = line.split()
                    try:
                        idle = float(parts[-1])
                        collection.metrics.append(MetricResult(
                            name="cpu_idle", value=idle, unit="%",
                            source="mpstat", raw_output=stdout
                        ))
                        collection.metrics.append(MetricResult(
                            name="cpu_usage", value=round(100 - idle, 1), unit="%",
                            source="mpstat"
                        ))
                    except (ValueError, IndexError):
                        collection.metrics.append(MetricResult(
                            name="cpu_idle", value=None, source="mpstat",
                            raw_output=stdout, error="Failed to parse mpstat output"
                        ))
                    break

    else:
        collection.missing_tools.append("mpstat")

    # sar -u (CPU utilization)
    if _tool_available("sar"):
        stdout, err = _run_command(["sar", "-u", "1", "1"])
        if not err:
            lines = stdout.strip().splitlines()
            for line in lines:
                if "Average" in line:
                    parts = line.split()
                    try:
                        idle = float(parts[-1])
                        # Only add if mpstat didn't already provide
                        existing = [m.name for m in collection.metrics]
                        if "cpu_idle_sar" not in existing:
                            collection.metrics.append(MetricResult(
                                name="cpu_idle_sar", value=idle, unit="%",
                                source="sar -u", raw_output=stdout
                            ))
                    except (ValueError, IndexError):
                        pass
                    break
    else:
        collection.missing_tools.append("sar")

    # Load averages from /proc/loadavg (always available)
    try:
        with open("/proc/loadavg") as f:
            loadavg = f.read().strip().split()
            collection.metrics.append(MetricResult(
                name="load_1m", value=float(loadavg[0]), source="/proc/loadavg"
            ))
            collection.metrics.append(MetricResult(
                name="load_5m", value=float(loadavg[1]), source="/proc/loadavg"
            ))
            collection.metrics.append(MetricResult(
                name="load_15m", value=float(loadavg[2]), source="/proc/loadavg"
            ))
    except Exception as e:
        collection.metrics.append(MetricResult(
            name="load_1m", value=None, source="/proc/loadavg", error=str(e)
        ))

    # CPU count
    try:
        with open("/proc/cpuinfo") as f:
            count = sum(1 for line in f if line.startswith("processor"))
            collection.metrics.append(MetricResult(
                name="cpu_count", value=count, source="/proc/cpuinfo"
            ))
    except Exception as e:
        collection.metrics.append(MetricResult(
            name="cpu_count", value=None, source="/proc/cpuinfo", error=str(e)
        ))

    # Context switches via perf if available
    if _tool_available("perf"):
        stdout, err = _run_command(["perf", "stat", "-e", "context-switches", "--", "sleep", "1"], timeout=15)
        if not err:
            # Parse perf stat output
            for line in stdout.splitlines():
                if "context-switches" in line:
                    match = re.search(r"[\d,]+", line)
                    if match:
                        val = int(match.group().replace(",", ""))
                        collection.metrics.append(MetricResult(
                            name="context_switches_per_sec", value=val,
                            source="perf stat", raw_output=stdout
                        ))
                    break
    else:
        collection.missing_tools.append("perf")

    return collection


# ---------------------------------------------------------------------------
# Memory Collectors
# ---------------------------------------------------------------------------

def collect_memory_metrics() -> MetricCollection:
    """Collect memory metrics using free and /proc/meminfo."""
    collection = MetricCollection(category="memory")

    # /proc/meminfo (always available)
    meminfo = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    val = int(parts[1])  # in kB
                    meminfo[key] = val
    except Exception as e:
        collection.error = str(e)
        return collection

    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)
    buffers = meminfo.get("Buffers", 0)
    cached = meminfo.get("Cached", 0)
    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    used = total - available
    swap_used = swap_total - swap_free

    collection.metrics.append(MetricResult(
        name="mem_total_mb", value=round(total / 1024, 1), unit="MB", source="/proc/meminfo"
    ))
    collection.metrics.append(MetricResult(
        name="mem_available_mb", value=round(available / 1024, 1), unit="MB", source="/proc/meminfo"
    ))
    collection.metrics.append(MetricResult(
        name="mem_used_mb", value=round(used / 1024, 1), unit="MB", source="/proc/meminfo"
    ))
    if total > 0:
        collection.metrics.append(MetricResult(
            name="mem_used_pct", value=round(used / total * 100, 1), unit="%",
            source="/proc/meminfo"
        ))
    collection.metrics.append(MetricResult(
        name="mem_buffers_mb", value=round(buffers / 1024, 1), unit="MB", source="/proc/meminfo"
    ))
    collection.metrics.append(MetricResult(
        name="mem_cached_mb", value=round(cached / 1024, 1), unit="MB", source="/proc/meminfo"
    ))
    if swap_total > 0:
        collection.metrics.append(MetricResult(
            name="swap_total_mb", value=round(swap_total / 1024, 1), unit="MB", source="/proc/meminfo"
        ))
        collection.metrics.append(MetricResult(
            name="swap_used_mb", value=round(swap_used / 1024, 1), unit="MB", source="/proc/meminfo"
        ))
        collection.metrics.append(MetricResult(
            name="swap_used_pct", value=round(swap_used / swap_total * 100, 1), unit="%",
            source="/proc/meminfo"
        ))
    else:
        collection.metrics.append(MetricResult(
            name="swap_total_mb", value=0, unit="MB", source="/proc/meminfo"
        ))
        collection.metrics.append(MetricResult(
            name="swap_used_pct", value=0, unit="%", source="/proc/meminfo"
        ))

    # Huge pages
    huge_pages_total = meminfo.get("HugePages_Total", 0)
    huge_pages_free = meminfo.get("HugePages_Free", 0)
    if huge_pages_total > 0:
        collection.metrics.append(MetricResult(
            name="hugepages_total", value=huge_pages_total, source="/proc/meminfo"
        ))
        collection.metrics.append(MetricResult(
            name="hugepages_free", value=huge_pages_free, source="/proc/meminfo"
        ))

    return collection


# ---------------------------------------------------------------------------
# Disk Collectors
# ---------------------------------------------------------------------------

def _sanitize_mount_name(mount: str) -> str:
    """Convert a mount path to a safe metric name component."""
    if mount == "/":
        return "root"
    # Remove leading slash, replace remaining slashes and hyphens with underscores
    name = mount.lstrip("/").replace("/", "_").replace("-", "_")
    return name


def collect_disk_metrics() -> MetricCollection:
    """Collect disk usage metrics using df."""
    collection = MetricCollection(category="disk")

    stdout, err = _run_command(["df", "-B", "M", "--output=source,size,used,avail,pcent,target"])
    if err:
        collection.error = err
        return collection

    # Filesystem types to skip (virtual/pseudo)
    skip_fs_types = {"devtmpfs", "tmpfs", "overlay", "shm", "proc", "sys", "cgroup",
                     "cgroup2", "devpts", "mqueue", "hugetlbfs", "debugfs",
                     "tracefs", "securityfs", "fusectl", "configfs", "pstore",
                     "efivarfs", "bpf", "binfmt_misc"}

    lines = stdout.strip().splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 6:
            device = parts[0]
            size_str = parts[1].rstrip("M")
            used_str = parts[2].rstrip("M")
            avail_str = parts[3].rstrip("M")
            pct_str = parts[4].rstrip("%")
            mount = parts[5]

            # Skip virtual/pseudo filesystems and uninteresting mounts
            skip_prefixes = ("devtmpfs", "tmpfs", "overlay", "shm", "proc", "sys",
                              "cgroup", "efivarfs", "devpts", "mqueue", "fusectl",
                              "debugfs", "tracefs", "securityfs", "pstore", "bpf",
                              "binfmt_misc", "hugetlbfs", "configfs")
            if any(device.startswith(p) for p in skip_prefixes):
                continue
            if device == "none":
                continue
            # Skip container/sandbox shm mounts
            if "/containerd/" in mount or "/sandboxes/" in mount:
                continue
            # Skip snap loop mounts
            if device.startswith("/dev/loop"):
                continue

            safe_name = _sanitize_mount_name(mount)
            try:
                collection.metrics.append(MetricResult(
                    name=f"disk_{safe_name}_total_mb",
                    value=float(size_str), unit="MB", source="df"
                ))
                collection.metrics.append(MetricResult(
                    name=f"disk_{safe_name}_used_mb",
                    value=float(used_str), unit="MB", source="df"
                ))
                collection.metrics.append(MetricResult(
                    name=f"disk_{safe_name}_avail_mb",
                    value=float(avail_str), unit="MB", source="df"
                ))
                collection.metrics.append(MetricResult(
                    name=f"disk_{safe_name}_used_pct",
                    value=int(pct_str), unit="%", source="df"
                ))
            except ValueError:
                pass

    return collection


# ---------------------------------------------------------------------------
# I/O Collectors
# ---------------------------------------------------------------------------

def collect_io_metrics() -> MetricCollection:
    """Collect I/O metrics using iostat and vmstat."""
    collection = MetricCollection(category="io")

    # iostat - skip loop devices to reduce noise
    _skip_device_prefixes = ("loop", "ram", "zram")

    # iostat
    if _tool_available("iostat"):
        stdout, err = _run_command(["iostat", "-dx", "1", "1"])
        if not err and stdout.strip():
            lines = stdout.strip().splitlines()
            in_device_section = False
            for line in lines:
                # Skip header lines, look for device lines
                if line.startswith("Device"):
                    in_device_section = True
                    continue
                if in_device_section and line.strip():
                    parts = line.split()
                    if len(parts) >= 14:
                        device = parts[0]

                        # Skip loop, ram, and zram devices
                        if any(device.startswith(p) for p in _skip_device_prefixes):
                            continue

                        try:
                            await_ms = float(parts[-4]) if len(parts) > 10 else None
                            svc_ms = float(parts[-1]) if len(parts) > 10 else None
                            util_pct = float(parts[-2]) if len(parts) > 10 else None

                            safe_name = device.replace("/", "_")
                            if await_ms is not None:
                                collection.metrics.append(MetricResult(
                                    name=f"io_{safe_name}_await_ms",
                                    value=await_ms, unit="ms", source="iostat"
                                ))
                            if svc_ms is not None:
                                collection.metrics.append(MetricResult(
                                    name=f"io_{safe_name}_svctm_ms",
                                    value=svc_ms, unit="ms", source="iostat"
                                ))
                            if util_pct is not None:
                                collection.metrics.append(MetricResult(
                                    name=f"io_{safe_name}_util_pct",
                                    value=util_pct, unit="%", source="iostat"
                                ))
                        except (ValueError, IndexError):
                            pass

    else:
        collection.missing_tools.append("iostat")

    # vmstat - disk I/O summary
    if _tool_available("vmstat"):
        stdout, err = _run_command(["vmstat", "1", "2"])
        if not err:
            lines = stdout.strip().splitlines()
            if len(lines) >= 3:
                # Last data line
                data_line = lines[-1]
                parts = data_line.split()
                if len(parts) >= 18:
                    try:
                        # bo (blocks out), bi (blocks in) are at indices 8, 9
                        collection.metrics.append(MetricResult(
                            name="io_blocks_in_per_sec", value=int(parts[8]),
                            source="vmstat", raw_output=stdout
                        ))
                        collection.metrics.append(MetricResult(
                            name="io_blocks_out_per_sec", value=int(parts[9]),
                            source="vmstat"
                        ))
                        # wa (IO wait) at index 16
                        collection.metrics.append(MetricResult(
                            name="io_wait_pct", value=int(parts[16]), unit="%",
                            source="vmstat"
                        ))
                    except (ValueError, IndexError):
                        pass
    else:
        collection.missing_tools.append("vmstat")

    return collection


# ---------------------------------------------------------------------------
# Network Collectors
# ---------------------------------------------------------------------------

def collect_network_metrics() -> MetricCollection:
    """Collect network metrics from /proc/net/dev and ss."""
    collection = MetricCollection(category="network")

    # /proc/net/dev
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()
            for line in lines[2:]:  # skip 2 header lines
                parts = line.strip().split(":")
                if len(parts) == 2:
                    iface = parts[0].strip()
                    if iface == "lo":
                        continue
                    fields = parts[1].split()
                    if len(fields) >= 10:
                        safe_name = iface.replace(".", "_")
                        collection.metrics.append(MetricResult(
                            name=f"net_{safe_name}_rx_bytes",
                            value=int(fields[0]), source="/proc/net/dev"
                        ))
                        collection.metrics.append(MetricResult(
                            name=f"net_{safe_name}_tx_bytes",
                            value=int(fields[8]), source="/proc/net/dev"
                        ))
                        collection.metrics.append(MetricResult(
                            name=f"net_{safe_name}_rx_errors",
                            value=int(fields[2]), source="/proc/net/dev"
                        ))
                        collection.metrics.append(MetricResult(
                            name=f"net_{safe_name}_tx_errors",
                            value=int(fields[10]), source="/proc/net/dev"
                        ))
    except Exception as e:
        collection.error = str(e)

    # ss - socket summary
    if _tool_available("ss"):
        stdout, err = _run_command(["ss", "-s"])
        if not err:
            # Parse summary: "Total: 1234 (kernel 5678) TCP: 90 (estab 30, ...)
            for line in stdout.splitlines():
                if line.startswith("TCP:"):
                    # e.g. "TCP:   33 (estab 18, closed 0, orphaned 0, timewait 0)"
                    match = re.search(r"estab\s+(\d+)", line)
                    if match:
                        collection.metrics.append(MetricResult(
                            name="tcp_established", value=int(match.group(1)),
                            source="ss -s", raw_output=stdout
                        ))
                    match = re.search(r"timewait\s+(\d+)", line)
                    if match:
                        collection.metrics.append(MetricResult(
                            name="tcp_timewait", value=int(match.group(1)),
                            source="ss -s"
                        ))
                    break

    else:
        collection.missing_tools.append("ss")

    # Network connections in various states (sar -n SOCK if available)
    if _tool_available("sar"):
        stdout, err = _run_command(["sar", "-n", "SOCK", "1", "1"])
        if not err:
            for line in stdout.splitlines():
                if "Average" in line:
                    parts = line.split()
                    try:
                        collection.metrics.append(MetricResult(
                            name="tcp_sockets_total", value=int(parts[1]),
                            source="sar -n SOCK", raw_output=stdout
                        ))
                    except (ValueError, IndexError):
                        pass
                    break

    else:
        collection.missing_tools.append("sar")

    return collection


# ---------------------------------------------------------------------------
# Load / Uptime Collectors
# ---------------------------------------------------------------------------

def collect_load_metrics() -> MetricCollection:
    """Collect load and uptime metrics."""
    collection = MetricCollection(category="load")

    # uptime
    if _tool_available("uptime"):
        stdout, err = _run_command(["uptime"])
        if not err:
            collection.metrics.append(MetricResult(
                name="uptime_raw", value=stdout.strip(), source="uptime"
            ))
    else:
        collection.missing_tools.append("uptime")

    # /proc/uptime (always available)
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
            days = uptime_seconds / 86400
            collection.metrics.append(MetricResult(
                name="uptime_seconds", value=round(uptime_seconds, 0), unit="s",
                source="/proc/uptime"
            ))
            collection.metrics.append(MetricResult(
                name="uptime_days", value=round(days, 1), unit="days",
                source="/proc/uptime"
            ))
    except Exception as e:
        collection.metrics.append(MetricResult(
            name="uptime_seconds", value=None, source="/proc/uptime", error=str(e)
        ))

    # Process count
    try:
        import os
        pids = os.listdir("/proc")
        proc_count = sum(1 for p in pids if p.isdigit())
        collection.metrics.append(MetricResult(
            name="process_count", value=proc_count, source="/proc"
        ))
    except Exception:
        pass

    # Running/blocked processes from vmstat
    if _tool_available("vmstat"):
        stdout, err = _run_command(["vmstat", "1", "2"])
        if not err:
            lines = stdout.strip().splitlines()
            if len(lines) >= 3:
                parts = lines[-1].split()
                if len(parts) >= 3:
                    try:
                        collection.metrics.append(MetricResult(
                            name="procs_running", value=int(parts[0]),
                            source="vmstat", raw_output=stdout
                        ))
                        collection.metrics.append(MetricResult(
                            name="procs_blocked", value=int(parts[1]),
                            source="vmstat"
                        ))
                    except (ValueError, IndexError):
                        pass
    else:
        collection.missing_tools.append("vmstat")

    return collection


# ---------------------------------------------------------------------------
# SAR Historical Data
# ---------------------------------------------------------------------------

def collect_sar_metrics() -> MetricCollection:
    """Collect historical SAR data if available."""
    collection = MetricCollection(category="sar_history")

    if not _tool_available("sar"):
        collection.missing_tools.append("sar")
        collection.metrics.append(MetricResult(
            name="sar_available", value=False, source="sar",
            error="sar (sysstat) not installed"
        ))
        return collection

    collection.metrics.append(MetricResult(
        name="sar_available", value=True, source="sar"
    ))

    # sar -r (memory history)
    stdout, err = _run_command(["sar", "-r", "1", "1"])
    if not err:
        for line in stdout.splitlines():
            if "Average" in line:
                parts = line.split()
                try:
                    # Find %memused column by header position
                    # Typical: kbmemfree kbavail kbmemused %memused kbbuffers kbcached kbcommit %commit ...
                    # %memused is the 4th data column (index 4 in 0-based after "Average:")
                    if len(parts) >= 5:
                        collection.metrics.append(MetricResult(
                            name="sar_mem_used_pct", value=float(parts[4]), unit="%",
                            source="sar -r", raw_output=stdout
                        ))
                    if len(parts) >= 9:
                        # %commit is the 8th data column (index 8)
                        collection.metrics.append(MetricResult(
                            name="sar_commit_pct", value=float(parts[8]), unit="%",
                            source="sar -r"
                        ))
                    if len(parts) >= 4:
                        # kbmemused (index 3)
                        collection.metrics.append(MetricResult(
                            name="sar_mem_used_kb", value=float(parts[3]), unit="kB",
                            source="sar -r"
                        ))
                except (ValueError, IndexError):
                    pass
                break

    # sar -W (swap)
    stdout, err = _run_command(["sar", "-W", "1", "1"])
    if not err:
        for line in stdout.splitlines():
            if "Average" in line:
                parts = line.split()
                try:
                    if len(parts) >= 4:
                        collection.metrics.append(MetricResult(
                            name="sar_swap_per_sec", value=float(parts[2]),
                            source="sar -W"
                        ))
                except (ValueError, IndexError):
                    pass
                break

    # sar -n DEV (network)
    stdout, err = _run_command(["sar", "-n", "DEV", "1", "1"])
    if not err:
        for line in stdout.splitlines():
            if "Average" in line and "IFACE" not in line:
                parts = line.split()
                try:
                    if len(parts) >= 6 and parts[1] != "lo":
                        iface = parts[1].replace(".", "_")
                        collection.metrics.append(MetricResult(
                            name=f"sar_net_{iface}_rx_kb_s", value=float(parts[4]),
                            unit="kB/s", source="sar -n DEV"
                        ))
                        collection.metrics.append(MetricResult(
                            name=f"sar_net_{iface}_tx_kb_s", value=float(parts[5]),
                            unit="kB/s", source="sar -n DEV"
                        ))
                except (ValueError, IndexError):
                    pass

    return collection


# ---------------------------------------------------------------------------
# Main collection entry point
# ---------------------------------------------------------------------------

ALL_COLLECTORS = {
    "cpu": collect_cpu_metrics,
    "memory": collect_memory_metrics,
    "disk": collect_disk_metrics,
    "io": collect_io_metrics,
    "network": collect_network_metrics,
    "load": collect_load_metrics,
    "sar": collect_sar_metrics,
}


def collect_all(checks: list[str] | None = None) -> list[MetricCollection]:
    """Run all collectors (or a subset) and return results."""
    if checks is None:
        checks = list(ALL_COLLECTORS.keys())

    results = []
    for name in checks:
        collector = ALL_COLLECTORS.get(name)
        if collector is None:
            results.append(MetricCollection(category=name, error=f"Unknown check: {name}"))
            continue
        try:
            results.append(collector())
        except Exception as e:
            results.append(MetricCollection(category=name, error=str(e)))

    return results