"""Collect performance metrics from remote hosts via SSH.

This module gathers metrics from remote Linux hosts by running traditional
performance tools (mpstat, vmstat, iostat, etc.) over SSH connections.
It converts the output into Prometheus-compatible metric names so that
the same analysis functions used for node_exporter can be applied.

Requirements:
  - Passwordless SSH access (key-based authentication)
  - Remote host keys already accepted
  - Standard Linux perf tools installed on the remote host:
    mpstat, vmstat, iostat, sar (sysstat package)

When running from the CLI, interactive host key acceptance and password
entry are allowed (the SSH command can prompt). From the web dashboard,
hosts requiring interactive auth are marked unreachable.
"""

import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# SSH connection helpers
# ---------------------------------------------------------------------------

@dataclass
class SSHResult:
    """Result from an SSH command execution."""
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    error: Optional[str] = None


def ssh_run(ssh_connect: str, command: str, timeout: int = 15,
            allow_interactive: bool = False) -> SSHResult:
    """Run a command on a remote host via SSH.

    Args:
        ssh_connect: SSH connection string (e.g. 'user@host' or 'host').
        command: The shell command to run on the remote host.
        timeout: Command timeout in seconds.
        allow_interactive: If True, allow interactive prompts (host key
            acceptance, password entry). If False, use BatchMode=yes to
            fail fast on any interactive prompt.

    Returns:
        SSHResult with stdout, stderr, returncode, and optional error.
    """
    ssh_opts = [
        "ssh",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no" if allow_interactive else "StrictHostKeyChecking=yes",
        "-o", f"BatchMode={'no' if allow_interactive else 'yes'}",
        "-o", f"ServerAliveInterval={min(timeout, 10)}",
        "-o", f"ServerAliveCountMax=3",
    ]

    cmd = ssh_opts + [ssh_connect, command]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return SSHResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            error=None if result.returncode == 0 else (result.stderr.strip() or f"exit code {result.returncode}"),
        )
    except subprocess.TimeoutExpired:
        return SSHResult(error=f"SSH command timed out after {timeout}s")
    except FileNotFoundError:
        return SSHResult(error="ssh command not found — is OpenSSH installed?")
    except Exception as e:
        return SSHResult(error=f"SSH error: {e}")


def ssh_test_connection(ssh_connect: str, timeout: int = 10,
                         allow_interactive: bool = False) -> tuple[bool, str]:
    """Test SSH connectivity to a remote host.

    Returns:
        Tuple of (reachable: bool, message: str).
    """
    result = ssh_run(ssh_connect, "echo ok", timeout=timeout, allow_interactive=allow_interactive)
    if result.error:
        # Check for common SSH errors
        err = result.error.lower()
        if "host key" in err or "hostkey" in err:
            return False, f"SSH host key verification failed for {ssh_connect}. Accept the key first: ssh {ssh_connect}"
        if "permission denied" in err or "auth" in err:
            return False, f"SSH authentication failed for {ssh_connect}. Set up passwordless auth."
        if "timed out" in err or "connection refused" in err:
            return False, f"Cannot connect to {ssh_connect}: {result.error}"
        return False, f"SSH error for {ssh_connect}: {result.error}"
    return True, "OK"


def resolve_ssh_connect(host: str, host_info: Optional[dict] = None) -> str:
    """Resolve the SSH connection string for a host.

    If host_info has an 'ssh_connect' field, use that.
    Otherwise, fall back to the host identifier itself.

    Args:
        host: Host identifier (hostname or IP).
        host_info: Host metadata dict from the registry.

    Returns:
        SSH connection string.
    """
    if host_info and "ssh_connect" in host_info:
        return host_info["ssh_connect"]
    return host


# ---------------------------------------------------------------------------
# SSH metric collection — produces Prometheus-compatible dicts
# ---------------------------------------------------------------------------

def collect_ssh_metrics(ssh_connect: str, allow_interactive: bool = False,
                              missing_tools: list | None = None) -> dict:
    """Collect metrics from a remote host via SSH.

    Runs traditional perf tools on the remote host and converts the output
    into the same Prometheus-compatible metric dict format used by
    parse_metrics() in analyzenode.py.

    Args:
        ssh_connect: SSH connection string.
        allow_interactive: Allow interactive SSH prompts.
        missing_tools: Optional list to append names of tools that were
            unavailable on the remote host. If provided, each collection
            function will append tool names (e.g., 'mpstat', 'iostat') when
            the remote command fails or is not found.

    Returns:
        Dict of metric_name -\u003e value or list of {labels, value} dicts,
        matching the format from parse_metrics().
    """
    metrics = {}
    if missing_tools is None:
        missing_tools = []

    # CPU metrics via mpstat
    _collect_ssh_cpu(ssh_connect, metrics, allow_interactive, missing_tools)

    # Memory metrics via /proc/meminfo
    _collect_ssh_memory(ssh_connect, metrics, allow_interactive, missing_tools)

    # Load averages via /proc/loadavg
    _collect_ssh_load(ssh_connect, metrics, allow_interactive, missing_tools)

    # Disk usage via df
    _collect_ssh_disk(ssh_connect, metrics, allow_interactive, missing_tools)

    # Disk I/O via iostat
    _collect_ssh_disk_io(ssh_connect, metrics, allow_interactive, missing_tools)

    # Network via /proc/net/dev
    _collect_ssh_network(ssh_connect, metrics, allow_interactive, missing_tools)

    # Context switches via /proc/stat
    _collect_ssh_context_switches(ssh_connect, metrics, allow_interactive, missing_tools)

    return metrics


def _parse_prometheus_label_value(value_str: str) -> float:
    """Parse a numeric value, returning 0.0 on failure."""
    try:
        return float(value_str)
    except (ValueError, TypeError):
        return 0.0


def _collect_ssh_cpu(ssh_connect: str, metrics: dict, allow_interactive: bool,
                     missing_tools: list):
    """Collect CPU metrics via mpstat on remote host."""
    result = ssh_run(ssh_connect, "mpstat 1 1", timeout=20, allow_interactive=allow_interactive)
    if result.error:
        missing_tools.append("mpstat")
        return

    total_idle = 0.0
    total_iowait = 0.0
    total_time = 0.0
    cpu_count = 0

    for line in result.stdout.strip().splitlines():
        if "Average" in line and "all" in line:
            # Average: all  CPU  ...  %idle  (last field)
            parts = line.split()
            try:
                idle_pct = float(parts[-1])
                iowait_pct = float(parts[-4]) if len(parts) >= 4 else 0.0
                # Store as approximate cumulative-style percentages
                metrics["node_cpu_idle_pct"] = idle_pct
                metrics["node_cpu_iowait_pct"] = iowait_pct
            except (ValueError, IndexError):
                pass
            break

    # Also get CPU count from nproc
    result_nproc = ssh_run(ssh_connect, "nproc", timeout=5, allow_interactive=allow_interactive)
    if not result_nproc.error and result_nproc.stdout.strip().isdigit():
        metrics["node_cpu_count"] = int(result_nproc.stdout.strip())

    # Build synthetic node_cpu_seconds_total for compatibility
    # Use mpstat percentages as approximate gauge
    result_detailed = ssh_run(ssh_connect, "mpstat -P ALL 1 1", timeout=20, allow_interactive=allow_interactive)
    if not result_detailed.error:
        cpu_entries = []
        for line in result_detailed.stdout.strip().splitlines():
            if "Average" in line and "all" not in line and "CPU" not in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        cpu_id = parts[1] if len(parts) > 2 else "0"
                        # We'll store approximate percentages as pseudo-metrics
                        idle_val = float(parts[-1])
                        iowait_val = float(parts[-4]) if len(parts) >= 8 else 0.0
                        cpu_entries.append({
                            "labels": {"cpu": cpu_id, "mode": "idle"},
                            "value": idle_val,
                        })
                        cpu_entries.append({
                            "labels": {"cpu": cpu_id, "mode": "iowait"},
                            "value": iowait_val,
                        })
                        cpu_entries.append({
                            "labels": {"cpu": cpu_id, "mode": "user"},
                            "value": float(parts[3]) if len(parts) > 3 else 0.0,
                        })
                    except (ValueError, IndexError):
                        pass
        if cpu_entries:
            metrics["node_cpu_seconds_total"] = cpu_entries


def _collect_ssh_memory(ssh_connect: str, metrics: dict, allow_interactive: bool,
                         missing_tools: list):
    """Collect memory metrics from /proc/meminfo on remote host."""
    result = ssh_run(ssh_connect, "cat /proc/meminfo", timeout=10, allow_interactive=allow_interactive)
    if result.error:
        return

    meminfo = {}
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0].rstrip(":")
            try:
                val_kb = int(parts[1])
                meminfo[key] = val_kb
            except ValueError:
                continue

    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)

    if total > 0:
        # Convert kB to bytes for Prometheus compatibility
        metrics["node_memory_MemTotal_bytes"] = float(total * 1024)
        metrics["node_memory_MemAvailable_bytes"] = float(available * 1024)


def _collect_ssh_load(ssh_connect: str, metrics: dict, allow_interactive: bool,
                      missing_tools: list):
    """Collect load averages from /proc/loadavg on remote host."""
    result = ssh_run(ssh_connect, "cat /proc/loadavg", timeout=5, allow_interactive=allow_interactive)
    if result.error:
        return

    parts = result.stdout.strip().split()
    if len(parts) >= 3:
        try:
            metrics["node_load1"] = float(parts[0])
            metrics["node_load5"] = float(parts[1])
            metrics["node_load15"] = float(parts[2])
        except (ValueError, IndexError):
            pass


def _collect_ssh_disk(ssh_connect: str, metrics: dict, allow_interactive: bool,
                      missing_tools: list):
    """Collect disk usage from df on remote host."""
    result = ssh_run(ssh_connect, "df -B1 --output=source,size,avail,pcent,target", timeout=10, allow_interactive=allow_interactive)
    if result.error:
        missing_tools.append("df")
        return

    size_entries = []
    avail_entries = []

    for line in result.stdout.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            device = parts[0]
            # Skip virtual/pseudo filesystems
            skip_prefixes = ("devtmpfs", "tmpfs", "overlay", "shm", "proc", "sys",
                              "cgroup", "efivarfs", "devpts", "mqueue", "fusectl",
                              "debugfs", "tracefs", "securityfs", "pstore", "bpf",
                              "binfmt_misc", "hugetlbfs", "configfs")
            if any(device.startswith(p) for p in skip_prefixes):
                continue
            if device == "none":
                continue
            if device.startswith("/dev/loop"):
                continue

            mountpoint = parts[4]
            try:
                size_bytes = float(parts[1])
                avail_bytes = float(parts[2])
                pct_str = parts[3].rstrip("%")

                size_entries.append({
                    "labels": {"mountpoint": mountpoint, "device": device},
                    "value": size_bytes,
                })
                avail_entries.append({
                    "labels": {"mountpoint": mountpoint, "device": device},
                    "value": avail_bytes,
                })
            except (ValueError, IndexError):
                continue

    if size_entries:
        metrics["node_filesystem_size_bytes"] = size_entries
    if avail_entries:
        metrics["node_filesystem_avail_bytes"] = avail_entries


def _collect_ssh_disk_io(ssh_connect: str, metrics: dict, allow_interactive: bool,
                          missing_tools: list):
    """Collect disk I/O metrics from iostat on remote host."""
    result = ssh_run(ssh_connect, "iostat -dx 1 1", timeout=20, allow_interactive=allow_interactive)
    if result.error:
        missing_tools.append("iostat")
        return

    io_entries = []
    in_device_section = False

    for line in result.stdout.strip().splitlines():
        if line.startswith("Device"):
            in_device_section = True
            continue
        if in_device_section and line.strip():
            parts = line.split()
            if len(parts) >= 14:
                device = parts[0]
                # Skip loop/ram devices
                if any(device.startswith(p) for p in ("loop", "ram", "zram")):
                    continue
                try:
                    util_pct = float(parts[-1])
                    # Store as a percentage-based metric
                    io_entries.append({
                        "labels": {"device": device},
                        "value": util_pct,
                    })
                except (ValueError, IndexError):
                    pass

    if io_entries:
        metrics["node_disk_io_util_pct"] = io_entries


def _collect_ssh_network(ssh_connect: str, metrics: dict, allow_interactive: bool,
                          missing_tools: list):
    """Collect network metrics from /proc/net/dev on remote host."""
    result = ssh_run(ssh_connect, "cat /proc/net/dev", timeout=10, allow_interactive=allow_interactive)
    if result.error:
        return

    rx_entries = []
    tx_entries = []

    for line in result.stdout.strip().splitlines()[2:]:
        parts = line.strip().split(":")
        if len(parts) == 2:
            iface = parts[0].strip()
            if iface == "lo":
                continue
            fields = parts[1].split()
            if len(fields) >= 11:
                try:
                    rx_bytes = float(fields[0])
                    tx_bytes = float(fields[8])
                    rx_errors = float(fields[2])
                    tx_errors = float(fields[10])

                    rx_entries.append({"labels": {"device": iface}, "value": rx_bytes})
                    tx_entries.append({"labels": {"device": iface}, "value": tx_bytes})
                except (ValueError, IndexError):
                    pass

    if rx_entries:
        metrics["node_network_receive_bytes_total"] = rx_entries
    if tx_entries:
        metrics["node_network_transmit_bytes_total"] = tx_entries


def _collect_ssh_context_switches(ssh_connect: str, metrics: dict, allow_interactive: bool,
                                  missing_tools: list):
    """Collect context switch count from /proc/stat on remote host."""
    result = ssh_run(ssh_connect, "grep ctxt /proc/stat", timeout=5, allow_interactive=allow_interactive)
    if result.error:
        return

    # Format: ctxt 123456789
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "ctxt":
            try:
                metrics["node_context_switches_total"] = float(parts[1])
            except (ValueError, IndexError):
                pass


# ---------------------------------------------------------------------------
# Remote tool availability check
# ---------------------------------------------------------------------------

# Tools that linuxdoctor recommendations may reference in action text.
# We check these on remote hosts so we can suggest installing them.
REMOTE_DIAGNOSTIC_TOOLS = [
    "mpstat", "sar", "iostat", "pidstat", "perf",
    "vmstat", "ss", "iotop", "blktrace",
    "ncdu", "ethtool", "smem",
    "pstree",
]


def check_remote_tools(ssh_connect: str, allow_interactive: bool = False) -> list[str]:
    """Check which diagnostic tools are unavailable on a remote host via SSH.

    Runs 'command -v <tool>' for each tool in REMOTE_DIAGNOSTIC_TOOLS over a
    single SSH connection to minimize round trips. Returns a list of tool
    names that were not found on the remote system.

    The PATH is expanded to include /usr/sbin and /sbin so that system
    tools (like ethtool, blktrace) installed outside the non-root user's
    default PATH are still found.

    Args:
        ssh_connect: SSH connection string (e.g. 'user@host').
        allow_interactive: Allow interactive SSH prompts.

    Returns:
        List of tool names that are NOT available on the remote host.
    """
    # Expand PATH to include sbin directories so tools like ethtool, blktrace
    # (typically in /usr/sbin or /sbin) are found even for non-root SSH users.
    # Also map alternate binary names: some distros install iotop as iotop-py.
    path_prefix = 'PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH'

    # Build check commands: try the canonical name, then any known aliases
    tool_aliases = {
        "iotop": ["iotop", "iotop-py"],
    }

    check_cmds = []
    for t in REMOTE_DIAGNOSTIC_TOOLS:
        aliases = tool_aliases.get(t, [t])
        # Tool is "found" if ANY of its aliases exist
        alias_checks = " || ".join(f"command -v {a} >/dev/null 2>&1" for a in aliases)
        check_cmds.append(f"( {alias_checks} ) || echo MISSING:{t}")

    compound_cmd = path_prefix + "; " + "; ".join(check_cmds)

    result = ssh_run(ssh_connect, compound_cmd, timeout=15, allow_interactive=allow_interactive)
    if result.error:
        # SSH connection issue — can't determine tool availability
        return []

    missing = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line.startswith("MISSING:"):
            tool_name = line[len("MISSING:"):]
            missing.append(tool_name)

    return missing