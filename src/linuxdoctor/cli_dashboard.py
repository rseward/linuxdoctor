"""CLI dashboard for linuxdoctor.

Provides a one-shot health check table for all registered hosts,
analogous to the web dashboard but rendered in the terminal.

By default it scans each host once and prints a summary table,
then exits. Use --resample to take two samples (spaced by
--resample-interval seconds) for more accurate counter-metric rates.

Use --json for machine-readable output. A tqdm progress bar is shown
during scanning unless --json is specified.
"""

import json
import sys
import time
from dataclasses import asdict
from datetime import datetime
from typing import Optional

import click

from linuxdoctor.host_registry import load_registry, DEFAULT_REGISTRY_PATH
from linuxdoctor.web import (
    HostHealth,
    HealthStore,
    scan_host,
    scan_ssh_host,
)


# ---------------------------------------------------------------------------
# Health icon mapping (terminal-friendly)
# ---------------------------------------------------------------------------

_HEALTH_ICONS = {
    "healthy": "✅",
    "warning": "⚠️ ",
    "critical": "🔴",
    "unknown": "❓",
}

_HEALTH_TEXT = {
    "healthy": "OK",
    "warning": "WARN",
    "critical": "CRIT",
    "unknown": "?",
}


def _health_icon(status: str) -> str:
    """Return a compact terminal icon for a health status."""
    return _HEALTH_ICONS.get(status, "❓")


def _health_text(status: str) -> str:
    """Return a short text label for a health status."""
    return _HEALTH_TEXT.get(status, "??")


# ---------------------------------------------------------------------------
# Scanning logic
# ---------------------------------------------------------------------------

def scan_hosts_for_dashboard(
    hosts: list[str],
    port: int = 9100,
    threshold_profile: str = "default",
    registry_path: str = DEFAULT_REGISTRY_PATH,
    resample: bool = False,
    resample_interval: int = 30,
    json_output: bool = False,
) -> list[HostHealth]:
    """Scan all specified hosts and return health summaries.

    Args:
        hosts: List of host names/IPs to scan.
        port: Node exporter port.
        threshold_profile: Threshold profile name.
        registry_path: Path to the host registry.
        resample: If True, take two samples per host.
        resample_interval: Seconds between samples when resampling.
        json_output: If True, suppress progress bar.

    Returns:
        List of HostHealth objects.
    """
    results: list[HostHealth] = []

    # Show progress bar unless JSON output
    show_progress = not json_output and len(hosts) > 0

    if show_progress:
        try:
            from tqdm import tqdm
            iterator = tqdm(hosts, desc="Scanning hosts", unit="host")
        except ImportError:
            iterator = hosts
    else:
        iterator = hosts

    for host in iterator:
        if resample:
            # First sample
            health = scan_host(
                host, port=port, threshold_profile=threshold_profile,
                registry_path=registry_path,
            )

            if not health.reachable:
                results.append(health)
                continue

            # Wait between samples
            time.sleep(resample_interval)

            # Second sample
            health2 = scan_host(
                host, port=port, threshold_profile=threshold_profile,
                registry_path=registry_path,
            )
            # Use the second sample's data (which benefits from rate computation)
            results.append(health2)
        else:
            health = scan_host(
                host, port=port, threshold_profile=threshold_profile,
                registry_path=registry_path,
            )
            results.append(health)

    return results


# ---------------------------------------------------------------------------
# Table rendering
# ---------------------------------------------------------------------------

def _render_table(results: list[HostHealth]) -> str:
    """Render health results as a terminal table.

    Columns: Host | CPU | Context | I/O Wait | Disk | Status
    """
    if not results:
        return "No hosts to scan. Register hosts with: linuxdoctor registerhost HOST"

    # Column widths
    host_w = max(len(r.host) for r in results)
    host_w = max(host_w, 8)  # minimum width for "Host" header

    # SSH badge width
    for r in results:
        if r.collection_method == "ssh" and r.ssh_connect and r.ssh_connect != r.host:
            host_w = max(host_w, len(r.host) + len(r.ssh_connect) + 6)

    col_w = 8  # width for health columns
    status_w = 12

    # Header
    sep = "+" + "-" * (host_w + 2) + "+" + "-" * (col_w + 2) + "+" + \
          "-" * (col_w + 2) + "+" + "-" * (col_w + 2) + "+" + \
          "-" * (col_w + 2) + "+" + "-" * (status_w + 2) + "+"

    header = "| {:<{hw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{sw}} |".format(
        "Host", "CPU", "Context", "I/O Wait", "Disk", "Status",
        hw=host_w, cw=col_w, sw=status_w,
    )

    lines = [
        "",
        "🩺 Linux Doctor CLI Dashboard",
        f"📊 Scanned {len(results)} host(s) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        sep,
        header,
        sep,
    ]

    for r in results:
        if r.reachable:
            status_str = "UP"
        else:
            status_str = "DOWN"

        # Host column: show SSH badge if applicable
        if r.collection_method == "ssh":
            host_display = f"{r.host} [SSH]"
        else:
            host_display = r.host

        # Health columns
        cpu = _health_text(r.cpu_health)
        ctx = _health_text(r.context_health)
        io = _health_text(r.io_wait_health)
        disk = _health_text(r.disk_health)

        row = "| {:<{hw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{sw}} |".format(
            host_display, cpu, ctx, io, disk, status_str,
            hw=host_w, cw=col_w, sw=status_w,
        )
        lines.append(row)

        # If host is unreachable, show error on next line
        if not r.reachable and r.error:
            err_line = f"|   └─ {r.error}"
            # Pad to table width
            total_w = host_w + 4 * (col_w + 3) + status_w + 3
            if len(err_line) < total_w:
                err_line += " " * (total_w - len(err_line))
            err_line += "|"
            lines.append(err_line)

    lines.append(sep)

    # Summary
    healthy = sum(1 for r in results if r.reachable and
                  all(getattr(r, f"{c}_health", "unknown") != "critical"
                      for c in ("cpu", "context", "io_wait", "disk")))
    critical = sum(1 for r in results if r.reachable and
                   any(getattr(r, f"{c}_health") == "critical"
                       for c in ("cpu", "context", "io_wait", "disk")))
    warning = sum(1 for r in results if r.reachable and critical == 0 and
                 any(getattr(r, f"{c}_health") == "warning"
                     for c in ("cpu", "context", "io_wait", "disk")))
    unreachable = sum(1 for r in results if not r.reachable)

    lines.append("")
    if critical:
        lines.append(f"🔴 {critical} host(s) with CRITICAL issues")
    elif warning:
        lines.append(f"⚠️  {warning} host(s) with warnings")
    elif unreachable == len(results):
        lines.append(f"❌ All {unreachable} host(s) unreachable")
    elif healthy:
        lines.append(f"✅ All {healthy} host(s) look healthy")

    if unreachable and unreachable < len(results):
        lines.append(f"❌ {unreachable} host(s) unreachable")

    # Detail section: show issues for each host with warnings/critical
    has_issues = False
    for r in results:
        if not r.reachable:
            continue
        issues = []
        for cat, attr in [("CPU", "cpu_health"), ("Context", "context_health"),
                          ("I/O Wait", "io_wait_health"), ("Disk", "disk_health")]:
            status = getattr(r, attr, "unknown")
            if status in ("warning", "critical"):
                detail = getattr(r, f"{attr.replace('_health', '_detail')}", "")
                suggestion = getattr(r, f"{attr.replace('_health', '_suggestion')}", "")
                issues.append((cat, status, detail, suggestion))

        if issues:
            if not has_issues:
                lines.append("")
                lines.append("=" * 60)
                lines.append("ISSUE DETAILS")
                lines.append("=" * 60)
                has_issues = True

            lines.append(f"  {r.host}:")
            for cat, status, detail, suggestion in issues:
                icon = "🔴" if status == "critical" else "⚠️ "
                lines.append(f"    {icon} {cat}: {detail}")
                if suggestion:
                    lines.append(f"       → {suggestion}")

    lines.append("")
    return "\n".join(lines)


def _render_json(results: list[HostHealth]) -> str:
    """Render health results as JSON."""
    data = {
        "timestamp": datetime.now().isoformat(),
        "hosts": {},
    }
    for r in results:
        data["hosts"][r.host] = asdict(r)
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

def dashboard_command(
    json_output: bool = False,
    resample: bool = False,
    resample_interval: Optional[int] = None,
    threshold: str = "default",
    port: int = 9100,
    registry_path: Optional[str] = None,
):
    """Run the CLI dashboard — scan all registered hosts and print a health table."""
    from linuxdoctor.host_registry import DEFAULT_REGISTRY_PATH as _default_path

    reg_path = registry_path or _default_path

    # Load registered hosts
    registry = load_registry(reg_path)
    if not registry:
        click.echo("No registered hosts found.")
        click.echo(f"Registry: {reg_path}")
        click.echo("Register hosts with: linuxdoctor registerhost HOST --cpu-cores N")
        sys.exit(1)

    hosts = list(registry.keys())

    interval = resample_interval or 30

    # Scan all hosts
    results = scan_hosts_for_dashboard(
        hosts=hosts,
        port=port,
        threshold_profile=threshold,
        registry_path=reg_path,
        resample=resample,
        resample_interval=interval,
        json_output=json_output,
    )

    # Render output
    if json_output:
        click.echo(_render_json(results))
    else:
        click.echo(_render_table(results))

    # Exit with non-zero if any critical issues found
    has_critical = any(
        any(getattr(r, f"{c}_health") == "critical"
            for c in ("cpu", "context", "io_wait", "disk"))
        for r in results if r.reachable
    )
    if has_critical:
        sys.exit(1)