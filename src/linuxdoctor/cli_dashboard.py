"""CLI dashboard for linuxdoctor.

Provides a one-shot health check table for all registered hosts,
analogous to the web dashboard but rendered in the terminal.

By default it scans each host once and prints a summary table,
then exits. Use --resample to take two samples (spaced by
--resample-interval seconds) for more accurate counter-metric rates.

Use --json for machine-readable output. A tqdm progress bar is shown
during scanning unless --json is specified.

Terminal colors are enabled by default. Use --no-color to disable
ANSI color output (e.g. when piping to a file or on terminals
without color support).
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

# ---------------------------------------------------------------------------
# ANSI color codes for terminal output
# ---------------------------------------------------------------------------

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_GRAY = "\033[90m"
ANSI_BOLD_GREEN = "\033[1;32m"
ANSI_BOLD_YELLOW = "\033[1;33m"
ANSI_BOLD_RED = "\033[1;31m"

# Map health status to ANSI color
_HEALTH_COLOR = {
    "healthy": ANSI_GREEN,
    "warning": ANSI_YELLOW,
    "critical": ANSI_RED,
    "unknown": ANSI_GRAY,
}

# Map overall status (UP/DOWN) to ANSI color
_STATUS_COLOR = {
    "UP": ANSI_BOLD_GREEN,
    "DOWN": ANSI_BOLD_RED,
}


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


def _colorize(text: str, color_code: str, use_color: bool = True) -> str:
    """Wrap text in ANSI color codes if use_color is True."""
    if not use_color:
        return text
    return f"{color_code}{text}{ANSI_RESET}"


def _colorize_health(status_text: str, health_status: str, use_color: bool = True) -> str:
    """Colorize a health text label based on its status.

    Args:
        status_text: The text to colorize (e.g. 'OK', 'WARN', 'CRIT').
        health_status: The health status key ('healthy', 'warning', 'critical', 'unknown').
        use_color: If False, return text without ANSI codes.
    """
    color = _HEALTH_COLOR.get(health_status)
    if color and use_color:
        return f"{color}{status_text}{ANSI_RESET}"
    return status_text


def _colorize_status(status_text: str, use_color: bool = True) -> str:
    """Colorize an overall status (UP/DOWN)."""
    color = _STATUS_COLOR.get(status_text)
    if color and use_color:
        return f"{color}{status_text}{ANSI_RESET}"
    return status_text


def _center_col(colored_text: str, visible_width: int, col_width: int) -> str:
    """Center-align a string that may contain ANSI escape codes.

    Args:
        colored_text: The text (possibly with ANSI codes) to center.
        visible_width: The number of visible (non-ANSI) characters.
        col_width: The total column width to center within.

    Returns:
        The centered string, padded with spaces on left and right.
    """
    total_pad = col_width - visible_width
    left_pad = total_pad // 2
    right_pad = total_pad - left_pad
    return f"{' ' * left_pad}{colored_text}{' ' * right_pad}"


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

def _render_table(results: list[HostHealth], use_color: bool = True) -> str:
    """Render health results as a terminal table.

    Columns: Host | CPU | Context | I/O Wait | Disk | SMART | Status

    Args:
        results: List of HostHealth objects to render.
        use_color: If True, apply ANSI color codes to status text.
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
    smart_w = 8  # SMART column
    status_w = 12

    # Header
    sep = "+" + "-" * (host_w + 2) + "+" + "-" * (col_w + 2) + "+" + \
          "-" * (col_w + 2) + "+" + "-" * (col_w + 2) + "+" + \
          "-" * (col_w + 2) + "+" + "-" * (smart_w + 2) + "+" + "-" * (status_w + 2) + "+"

    header = "| {:<{hw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{sw}} | {:^{stw}} |".format(
        "Host", "CPU", "Context", "I/O Wait", "Disk", "SMART", "Status",
        hw=host_w, cw=col_w, sw=smart_w, stw=status_w,
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
            status_str = _colorize_status("UP", use_color)
        else:
            status_str = _colorize_status("DOWN", use_color)

        # Host column: show SSH badge if applicable
        if r.collection_method == "ssh":
            host_display = f"{r.host} [SSH]"
        else:
            host_display = r.host

        # Health columns — colorize based on status
        cpu = _colorize_health(_health_text(r.cpu_health), r.cpu_health, use_color)
        ctx = _colorize_health(_health_text(r.context_health), r.context_health, use_color)
        io = _colorize_health(_health_text(r.io_wait_health), r.io_wait_health, use_color)
        disk = _colorize_health(_health_text(r.disk_health), r.disk_health, use_color)
        smart = _colorize_health(_health_text(r.smart_health), r.smart_health, use_color)

        # Note: When color is active, ANSI codes make strings wider than
        # visible chars, so we format using the plain (uncolored) widths
        # for column alignment. We use the plain text for width calculation
        # and build the row manually to preserve alignment.
        if use_color:
            # Build row with colored values — pad based on visible width
            cpu_plain = _health_text(r.cpu_health)
            ctx_plain = _health_text(r.context_health)
            io_plain = _health_text(r.io_wait_health)
            disk_plain = _health_text(r.disk_health)
            smart_plain = _health_text(r.smart_health)
            status_plain = "UP" if r.reachable else "DOWN"

            host_pad = host_w
            # Calculate visible widths for centering
            cpu_vis = len(cpu_plain)
            ctx_vis = len(ctx_plain)
            io_vis = len(io_plain)
            disk_vis = len(disk_plain)
            smart_vis = len(smart_plain)
            status_vis = len(status_plain)

            # Build left-aligned host col
            host_col = f"{host_display:<{host_pad}}"
            # Build center-aligned cols
            cpu_col = _center_col(cpu, cpu_vis, col_w)
            ctx_col = _center_col(ctx, ctx_vis, col_w)
            io_col = _center_col(io, io_vis, col_w)
            disk_col = _center_col(disk, disk_vis, col_w)
            smart_col = _center_col(smart, smart_vis, smart_w)
            status_col = _center_col(status_str, status_vis, status_w)

            row = f"| {host_col} | {cpu_col} | {ctx_col} | {io_col} | {disk_col} | {smart_col} | {status_col} |"
        else:
            row = "| {:<{hw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{cw}} | {:^{sw}} | {:^{stw}} |".format(
                host_display, _health_text(r.cpu_health), _health_text(r.context_health),
                _health_text(r.io_wait_health), _health_text(r.disk_health),
                _health_text(r.smart_health),
                "UP" if r.reachable else "DOWN",
                hw=host_w, cw=col_w, sw=smart_w, stw=status_w,
            )

        lines.append(row)

        # If host is unreachable, show error on next line
        if not r.reachable and r.error:
            err_msg = _colorize(r.error, ANSI_RED, use_color) if use_color else r.error
            err_line = f"|   └─ {err_msg}"
            # Pad to table width
            total_w = host_w + 4 * (col_w + 3) + (smart_w + 3) + status_w + 3
            # Calculate visible length (without ANSI codes) for padding
            visible_len = len(f"|   └─ {r.error}")
            if visible_len < total_w:
                err_line += " " * (total_w - visible_len)
            err_line += "|"
            lines.append(err_line)

    lines.append(sep)

    # Summary
    healthy = sum(1 for r in results if r.reachable and
                  all(getattr(r, f"{c}_health", "unknown") != "critical"
                      for c in ("cpu", "context", "io_wait", "disk", "smart")))
    critical = sum(1 for r in results if r.reachable and
                   any(getattr(r, f"{c}_health") == "critical"
                       for c in ("cpu", "context", "io_wait", "disk", "smart")))
    warning = sum(1 for r in results if r.reachable and critical == 0 and
                 any(getattr(r, f"{c}_health") == "warning"
                     for c in ("cpu", "context", "io_wait", "disk", "smart")))
    unreachable = sum(1 for r in results if not r.reachable)

    lines.append("")
    if critical:
        lines.append(_colorize(f"🔴 {critical} host(s) with CRITICAL issues", ANSI_RED, use_color))
    elif warning:
        lines.append(_colorize(f"⚠️  {warning} host(s) with warnings", ANSI_YELLOW, use_color))
    elif unreachable == len(results):
        lines.append(_colorize(f"❌ All {unreachable} host(s) unreachable", ANSI_RED, use_color))
    elif healthy:
        lines.append(_colorize(f"✅ All {healthy} host(s) look healthy", ANSI_GREEN, use_color))

    if unreachable and unreachable < len(results):
        lines.append(_colorize(f"❌ {unreachable} host(s) unreachable", ANSI_RED, use_color))

    # Detail section: show issues for each host with warnings/critical
    has_issues = False
    for r in results:
        if not r.reachable:
            continue
        issues = []
        for cat, attr in [("CPU", "cpu_health"), ("Context", "context_health"),
                          ("I/O Wait", "io_wait_health"), ("Disk", "disk_health"),
                          ("SMART", "smart_health")]:
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
                if use_color:
                    if status == "critical":
                        icon = _colorize("🔴", ANSI_RED, use_color)
                        label = _colorize(f"{cat}: {detail}", ANSI_RED, use_color)
                    else:
                        icon = _colorize("⚠️ ", ANSI_YELLOW, use_color)
                        label = _colorize(f"{cat}: {detail}", ANSI_YELLOW, use_color)
                else:
                    icon = "🔴" if status == "critical" else "⚠️ "
                    label = f"{cat}: {detail}"
                lines.append(f"    {icon} {label}")
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
    use_color: bool = True,
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
        click.echo(_render_table(results, use_color=use_color), color=use_color)

    # Exit with non-zero if any critical issues found
    has_critical = any(
        any(getattr(r, f"{c}_health") == "critical"
            for c in ("cpu", "context", "io_wait", "disk", "smart"))
        for r in results if r.reachable
    )
    if has_critical:
        sys.exit(1)