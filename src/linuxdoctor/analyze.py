"""Analyze the current host using local performance tools.

Gathers metrics from sar, vmstat, iostat, mpstat, and other standard
Linux performance tools, then generates recommendations for improving
system health (analogous to node_exporter recommendations).
"""

import json
import platform
import sys
from datetime import datetime

from linuxdoctor.collectors import collect_all, MetricCollection
from linuxdoctor.recommendations import generate_recommendations, Recommendation


def _format_table(rows: list[list[str]], headers: list[str]) -> str:
    """Simple table formatter."""
    if not rows:
        return ""

    # Calculate column widths
    all_rows = [headers] + rows
    widths = [max(len(str(row[i])) for row in all_rows) for i in range(len(headers))]

    lines = []
    # Header
    header_line = "  ".join(str(headers[i]).ljust(widths[i]) for i in range(len(headers)))
    lines.append(header_line)
    lines.append("-" * len(header_line))

    # Rows
    for row in rows:
        line = "  ".join(str(row[i]).ljust(widths[i]) for i in range(len(row)))
        lines.append(line)

    return "\n".join(lines)


def _severity_icon(severity: str) -> str:
    """Return an icon for severity level."""
    return {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(severity, "⚪")


def _format_human(collections: list[MetricCollection], recommendations: list[Recommendation]) -> str:
    """Format results for human-readable output."""
    lines = []
    lines.append("=" * 72)
    lines.append(f"  linuxdoctor — Host Analysis Report")
    lines.append(f"  {platform.node()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  {platform.system()} {platform.release()} ({platform.machine()})")
    lines.append("=" * 72)
    lines.append("")

    # Metrics by category
    for coll in collections:
        if coll.error:
            lines.append(f"  ⚠ {coll.category.upper()} — Collection Error: {coll.error}")
            lines.append("")
            continue

        valid_metrics = [m for m in coll.metrics if m.error is None and m.value is not None]
        if not valid_metrics:
            continue

        lines.append(f"  {coll.category.upper()}")
        lines.append("  " + "-" * 40)

        for m in valid_metrics:
            unit_str = f" {m.unit}" if m.unit else ""
            source_str = f" ({m.source})" if m.source else ""
            lines.append(f"    {m.name:<35} {m.value}{unit_str}{source_str}")
        lines.append("")

    # Recommendations
    if recommendations:
        lines.append("=" * 72)
        lines.append("  RECOMMENDATIONS")
        lines.append("=" * 72)
        lines.append("")

        crit_count = sum(1 for r in recommendations if r.severity == "critical")
        warn_count = sum(1 for r in recommendations if r.severity == "warning")
        info_count = sum(1 for r in recommendations if r.severity == "info")

        lines.append(f"  Critical: {crit_count} | Warning: {warn_count} | Info: {info_count}")
        lines.append("")

        for rec in recommendations:
            icon = _severity_icon(rec.severity)
            lines.append(f"  {icon} [{rec.severity.upper()}] {rec.category}: {rec.message}")
            if rec.detail:
                lines.append(f"     {rec.detail}")
            if rec.action:
                lines.append(f"     → {rec.action}")
            lines.append("")
    else:
        lines.append("  ✅ No recommendations — system health looks good!")
        lines.append("")

    lines.append("=" * 72)
    return "\n".join(lines)


def _format_json(collections: list[MetricCollection], recommendations: list[Recommendation]) -> str:
    """Format results as JSON."""
    output = {
        "host": platform.node(),
        "timestamp": datetime.now().isoformat(),
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "metrics": {},
        "recommendations": [],
    }

    for coll in collections:
        metrics_dict = {}
        for m in coll.metrics:
            if m.error is not None:
                metrics_dict[m.name] = {"error": m.error, "value": None}
            else:
                entry = {"value": m.value}
                if m.unit:
                    entry["unit"] = m.unit
                if m.source:
                    entry["source"] = m.source
                metrics_dict[m.name] = entry
        output["metrics"][coll.category] = {
            "metrics": metrics_dict,
        }
        if coll.error:
            output["metrics"][coll.category]["error"] = coll.error

    for rec in recommendations:
        output["recommendations"].append({
            "severity": rec.severity,
            "category": rec.category,
            "metric": rec.metric,
            "message": rec.message,
            "detail": rec.detail,
            "action": rec.action,
        })

    return json.dumps(output, indent=2)


def analyze_host(
    json_output: bool = False,
    include_recommendations: bool = True,
    checks: list[str] | None = None,
    threshold_profile: str = "default",
) -> str:
    """Analyze the current host and return a formatted report.

    Args:
        json_output: If True, output JSON instead of human-readable format.
        include_recommendations: If True, generate recommendations from metrics.
        checks: List of specific check categories to run (cpu, memory, disk, io, network, load, sar).
        threshold_profile: Threshold profile for recommendations (default, strict, relaxed).

    Returns:
        Formatted string with analysis results.
    """
    # Collect metrics
    collections = collect_all(checks)

    # Generate recommendations
    recommendations = []
    if include_recommendations:
        recommendations = generate_recommendations(collections, threshold_profile)

    # Format output
    if json_output:
        return _format_json(collections, recommendations)
    else:
        return _format_human(collections, recommendations)