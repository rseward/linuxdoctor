"""Web dashboard for linuxdoctor.

Provides a simple, zero-config web dashboard that periodically analyzes
registered hosts and presents a dynamically refreshing health table.

Default: http://0.0.0.0:7193
"""

import json
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
import urllib.parse

from linuxdoctor.host_registry import load_registry, DEFAULT_REGISTRY_PATH
from linuxdoctor.analyzenode import (
    fetch_metrics_text,
    parse_metrics,
    analyze_cpu,
    analyze_memory,
    analyze_disk,
    analyze_disk_io,
    analyze_network,
    analyze_context_switching,
    _get_thresholds,
    AnalysisResult,
    Recommendation,
)
from linuxdoctor.ssh_collector import (
    collect_ssh_metrics,
    resolve_ssh_connect,
    ssh_test_connection,
)


# ---------------------------------------------------------------------------
# Health store — in-memory JSON store of per-host analysis results
# ---------------------------------------------------------------------------

@dataclass
class HostHealth:
    """Health summary for a single host."""
    host: str
    timestamp: str = ""
    reachable: bool = False
    error: str = ""
    # How metrics are collected: "node_exporter" or "ssh"
    collection_method: str = "node_exporter"
    # SSH connection string (if collection_method is "ssh")
    ssh_connect: str = ""
    # Category health: "healthy", "warning", "critical", "unknown"
    cpu_health: str = "unknown"
    cpu_detail: str = ""
    cpu_suggestion: str = ""
    context_health: str = "unknown"
    context_detail: str = ""
    context_suggestion: str = ""
    io_wait_health: str = "unknown"
    io_wait_detail: str = ""
    io_wait_suggestion: str = ""
    disk_health: str = "unknown"
    disk_detail: str = ""
    disk_suggestion: str = ""
    # Full analysis JSON for modal view
    full_analysis: dict = field(default_factory=dict)


class HealthStore:
    """Thread-safe in-memory store for host health data."""

    def __init__(self):
        self._data: dict[str, HostHealth] = {}
        self._lock = threading.Lock()

    def update(self, host: str, health: HostHealth):
        with self._lock:
            self._data[host] = health

    def get(self, host: str) -> Optional[HostHealth]:
        with self._lock:
            return self._data.get(host)

    def get_all(self) -> dict[str, HostHealth]:
        with self._lock:
            return dict(self._data)

    def to_json(self) -> str:
        with self._lock:
            return json.dumps(
                {h: asdict(v) for h, v in self._data.items()}, indent=2
            )


# Global store
store = HealthStore()


# ---------------------------------------------------------------------------
# Host scanner — periodically connects to hosts and runs analysis
# ---------------------------------------------------------------------------

def _worst_severity(results: list[AnalysisResult], category: str) -> str:
    """Determine worst severity for a category from analysis results.

    Returns "healthy", "warning", "critical", or "unknown".
    """
    found_category = False
    worst = None
    for r in results:
        if r.category != category:
            continue
        found_category = True
        for rec in r.recommendations:
            if rec.severity == "critical":
                return "critical"
            if rec.severity == "warning" and worst != "critical":
                worst = "warning"
            if rec.severity == "info" and worst is None:
                worst = "info"

    if worst == "warning":
        return "warning"
    if found_category:
        return "healthy"
    return "unknown"


def _category_detail(results: list[AnalysisResult], category: str) -> tuple[str, str]:
    """Extract detail message and suggestion for a category.

    Returns (detail, suggestion). Prefers the most severe recommendation.
    """
    best = None
    severity_rank = {"critical": 0, "warning": 1, "info": 2}
    for r in results:
        if r.category != category:
            continue
        for rec in r.recommendations:
            if best is None or severity_rank.get(rec.severity, 3) < severity_rank.get(best.severity, 3):
                best = rec
    if best and best.message:
        return (best.message, best.action or "")
    return ("", "")


def scan_host(host: str, port: int = 9100, threshold_profile: str = "default",
               registry_path: str = DEFAULT_REGISTRY_PATH) -> HostHealth:
    """Scan a single host and return its health summary.

    Automatically detects whether to use node_exporter or SSH for metric
    collection based on the host registry entry.
    """
    host_info = None
    try:
        from linuxdoctor.host_registry import get_host_info
        host_info = get_host_info(host, path=registry_path)
    except Exception:
        pass

    # Determine collection method
    if host_info and "ssh_connect" in host_info:
        return scan_ssh_host(host, threshold_profile=threshold_profile,
                             host_info=host_info)

    # --- node_exporter path ---
    health = HostHealth(host=host, timestamp=datetime.now().isoformat(),
                        collection_method="node_exporter")
    thresholds = _get_thresholds(threshold_profile)

    try:
        metrics_text = fetch_metrics_text(host, port)
        metrics = parse_metrics(metrics_text)
    except RuntimeError as e:
        health.reachable = False
        health.error = str(e)
        return health

    health.reachable = True

    # Determine CPU cores from metrics or registry
    cpu_cores = None
    if host_info:
        cpu_cores = host_info.get("cpu_cores")
    if cpu_cores is None:
        cpu_seconds = metrics.get("node_cpu_seconds_total", [])
        if cpu_seconds:
            cpu_cores = len(set(
                e["labels"]["cpu"] for e in cpu_seconds if "cpu" in e["labels"]
            ))

    # Run analysis functions
    results = [
        analyze_cpu(metrics, thresholds),
        analyze_memory(metrics, thresholds),
        analyze_disk(metrics, thresholds),
        analyze_disk_io(metrics, thresholds),
        analyze_network(metrics, thresholds),
        analyze_context_switching(
            metrics, thresholds,
            cpu_cores=cpu_cores,
            node_address=host,
        ),
    ]

    # Build health indicators
    health.cpu_health = _worst_severity(results, "cpu")
    health.cpu_detail, health.cpu_suggestion = _category_detail(results, "cpu")

    health.context_health = _worst_severity(results, "context_switching")
    health.context_detail, health.context_suggestion = _category_detail(results, "context_switching")

    health.io_wait_health = _worst_severity(results, "disk_io")
    health.io_wait_detail, health.io_wait_suggestion = _category_detail(results, "disk_io")

    health.disk_health = _worst_severity(results, "disk")
    health.disk_detail, health.disk_suggestion = _category_detail(results, "disk")

    # Build full analysis dict for modal
    all_recs = []
    for r in results:
        all_recs.extend(r.recommendations)
        r.recommendations = []

    health.full_analysis = {
        "host": host,
        "timestamp": health.timestamp,
        "collection_method": "node_exporter",
        "categories": {},
    }

    for r in results:
        cat_data = {
            "lines": r.lines,
            "recommendations": [],
        }
        for rec in all_recs:
            if rec.category == r.category:
                cat_data["recommendations"].append({
                    "severity": rec.severity,
                    "category": rec.category,
                    "message": rec.message,
                    "detail": rec.detail,
                    "action": rec.action,
                })
        health.full_analysis["categories"][r.category] = cat_data

    return health


def scan_ssh_host(host: str, threshold_profile: str = "default",
                  host_info: dict = None) -> HostHealth:
    """Scan an SSH host and return its health summary.

    Uses the SSH collector to gather metrics via traditional perf tools.
    From the web dashboard, BatchMode=yes is used (no interactive auth),
    so hosts requiring host key acceptance or passwords are marked unreachable.
    """
    ssh_connect = resolve_ssh_connect(host, host_info)
    cpu_cores = host_info.get("cpu_cores") if host_info else None

    health = HostHealth(
        host=host,
        timestamp=datetime.now().isoformat(),
        collection_method="ssh",
        ssh_connect=ssh_connect,
    )
    thresholds = _get_thresholds(threshold_profile)

    # Test SSH connectivity (BatchMode — no interactive auth from dashboard)
    reachable, message = ssh_test_connection(ssh_connect, allow_interactive=False)
    if not reachable:
        health.reachable = False
        # Provide a user-friendly error distinguishing common SSH issues
        err_lower = message.lower()
        if "host key" in err_lower:
            health.error = f"SSH host key not accepted for {ssh_connect}. Run: ssh {ssh_connect} to accept the key first."
        elif "permission denied" in err_lower or "auth" in err_lower:
            health.error = f"SSH auth failed for {ssh_connect}. Set up passwordless key-based auth."
        else:
            health.error = message
        return health

    health.reachable = True

    # Collect metrics via SSH
    try:
        metrics = collect_ssh_metrics(ssh_connect, allow_interactive=False)
    except Exception as e:
        health.reachable = False
        health.error = f"SSH metric collection error: {e}"
        return health

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

    # Run analysis functions
    results = [
        analyze_cpu(metrics, thresholds),
        analyze_memory(metrics, thresholds),
        analyze_disk(metrics, thresholds),
        analyze_disk_io(metrics, thresholds),
        analyze_network(metrics, thresholds),
        analyze_context_switching(
            metrics, thresholds,
            cpu_cores=cpu_cores,
            node_address=host,
        ),
    ]

    # Build health indicators
    health.cpu_health = _worst_severity(results, "cpu")
    health.cpu_detail, health.cpu_suggestion = _category_detail(results, "cpu")

    health.context_health = _worst_severity(results, "context_switching")
    health.context_detail, health.context_suggestion = _category_detail(results, "context_switching")

    health.io_wait_health = _worst_severity(results, "disk_io")
    health.io_wait_detail, health.io_wait_suggestion = _category_detail(results, "disk_io")

    health.disk_health = _worst_severity(results, "disk")
    health.disk_detail, health.disk_suggestion = _category_detail(results, "disk")

    # Build full analysis dict for modal
    all_recs = []
    for r in results:
        all_recs.extend(r.recommendations)
        r.recommendations = []

    health.full_analysis = {
        "host": host,
        "timestamp": health.timestamp,
        "collection_method": "ssh",
        "ssh_connect": ssh_connect,
        "categories": {},
    }

    for r in results:
        cat_data = {
            "lines": r.lines,
            "recommendations": [],
        }
        for rec in all_recs:
            if rec.category == r.category:
                cat_data["recommendations"].append({
                    "severity": rec.severity,
                    "category": rec.category,
                    "message": rec.message,
                    "detail": rec.detail,
                    "action": rec.action,
                })
        health.full_analysis["categories"][r.category] = cat_data

    return health


def scan_all_hosts(registry_path: str = DEFAULT_REGISTRY_PATH, port: int = 9100,
                   threshold_profile: str = "default"):
    """Scan all registered hosts and update the store."""
    registry = load_registry(registry_path)
    if not registry:
        return

    for host in registry:
        try:
            health = scan_host(host, port=port, threshold_profile=threshold_profile,
                               registry_path=registry_path)
            store.update(host, health)
        except Exception as e:
            err_health = HostHealth(
                host=host,
                timestamp=datetime.now().isoformat(),
                reachable=False,
                error=str(e),
            )
            store.update(host, err_health)


def scanner_loop(interval: int, registry_path: str, port: int, threshold_profile: str,
                 stop_event: threading.Event):
    """Background thread that periodically scans all hosts."""
    while not stop_event.is_set():
        scan_all_hosts(registry_path, port=port, threshold_profile=threshold_profile)
        stop_event.wait(timeout=interval)


# ---------------------------------------------------------------------------
# HTTP Dashboard Server
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Linux Doctor Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    min-height: 100vh;
  }
  header {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 16px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  header h1 {
    font-size: 20px;
    font-weight: 600;
    color: #58a6ff;
  }
  header .logo { font-size: 24px; }
  header .meta { margin-left: auto; font-size: 13px; color: #8b949e; }
  header .meta .refresh-indicator { color: #3fb950; margin-left: 8px; }
  main { padding: 24px; max-width: 1200px; margin: 0 auto; }
  .no-hosts { text-align: center; color: #8b949e; padding: 48px; }
  .no-hosts code { background: #161b22; padding: 2px 6px; border-radius: 4px; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  thead th {
    text-align: left;
    padding: 12px 16px;
    background: #161b22;
    border-bottom: 2px solid #30363d;
    font-size: 13px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  tbody tr {
    border-bottom: 1px solid #21262d;
    transition: background 0.15s;
  }
  tbody tr:hover { background: #161b22; }
  tbody td { padding: 14px 16px; font-size: 14px; }
  .host-name {
    color: #58a6ff;
    cursor: pointer;
    text-decoration: underline;
    text-decoration-color: transparent;
    transition: text-decoration-color 0.15s;
  }
  .host-name:hover { text-decoration-color: #58a6ff; }
  .health-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    font-size: 14px;
    position: relative;
    cursor: help;
  }
  .health-healthy { background: #0d2818; color: #3fb950; }
  .health-warning { background: #2a1f0a; color: #d29922; }
  .health-critical { background: #2d0a0a; color: #f85149; }
  .health-unknown { background: #1c2128; color: #8b949e; }
  .health-unreachable { background: #2d0a0a; color: #f85149; font-size: 11px; }

  /* Tooltip */
  .tooltip {
    display: none;
    position: absolute;
    bottom: calc(100% + 8px);
    left: 50%;
    transform: translateX(-50%);
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px 14px;
    min-width: 200px;
    max-width: 320px;
    z-index: 100;
    font-size: 13px;
    line-height: 1.5;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    pointer-events: none;
  }
  .tooltip .tt-title { font-weight: 600; margin-bottom: 4px; color: #e6edf3; }
  .tooltip .tt-detail { color: #c9d1d9; }
  .tooltip .tt-suggestion { color: #58a6ff; margin-top: 6px; }
  .health-icon:hover .tooltip { display: block; }

  /* Modal */
  .modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 200;
    justify-content: center;
    align-items: center;
  }
  .modal-overlay.active { display: flex; }
  .modal {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    width: 90%;
    max-width: 800px;
    max-height: 85vh;
    overflow-y: auto;
    padding: 24px;
    position: relative;
  }
  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid #30363d;
  }
  .modal-header h2 { font-size: 18px; color: #58a6ff; }
  .modal-close {
    background: none;
    border: 1px solid #30363d;
    color: #8b949e;
    width: 32px;
    height: 32px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 18px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
  }
  .modal-close:hover { background: #21262d; color: #e6edf3; }
  .modal-section {
    margin-bottom: 16px;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px;
  }
  .modal-section h3 {
    font-size: 14px;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }
  .modal-section pre {
    font-family: 'SF Mono', 'Cascadia Code', monospace;
    font-size: 12px;
    line-height: 1.6;
    white-space: pre-wrap;
    color: #8b949e;
  }
  .modal-section .rec-item {
    padding: 8px 12px;
    margin: 6px 0;
    border-radius: 6px;
    font-size: 13px;
  }
  .rec-critical { background: #2d0a0a; border-left: 3px solid #f85149; }
  .rec-warning { background: #2a1f0a; border-left: 3px solid #d29922; }
  .rec-info { background: #0a1929; border-left: 3px solid #58a6ff; }
  .rec-action { color: #58a6ff; font-size: 12px; margin-top: 4px; }

  .error-msg { color: #f85149; font-size: 13px; }
  .timestamp { color: #8b949e; font-size: 12px; }
  .ssh-badge {
    display: inline-block;
    background: #1a3a5c;
    color: #58a6ff;
    font-size: 11px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 3px;
    border: 1px solid #30496d;
    vertical-align: middle;
    margin-left: 4px;
  }
</style>
</head>
<body>
<header>
  <span class="logo">🩺</span>
  <h1>Linux Doctor Dashboard</h1>
  <div class="meta">
    <span id="last-refresh">Loading...</span>
    <span class="refresh-indicator" id="refresh-dot">●</span>
  </div>
</header>
<main>
  <div id="content">
    <div class="no-hosts">
      <p>Scanning hosts...</p>
    </div>
  </div>
</main>

<!-- Modal -->
<div class="modal-overlay" id="modal-overlay">
  <div class="modal">
    <div class="modal-header">
      <h2 id="modal-title">Host Details</h2>
      <button class="modal-close" id="modal-close">&times;</button>
    </div>
    <div id="modal-body"></div>
  </div>
</div>

<script>
const REFRESH_INTERVAL = 5000; // 5 seconds
let hostsData = {};

function healthIcon(status) {
  const icons = {
    healthy: { emoji: '✓', cls: 'health-healthy' },
    warning: { emoji: '⚠', cls: 'health-warning' },
    critical: { emoji: '✗', cls: 'health-critical' },
    unknown: { cls: 'health-unknown', emoji: '?' },
  };
  const unreachable = { cls: 'health-unreachable', emoji: '✗' };
  const info = icons[status] || icons.unknown;
  return info;
}

function tooltipHtml(detail, suggestion) {
  let html = '<div class="tooltip">';
  if (detail) html += '<div class="tt-detail">' + escapeHtml(detail) + '</div>';
  if (suggestion) html += '<div class="tt-suggestion">→ ' + escapeHtml(suggestion) + '</div>';
  if (!detail && !suggestion) html += '<div class="tt-detail">No issues detected</div>';
  html += '</div>';
  return html;
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function renderDashboard(data) {
  const hosts = Object.values(data);
  if (!hosts || hosts.length === 0) {
    document.getElementById('content').innerHTML =
      '<div class="no-hosts"><p>No registered hosts found.</p>' +
      '<p style="margin-top:12px">Register hosts with: <code>linuxdoctor registerhost HOST --cpu-cores N</code></p></div>';
    return;
  }

  let html = '<table><thead><tr>';
  html += '<th>Host</th><th>CPU</th><th>Context</th><th>I/O Wait</th><th>Disk</th>';
  html += '</tr></thead><tbody>';

  for (const h of hosts) {
    html += '<tr>';

    // Host name (clickable) — show SSH badge for SSH hosts
    if (h.collection_method === 'ssh') {
      html += '<td><span class="host-name" onclick="showModal(\\'' + escapeHtml(h.host) + '\\')">' + escapeHtml(h.host) + '</span>';
      html += ' <span class="ssh-badge">SSH</span>';
      if (h.ssh_connect && h.ssh_connect !== h.host) {
        html += '<br><span class="timestamp">via ' + escapeHtml(h.ssh_connect) + '</span>';
      }
      html += '<br><span class="timestamp">' + escapeHtml(h.timestamp || '') + '</span></td>';
    } else if (h.reachable) {
      html += '<td><span class="host-name" onclick="showModal(\\'' + escapeHtml(h.host) + '\\')">' + escapeHtml(h.host) + '</span>';
      html += '<br><span class="timestamp">' + escapeHtml(h.timestamp || '') + '</span></td>';
    } else {
      html += '<td><span class="error-msg">' + escapeHtml(h.host) + '</span>';
      html += '<br><span class="error-msg" style="font-size:12px">' + escapeHtml(h.error || 'Unreachable') + '</span></td>';
    }

    // Health columns
    const cols = [
      { status: h.cpu_health, detail: h.cpu_detail, suggestion: h.cpu_suggestion },
      { status: h.context_health, detail: h.context_detail, suggestion: h.context_suggestion },
      { status: h.io_wait_health, detail: h.io_wait_detail, suggestion: h.io_wait_suggestion },
      { status: h.disk_health, detail: h.disk_detail, suggestion: h.disk_suggestion },
    ];

    for (const col of cols) {
      if (!h.reachable) {
        const i = { cls: 'health-unreachable', emoji: '✗' };
        html += '<td><span class="health-icon ' + i.cls + '">' + i.emoji + tooltipHtml('Host unreachable', '') + '</span></td>';
        continue;
      }
      const i = healthIcon(col.status);
      html += '<td><span class="health-icon ' + i.cls + '">' + i.emoji;
      html += tooltipHtml(col.detail, col.suggestion);
      html += '</span></td>';
    }

    html += '</tr>';
  }

  html += '</tbody></table>';
  document.getElementById('content').innerHTML = html;
}

function showModal(host) {
  const h = hostsData[host];
  if (!h || !h.full_analysis) return;

  document.getElementById('modal-title').textContent = host + ' — Detailed Analysis';

  let html = '<div class="timestamp" style="margin-bottom:12px">Last scan: ' + escapeHtml(h.timestamp) + '</div>';
  if (h.collection_method === 'ssh') {
    html += '<div style="margin-bottom:8px"><span class="ssh-badge">SSH</span> Metrics collected via SSH' + (h.ssh_connect ? ' to ' + escapeHtml(h.ssh_connect) : '') + '</div>';
  } else {
    html += '<div style="margin-bottom:8px"><span class="timestamp">Metrics via node_exporter</span></div>';
  }

  const categories = h.full_analysis.categories || {};
  for (const [cat, data] of Object.entries(categories)) {
    html += '<div class="modal-section">';
    html += '<h3>' + escapeHtml(cat) + '</h3>';

    if (data.lines && data.lines.length > 0) {
      html += '<pre>' + escapeHtml(data.lines.join('\\n')) + '</pre>';
    }

    if (data.recommendations && data.recommendations.length > 0) {
      for (const rec of data.recommendations) {
        const cls = rec.severity === 'critical' ? 'rec-critical' :
                    rec.severity === 'warning' ? 'rec-warning' : 'rec-info';
        html += '<div class="rec-item ' + cls + '">';
        html += '<strong>[' + rec.severity.toUpperCase() + ']</strong> ' + escapeHtml(rec.message);
        if (rec.action) html += '<div class="rec-action">→ ' + escapeHtml(rec.action) + '</div>';
        html += '</div>';
      }
    } else {
      html += '<pre style="color:#3fb950">✓ No issues in this category</pre>';
    }

    html += '</div>';
  }

  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').classList.add('active');
}

document.getElementById('modal-close').addEventListener('click', function() {
  document.getElementById('modal-overlay').classList.remove('active');
});
document.getElementById('modal-overlay').addEventListener('click', function(e) {
  if (e.target === this) this.classList.remove('active');
});
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') document.getElementById('modal-overlay').classList.remove('active');
});

async function refresh() {
  try {
    const resp = await fetch('/api/health');
    const data = await resp.json();
    hostsData = data;
    renderDashboard(data);
    document.getElementById('last-refresh').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    document.getElementById('refresh-dot').style.color = '#3fb950';
  } catch (e) {
    document.getElementById('refresh-dot').style.color = '#f85149';
    document.getElementById('last-refresh').textContent = 'Connection error';
  }
}

setInterval(refresh, REFRESH_INTERVAL);
refresh();
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the web dashboard."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            self._send_html(DASHBOARD_HTML)
        elif parsed.path == "/api/health":
            self._send_json(store.to_json())
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def _send_html(self, content: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _send_json(self, content: str):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


def run_dashboard(
    host: str = "0.0.0.0",
    port: int = 7193,
    interval: int = 300,
    node_port: int = 9100,
    registry_path: str = DEFAULT_REGISTRY_PATH,
    threshold_profile: str = "default",
):
    """Start the web dashboard server with background scanner.

    Args:
        host: Interface to bind to (default: 0.0.0.0).
        port: Port to listen on (default: 7193).
        interval: Scan interval in seconds (default: 300 = 5 min).
        node_port: Node exporter port (default: 9100).
        registry_path: Path to the host registry YAML file.
        threshold_profile: Threshold profile to use.
    """
    # Start background scanner
    stop_event = threading.Event()
    scanner_thread = threading.Thread(
        target=scanner_loop,
        args=(interval, registry_path, node_port, threshold_profile, stop_event),
        daemon=True,
    )
    scanner_thread.start()

    # Start HTTP server
    server = HTTPServer((host, port), DashboardHandler)

    url = f"http://{host}:{port}"
    if host == "0.0.0.0":
        # Show a more useful URL hint
        import socket
        try:
            hostname = socket.getfqdn()
            url_hint = f"http://localhost:{port} or http://{hostname}:{port}"
        except Exception:
            url_hint = f"http://localhost:{port}"
    else:
        url_hint = url

    click_echo_safe(f"🩺 Linux Doctor Dashboard")
    click_echo_safe(f"📊 Dashboard URL: {url_hint}")
    click_echo_safe(f"🔄 Scan interval: {interval}s")
    click_echo_safe(f"📋 Registry: {registry_path}")
    click_echo_safe(f"Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click_echo_safe("\n🛑 Shutting down dashboard...")
        stop_event.set()
        server.shutdown()


def click_echo_safe(msg: str) -> None:
    """Print a message to stdout safely."""
    try:
        import click
        click.echo(msg)
    except Exception:
        print(msg)