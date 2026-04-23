"""CLI entry point for linuxdoctor."""

import sys

import click
from linuxdoctor.analyze import analyze_host
from linuxdoctor.prometheus import list_hosts_from_prometheus


@click.group()
@click.version_option()
def cli():
    """linuxdoctor - Analyze performance metrics and recommend actions."""
    pass


@cli.command()
@click.option("--json-output", "json_output", is_flag=True, help="Output results as JSON")
@click.option("--no-recommendations", "no_recs", is_flag=True, help="Skip recommendation generation")
@click.option("--check", "-c", multiple=True, help="Run only specific checks (cpu,memory,disk,io,network,load,sar)")
@click.option("--threshold", "-t", default="default", help="Threshold profile: default, strict, or relaxed")
def analyze(json_output, no_recs, check, threshold):
    """Analyze the current host using local performance tools.

    Gathers metrics from sar, vmstat, iostat, mpstat, and other standard
    Linux performance tools, then generates recommendations for improving
    system health (analogous to node_exporter recommendations).
    """
    checks = list(check) if check else None
    result = analyze_host(
        json_output=json_output,
        include_recommendations=not no_recs,
        checks=checks,
        threshold_profile=threshold,
    )
    click.echo(result)


@cli.command()
@click.argument("node_address")
@click.option("--port", "-p", default=9100, help="Node exporter port (default: 9100)")
@click.option("--json-output", "json_output", is_flag=True, help="Output results as JSON")
@click.option("--no-recommendations", "no_recs", is_flag=True, help="Skip recommendation generation")
@click.option("--threshold", "-t", default="default", help="Threshold profile: default, strict, or relaxed")
@click.option("--verbose", "-v", is_flag=True, help="Show verbose output")
def analyzenode(node_address, port, json_output, no_recs, threshold, verbose):
    """Analyze a remote node using node_exporter metrics.

    NODE_ADDRESS is the hostname or IP of the target node.

    Example: linuxdoctor analyzenode server.example.com
    """
    from linuxdoctor.analyzenode import analyze_remote_node
    result = analyze_remote_node(
        node_address=node_address,
        port=port,
        json_output=json_output,
        include_recommendations=not no_recs,
        threshold_profile=threshold,
        verbose=verbose,
    )
    click.echo(result)

    # Exit with proper status code if there are critical/warning recommendations
    if not json_output and not no_recs:
        if "⚠️" in result or "🔴" in result:
            sys.exit(1)


@cli.command("list-hosts")
@click.argument("prometheus_url", default="http://localhost:9090")
@click.option("--timeout", default=10, help="Request timeout in seconds")
def list_hosts(prometheus_url, timeout):
    """List available hosts from a Prometheus server.

    PROMETHEUS_URL is the base URL of the Prometheus server
    (e.g., 'http://localhost:9090' or 'prometheus.example.com').

    Example: linuxdoctor list-hosts prometheus.example.com
    """
    # Fix up URL if needed
    if not prometheus_url.startswith("http"):
        prometheus_url = f"http://{prometheus_url}:9090"

    click.echo("🔍 Linux Doctor v0.1.0")
    click.echo(f"📋 Listing hosts from Prometheus at {prometheus_url}")
    click.echo("=" * 50)

    try:
        hosts = list_hosts_from_prometheus(prometheus_url, timeout=timeout)
    except RuntimeError as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(2)

    if not hosts:
        click.echo("❌ No hosts found or unable to connect to Prometheus.")
        sys.exit(2)

    click.echo(f"\n📊 Found {len(hosts)} host(s):\n")

    for i, host in enumerate(hosts, 1):
        health_icon = "✅" if host.health == "up" else "❌"
        click.echo(f"{i}. {health_icon} {host.instance}")
        click.echo(f"   Host: {host.host}")
        click.echo(f"   Job: {host.job}")
        click.echo(f"   Health: {host.health}")
        click.echo()

    click.echo("=" * 50)
    click.echo("💡 To analyze a host, use:")
    for host in hosts[:3]:  # Show examples for up to 3 hosts
        click.echo(f"   linuxdoctor analyzenode {host.host}")
    click.echo("=" * 50)