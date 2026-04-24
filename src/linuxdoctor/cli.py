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
@click.option("--resample", is_flag=True, help="Take two samples to compute rates for counter metrics (context switches, disk I/O)")
@click.option("--resample-interval", "resample_interval", default=None, type=int, help="Seconds between samples (default: 30, requires --resample)")
def analyzenode(node_address, port, json_output, no_recs, threshold, verbose, resample, resample_interval):
    """Analyze a remote node using node_exporter metrics.

    NODE_ADDRESS is the hostname or IP of the target node.

    Example: linuxdoctor analyzenode server.example.com

    For accurate counter-based metrics (context switches, disk I/O), use --resample
    to take two samples and compute rates:

        linuxdoctor analyzenode server.example.com --resample

    Register host metadata for better context switch analysis:

        linuxdoctor registerhost server.example.com --cpu-cores 8
    """
    from linuxdoctor.analyzenode import analyze_remote_node
    result = analyze_remote_node(
        node_address=node_address,
        port=port,
        json_output=json_output,
        include_recommendations=not no_recs,
        threshold_profile=threshold,
        verbose=verbose,
        resample=resample,
        resample_interval=resample_interval,
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


# ---------------------------------------------------------------------------
# registerhost command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("host")
@click.option("--cpu-cores", "cpu_cores", type=int, help="Number of CPU cores (logical processors)")
@click.option("--cpu-sockets", "cpu_sockets", type=int, help="Number of physical CPU sockets")
@click.option("--description", "-d", help="Human-readable description of the host")
@click.option("--sshconnect", "ssh_connect", help="SSH connection string for metric collection (e.g. 'user@host'). Use this to collect metrics via SSH instead of node_exporter.")
@click.option("--registry", "registry_path", default=None, help="Path to the host registry YAML file")
def registerhost(host, cpu_cores, cpu_sockets, description, ssh_connect, registry_path):
    """Register host metadata for more accurate analysis.

    HOST is the hostname or IP address of the target node.

    This stores metadata (like CPU core count) that linuxdoctor uses to
    improve the accuracy of context switch and other per-core metrics.
    Without registered core count, context switch thresholds use less
    accurate absolute values.

    Use --sshconnect to register a host for SSH-based metric collection
    instead of node_exporter. The connection string should be in the format
    'user@host' or just 'host' (which uses the current username). The user
    must have passwordless SSH access and accepted host keys configured.

    Examples:

        linuxdoctor registerhost server1 --cpu-cores 8
        linuxdoctor registerhost 192.168.1.5 --cpu-cores 16 --cpu-sockets 2
        linuxdoctor registerhost db-main --cpu-cores 32 -d "Production DB server"
        linuxdoctor registerhost remote1 --sshconnect admin@remote1 --cpu-cores 4
        linuxdoctor registerhost remote2 --sshconnect remote2  # uses current username
    """
    from linuxdoctor.host_registry import register_host as _register_host
    from linuxdoctor.host_registry import DEFAULT_REGISTRY_PATH as _default_path

    path = registry_path or _default_path

    if cpu_cores is None and cpu_sockets is None and description is None and ssh_connect is None:
        click.echo("⚠️  No metadata specified. Use --cpu-cores, --cpu-sockets, --description, or --sshconnect.")
        click.echo(f"   Example: linuxdoctor registerhost {host} --cpu-cores 8")
        click.echo(f"   Example: linuxdoctor registerhost {host} --sshconnect user@{host}")
        sys.exit(1)

    try:
        entry = _register_host(
            host=host,
            cpu_cores=cpu_cores,
            cpu_sockets=cpu_sockets,
            description=description,
            ssh_connect=ssh_connect,
            path=path,
        )
        click.echo(f"✅ Registered {host}:")
        for key, value in entry.items():
            click.echo(f"   {key}: {value}")
        if ssh_connect:
            click.echo(f"   📡 Metric collection: SSH ({ssh_connect})")
        else:
            click.echo(f"   📡 Metric collection: node_exporter")
        click.echo(f"   Registry: {path}")
    except Exception as e:
        click.echo(f"❌ Failed to register {host}: {e}")
        sys.exit(2)


@cli.command()
@click.option("--host", "bind_host", default="0.0.0.0", help="Interface to bind to (default: 0.0.0.0)")
@click.option("--port", "-p", default=7193, help="Port to listen on (default: 7193)")
@click.option("--interval", "-i", default=300, type=int, help="Scan interval in seconds (default: 300 = 5 min)")
@click.option("--node-port", "node_port", default=9100, type=int, help="Node exporter port (default: 9100)")
@click.option("--threshold", "-t", default="default", help="Threshold profile: default, strict, or relaxed")
@click.option("--registry", "registry_path", default=None, help="Path to the host registry YAML file")
def web(bind_host, port, interval, node_port, threshold, registry_path):
    """Start a web dashboard showing host health status.

    Iterates through registered hosts, connects periodically (default 5 min),
    and presents a dynamically refreshing dashboard with health indicators
    for CPU, Context Switching, I/O Wait, and Disk.

    Hover over health icons for details. Click a host name for full analysis.

    Example: linuxdoctor web --port 7193 --interval 300
    """
    from linuxdoctor.web import run_dashboard
    from linuxdoctor.host_registry import DEFAULT_REGISTRY_PATH as _default_path

    reg_path = registry_path or _default_path
    run_dashboard(
        host=bind_host,
        port=port,
        interval=interval,
        node_port=node_port,
        registry_path=reg_path,
        threshold_profile=threshold,
    )


@cli.command("list-registered")
@click.option("--registry", "registry_path", default=None, help="Path to the host registry YAML file")
def list_registered(registry_path):
    """List all registered hosts and their metadata."""
    from linuxdoctor.host_registry import list_hosts as _list_hosts, DEFAULT_REGISTRY_PATH as _default_path

    path = registry_path or _default_path
    hosts = _list_hosts(path=path)

    if not hosts:
        click.echo(f"📋 No hosts registered. Registry: {path}")
        click.echo("   Use `linuxdoctor registerhost HOST --cpu-cores N` to register a host.")
        click.echo("   Use `linuxdoctor registerhost HOST --sshconnect user@host` to register an SSH host.")
        return

    click.echo(f"📋 Registered hosts ({len(hosts)}):")
    click.echo("=" * 50)
    for host, info in hosts.items():
        click.echo(f"  {host}:")
        for key, value in info.items():
            click.echo(f"    {key}: {value}")
        # Show collection method
        if "ssh_connect" in info:
            click.echo(f"    📡 Collection method: SSH ({info['ssh_connect']})")
        else:
            click.echo(f"    📡 Collection method: node_exporter")
    click.echo("=" * 50)
    click.echo(f"Registry: {path}")


@cli.command("unregisterhost")
@click.argument("host")
@click.option("--registry", "registry_path", default=None, help="Path to the host registry YAML file")
def unregisterhost(host, registry_path):
    """Remove a host from the registry.

    HOST is the hostname or IP address to remove.
    """
    from linuxdoctor.host_registry import unregister_host as _unregister_host, DEFAULT_REGISTRY_PATH as _default_path

    path = registry_path or _default_path

    if _unregister_host(host, path=path):
        click.echo(f"✅ Removed {host} from registry.")
    else:
        click.echo(f"⚠️  {host} not found in registry.")
        sys.exit(1)