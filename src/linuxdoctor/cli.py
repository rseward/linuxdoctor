"""CLI entry point for linuxdoctor."""

import click
from linuxdoctor.analyze import analyze_host
# analyzenode uses local import in command


@click.group()
@click.version_option()
def cli():
    """linuxdoctor - Analyze performance metrics and recommend actions."""
    pass


@cli.command()
@click.option("--json-output", "json_output", is_flag=True, help="Output results as JSON")
@click.option("--no-recommendations", "no_recs", is_flag=True, help="Skip recommendation generation")
@click.option("--check", "-c", multiple=True, help="Run only specific checks (cpu,memory,disk,io,network,load)")
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
def analyzenode(node_address, port, json_output, no_recs):
    """Analyze a remote node using node_exporter metrics.

    NODE_ADDRESS is the hostname or IP of the target node.
    """
    from linuxdoctor.node_analyzer import analyze_remote_node
    result = analyze_remote_node(
        node_address=node_address,
        port=port,
        json_output=json_output,
        include_recommendations=not no_recs,
    )
    click.echo(result)