#!/usr/bin/env python

import click
import httpx
import re

"""
This project implements a python script that analyzes a prometheus end point of a linux server,
to judge the health of the server. The script will make many useful recommendations for
poorly performing linux servers.
"""

def fetch_metrics(url):
    """
    Fetches metrics from the given URL.
    """
    try:
        response = httpx.get(url)
        response.raise_for_status()
        return response.text
    except httpx.RequestError as exc:
        click.echo(f"An error occurred while requesting {exc.request.url!r}.")
        return None
    except httpx.HTTPStatusError as exc:
        click.echo(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        return None

def list_hosts_from_prometheus(prometheus_url):
    """
    Lists available hosts from a Prometheus server by querying the targets API.
    """
    try:
        # Clean up the URL
        if prometheus_url.endswith('/'):
            prometheus_url = prometheus_url[:-1]
        
        # Try to get targets from Prometheus API
        api_url = f"{prometheus_url}/api/v1/targets"
        response = httpx.get(api_url)
        response.raise_for_status()
        
        data = response.json()
        
        if data['status'] != 'success':
            click.echo("Failed to retrieve targets from Prometheus.")
            return []
        
        targets = data['data']['activeTargets']
        hosts = []
        
        for target in targets:
            labels = target.get('labels', {})
            instance = labels.get('instance', 'unknown')
            job = labels.get('job', 'unknown')
            health = target.get('health', 'unknown')
            
            # Parse instance to get host and port
            if ':' in instance:
                host = instance.split(':')[0]
            else:
                host = instance
            
            hosts.append({
                'host': host,
                'instance': instance,
                'job': job,
                'health': health
            })
        
        return hosts
    
    except httpx.RequestError as exc:
        click.echo(f"An error occurred while requesting {exc.request.url!r}.")
        return []
    except httpx.HTTPStatusError as exc:
        click.echo(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        return []
    except Exception as exc:
        click.echo(f"An error occurred: {exc}")
        return []

def parse_metrics(metrics_text):
    """
    Parses the prometheus metrics text into a dictionary.
    """
    metrics = {}
    for line in metrics_text.splitlines():
        if line.startswith('#') or not line:
            continue
        parts = line.split()
        metric_name = parts[0]
        value = parts[-1]
        if '{' in metric_name:
            name_parts = metric_name.split('{')
            metric_name = name_parts[0]
            labels_str = name_parts[1][:-1]
            labels = {}
            for item in labels_str.split(','):
                if '=' in item:
                    key, val = item.split('=', 1)
                    labels[key] = val.strip('"')
            if metric_name not in metrics:
                metrics[metric_name] = []
            metrics[metric_name].append({'labels': labels, 'value': float(value)})
        else:
            metrics[metric_name] = float(value)
    return metrics

def analyze_cpu(metrics):
    """
    Analyzes CPU usage and provides recommendations.
    """
    recommendations = []
    click.echo("\n" + "="*50)
    click.echo("CPU ANALYSIS")
    click.echo("="*50)
    
    cpu_idle_warn_percent = 20
    cpu_iowait_warn_percent = 10

    cpu_seconds = metrics.get('node_cpu_seconds_total', [])
    if not cpu_seconds:
        click.echo("❌ CPU metrics not found.")
        return recommendations

    num_cpus = len(set(entry['labels']['cpu'] for entry in cpu_seconds if 'cpu' in entry['labels']))
    click.echo(f"Number of CPUs: {num_cpus}")

    idle_time = 0
    total_time = 0
    iowait_time = 0

    for entry in cpu_seconds:
        total_time += entry['value']
        if 'mode' in entry['labels']:
            if entry['labels']['mode'] == 'idle':
                idle_time += entry['value']
            if entry['labels']['mode'] == 'iowait':
                iowait_time += entry['value']

    if total_time > 0:
        idle_percent = (idle_time / total_time) * 100
        iowait_percent = (iowait_time / total_time) * 100

        cpu_status = "✅" if idle_percent >= cpu_idle_warn_percent else "⚠️"
        click.echo(f"{cpu_status} CPU Idle: {idle_percent:.2f}% [warning below {cpu_idle_warn_percent}%]")

        iowait_status = "✅" if iowait_percent <= cpu_iowait_warn_percent else "⚠️"
        click.echo(f"{iowait_status} CPU I/O Wait: {iowait_percent:.2f}% [warning above {cpu_iowait_warn_percent}%]")

        if idle_percent < cpu_idle_warn_percent:
            recommendations.append(f"CPU idle time is {idle_percent:.0f}%, below the {cpu_idle_warn_percent}% warning threshold. The server might be under heavy load.")
        if iowait_percent > cpu_iowait_warn_percent:
            recommendations.append(f"CPU I/O wait is {iowait_percent:.0f}%, above the {cpu_iowait_warn_percent}% warning threshold. The server might be experiencing a disk bottleneck.")

    load1 = metrics.get('node_load1', 0)
    load5 = metrics.get('node_load5', 0)
    load15 = metrics.get('node_load15', 0)

    load_status = "✅" if load1 <= num_cpus else "⚠️"
    click.echo(f"{load_status} Load Average (1m/5m/15m): {load1:.2f}, {load5:.2f}, {load15:.2f} [warning when 1-min load exceeds {num_cpus} CPUs]")

    if load1 > num_cpus:
        recommendations.append(f"1-minute load average ({load1:.2f}) exceeds the number of CPUs ({num_cpus}), indicating high load.")
    
    return recommendations

def analyze_memory(metrics):
    """
    Analyzes memory usage and provides recommendations.
    """
    recommendations = []
    click.echo("\n" + "="*50)
    click.echo("MEMORY ANALYSIS")
    click.echo("="*50)
    
    mem_warn_percent = 85

    mem_total_bytes = metrics.get('node_memory_MemTotal_bytes')
    mem_available_bytes = metrics.get('node_memory_MemAvailable_bytes')

    if mem_total_bytes is not None and mem_available_bytes is not None:
        mem_total_gb = mem_total_bytes / (1024**3)
        mem_available_gb = mem_available_bytes / (1024**3)
        mem_used_gb = mem_total_gb - mem_available_gb
        mem_used_percent = (mem_used_gb / mem_total_gb) * 100

        mem_status = "✅" if mem_used_percent <= mem_warn_percent else "⚠️"

        click.echo(f"Total Memory: {mem_total_gb:.2f} GB")
        click.echo(f"{mem_status} Used Memory: {mem_used_gb:.2f} GB ({mem_used_percent:.2f}%) [warning above {mem_warn_percent}%]")
        click.echo(f"Available Memory: {mem_available_gb:.2f} GB")

        if mem_used_percent > mem_warn_percent:
            recommendations.append(f"Memory usage is {mem_used_percent:.0f}%, above the {mem_warn_percent}% warning threshold. Consider adding more RAM or optimizing memory usage.")
    else:
        click.echo("❌ Memory metrics not found.")
    
    return recommendations

def analyze_disk(metrics):
    """
    Analyzes disk usage and provides recommendations.
    """
    recommendations = []
    click.echo("\n" + "="*50)
    click.echo("DISK ANALYSIS")
    click.echo("="*50)
    
    disk_size_bytes = metrics.get('node_filesystem_size_bytes', [])
    disk_avail_bytes = metrics.get('node_filesystem_avail_bytes', [])
    disk_warn_percent = 85

    if not disk_size_bytes:
        click.echo("❌ Disk metrics not found.")
        return recommendations

    for size_entry in disk_size_bytes:
        if 'mountpoint' in size_entry['labels']:
            mountpoint = size_entry['labels']['mountpoint']
            for avail_entry in disk_avail_bytes:
                if 'mountpoint' in avail_entry['labels'] and avail_entry['labels']['mountpoint'] == mountpoint:
                    disk_size_gb = size_entry['value'] / (1024**3)
                    disk_avail_gb = avail_entry['value'] / (1024**3)
                    disk_used_gb = disk_size_gb - disk_avail_gb
                    if disk_size_gb > 0:
                        disk_used_percent = (disk_used_gb / disk_size_gb) * 100
                        disk_status = "✅" if disk_used_percent <= disk_warn_percent else "⚠️"

                        click.echo(f"Mountpoint: {mountpoint}")
                        click.echo(f"  Total Size: {disk_size_gb:.2f} GB")
                        click.echo(f"  {disk_status} Used Space: {disk_used_gb:.2f} GB ({disk_used_percent:.2f}%) [warning at {disk_warn_percent}%]")
                        click.echo(f"  Available Space: {disk_avail_gb:.2f} GB")

                        if disk_used_percent > disk_warn_percent:
                            recommendations.append(f"Disk usage for {mountpoint} is {disk_used_percent:.0f}%, which exceeds the {disk_warn_percent}% warning threshold. Consider cleaning up disk space or expanding the filesystem.")
                    break
    return recommendations

def analyze_disk_io(metrics):
    """
    Analyzes disk I/O and provides recommendations.
    """
    recommendations = []
    click.echo("\n" + "="*50)
    click.echo("DISK I/O ANALYSIS")
    click.echo("="*50)
    
    io_time = metrics.get('node_disk_io_time_seconds_total', [])
    io_warn_seconds = 10000
    if not io_time:
        click.echo("❌ Disk I/O metrics not found.")
        return recommendations

    for entry in io_time:
        if 'device' in entry['labels']:
            device = entry['labels']['device']
            # This value is a counter, so to get a rate we'd need to compare over time.
            # For a single run, we can just check for very high values as an indicator of past issues.
            io_status = "✅" if entry['value'] <= io_warn_seconds else "⚠️"
            click.echo(f"{io_status} Device {device}: I/O time {entry['value']:.0f}s [warning above {io_warn_seconds}s]")
            if entry['value'] > io_warn_seconds:
                 recommendations.append(f"Device {device} I/O time is {entry['value']:.0f}s, above the {io_warn_seconds}s warning threshold. This could be a bottleneck.")
    return recommendations

def analyze_network(metrics):
    """
    Analyzes network usage and provides recommendations.
    """
    recommendations = []
    click.echo("\n" + "="*50)
    click.echo("NETWORK ANALYSIS")
    click.echo("="*50)
    
    receive_bytes = metrics.get('node_network_receive_bytes_total', [])
    transmit_bytes = metrics.get('node_network_transmit_bytes_total', [])
    receive_errs = metrics.get('node_network_receive_errs_total', [])
    transmit_errs = metrics.get('node_network_transmit_errs_total', [])

    if not receive_bytes:
        click.echo("❌ Network metrics not found.")
        return recommendations

    for i in range(len(receive_bytes)):
        if 'device' in receive_bytes[i]['labels']:
            device = receive_bytes[i]['labels']['device']
            click.echo(f"Device: {device}")
            click.echo(f"  Received: {receive_bytes[i]['value'] / (1024**2):.2f} MB")
            click.echo(f"  Transmitted: {transmit_bytes[i]['value'] / (1024**2):.2f} MB")
            
            if i < len(receive_errs) and receive_errs[i]['value'] > 0:
                click.echo(f"  ⚠️ Receive Errors: {receive_errs[i]['value']}")
                recommendations.append(f"High number of received errors on device {device}.")
            else:
                click.echo(f"  ✅ No receive errors")
                
            if i < len(transmit_errs) and transmit_errs[i]['value'] > 0:
                click.echo(f"  ⚠️ Transmit Errors: {transmit_errs[i]['value']}")
                recommendations.append(f"High number of transmitted errors on device {device}.")
            else:
                click.echo(f"  ✅ No transmit errors")
    return recommendations

def analyze_context_switching(metrics):
    """
    Analyzes context switching and provides recommendations.
    """
    recommendations = []
    click.echo("\n" + "="*50)
    click.echo("CONTEXT SWITCHING ANALYSIS")
    click.echo("="*50)
    
    cs_warn_count = 10000000

    context_switches = metrics.get('node_context_switches_total')
    if context_switches is None:
        click.echo("❌ Context switching metrics not found.")
        return recommendations

    cs_status = "✅" if context_switches <= cs_warn_count else "⚠️"
    click.echo(f"{cs_status} Total Context Switches: {context_switches:,} [warning above {cs_warn_count:,}]")

    # A high number of context switches can be an indicator of performance issues.
    # The definition of "high" is very dependent on the workload.
    if context_switches > cs_warn_count:
        recommendations.append(f"Context switches ({context_switches:,}) exceed the {cs_warn_count:,} warning threshold. This could indicate that the system is thrashing.")
    return recommendations

def print_recommendations(url, recommendations):
    """
    Prints the recommendations summary.
    """
    click.echo("\n" + "="*50)
    if recommendations:
        click.echo(f"⚠️  RECOMMENDATIONS FOR {url}")
        click.echo("="*50)
        for i, rec in enumerate(recommendations, 1):
            click.echo(f"{i}. {rec}")
    else:
        click.echo(f"✅ NO RECOMMENDATIONS - {url} LOOKS HEALTHY!")
    click.echo("="*50)

@click.group()
def cli():
    """
    Linux Doctor - Analyze Prometheus node exporter metrics for Linux server health.
    """
    pass

@cli.command()
@click.argument('url', default='localhost:9100')
@click.option('--verbose', '-v', is_flag=True, help='Show verbose output')
def analyze(url, verbose):
    """
    Analyze a Linux server's health using Prometheus node exporter metrics.
    
    URL can be:
    - A hostname (e.g., 'localhost' or 'server.example.com')
    - A full node exporter URL (e.g., 'http://server:9100/metrics')
    
    Example: python linuxdoctor.py analyze server.example.com
    """
    # Fix up the URL if it isn't in the proper format
    if not url.startswith('http'):
        # Assume the url is just a host name
        host = url
        url = f"http://{host}:9100/metrics"
    elif "metrics" not in url:
        # URL provided but missing /metrics endpoint
        url = f"{url}/metrics"

    click.echo("🔍 Linux Doctor v1.0")
    click.echo(f"📊 Analyzing prometheus node exporter at {url}")
    click.echo("="*50)
    
    metrics_text = fetch_metrics(url)
    if metrics_text:
        metrics = parse_metrics(metrics_text)
        
        recommendations = []
        recommendations.extend(analyze_cpu(metrics))
        recommendations.extend(analyze_memory(metrics))
        recommendations.extend(analyze_disk(metrics))
        recommendations.extend(analyze_disk_io(metrics))
        recommendations.extend(analyze_network(metrics))
        recommendations.extend(analyze_context_switching(metrics))

        print_recommendations(url, recommendations)
        
        # Exit with proper status code
        if recommendations:
            import sys
            sys.exit(1)
    else:
        click.echo("❌ Failed to fetch metrics from the provided URL.")
        import sys
        sys.exit(2)

@cli.command()
@click.argument('prometheus_url', default='http://localhost:9090')
def list_hosts(prometheus_url):
    """
    List available hosts from a Prometheus server.
    
    URL can be:
    - A Prometheus server address (e.g., 'localhost:9090')
    - A full Prometheus URL (e.g., 'http://prometheus:9090')
    
    Example: python linuxdoctor.py list-hosts prometheus.example.com
    """
    click.echo("🔍 Linux Doctor v1.0")
    click.echo(f"📋 Listing hosts from Prometheus at {prometheus_url}")
    click.echo("="*50)
    
    hosts = list_hosts_from_prometheus(prometheus_url)
    
    if not hosts:
        click.echo("❌ No hosts found or unable to connect to Prometheus.")
        import sys
        sys.exit(2)
    
    click.echo(f"\n📊 Found {len(hosts)} host(s):\n")
    
    for i, host in enumerate(hosts, 1):
        health_icon = "✅" if host['health'] == 'up' else "❌"
        click.echo(f"{i}. {health_icon} {host['instance']}")
        click.echo(f"   Host: {host['host']}")
        click.echo(f"   Job: {host['job']}")
        click.echo(f"   Health: {host['health']}")
        click.echo()
    
    click.echo("="*50)
    click.echo("💡 To analyze a host, use:")
    for host in hosts[:3]:  # Show examples for up to 3 hosts
        click.echo(f"   python linuxdoctor.py analyze {host['host']}")
    click.echo("="*50)

if __name__ == '__main__':
    cli()
