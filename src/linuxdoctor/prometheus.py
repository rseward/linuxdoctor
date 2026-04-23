"""Prometheus host discovery module.

Lists available hosts from a Prometheus server by querying the targets API.
"""

from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class HostInfo:
    """Information about a host discovered from Prometheus."""
    instance: str
    host: str
    job: str
    health: str


def list_hosts_from_prometheus(prometheus_url: str, timeout: int = 10) -> list[HostInfo]:
    """List available hosts from a Prometheus server.

    Queries the /api/v1/targets endpoint to discover all active targets.

    Args:
        prometheus_url: Base URL of the Prometheus server (e.g., 'http://localhost:9090').
        timeout: Request timeout in seconds.

    Returns:
        List of HostInfo objects for all active targets.

    Raises:
        RuntimeError: If the request fails or the response is invalid.
    """
    # Normalize URL
    url = prometheus_url.rstrip("/")
    api_url = f"{url}/api/v1/targets"

    try:
        response = httpx.get(api_url, timeout=timeout)
        response.raise_for_status()
    except httpx.RequestError as exc:
        raise RuntimeError(f"Cannot connect to Prometheus at {api_url}: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"HTTP {exc.response.status_code} from Prometheus at {api_url}"
        ) from exc

    try:
        data = response.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to parse Prometheus response: {exc}") from exc

    if data.get("status") != "success":
        raise RuntimeError(f"Prometheus returned status: {data.get('status', 'unknown')}")

    targets = data.get("data", {}).get("activeTargets", [])
    hosts = []

    for target in targets:
        labels = target.get("labels", {})
        instance = labels.get("instance", "unknown")
        job = labels.get("job", "unknown")
        health = target.get("health", "unknown")

        # Parse instance to get host (strip port)
        host = instance.split(":")[0] if ":" in instance else instance

        hosts.append(HostInfo(
            instance=instance,
            host=host,
            job=job,
            health=health,
        ))

    return hosts