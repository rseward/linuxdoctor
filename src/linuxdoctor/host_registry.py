"""Host registry for storing host metadata (CPU core count, etc.).

When analyzing remote nodes via node_exporter, certain metrics (like context
switches) need to be normalized by CPU core count for meaningful thresholds.
node_exporter doesn't always expose the actual physical/core CPU count reliably,
so this module lets users register that information manually.

Registry is stored as YAML in ~/.config/linuxdoctor/hosts.yaml by default.
"""

import os
from pathlib import Path
from typing import Optional

import yaml


DEFAULT_REGISTRY_PATH = os.path.expanduser("~/.config/linuxdoctor/hosts.yaml")


def _ensure_registry_dir(path: str = DEFAULT_REGISTRY_PATH) -> None:
    """Ensure the registry directory exists."""
    registry_dir = os.path.dirname(path)
    os.makedirs(registry_dir, exist_ok=True)


def load_registry(path: str = DEFAULT_REGISTRY_PATH) -> dict:
    """Load the host registry from disk.

    Returns:
        Dict mapping host identifiers to their metadata.
        e.g. {"server1": {"cpu_cores": 4}, "192.168.1.5": {"cpu_cores": 16}}
    """
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return {}
            # Validate structure: each value should be a dict (or None for empty entries)
            valid = {}
            for key, value in data.items():
                if isinstance(value, dict):
                    valid[key] = value
                elif value is None:
                    # YAML allows "key:" with no value, treat as empty dict
                    valid[key] = {}
                # Skip entries with non-dict values (corrupt data)
            return valid
    except Exception:
        return {}


def save_registry(registry: dict, path: str = DEFAULT_REGISTRY_PATH) -> None:
    """Save the host registry to disk."""
    _ensure_registry_dir(path)
    with open(path, "w") as f:
        yaml.dump(registry, f, default_flow_style=False, sort_keys=True)


def register_host(
    host: str,
    cpu_cores: Optional[int] = None,
    cpu_sockets: Optional[int] = None,
    description: Optional[str] = None,
    path: str = DEFAULT_REGISTRY_PATH,
) -> dict:
    """Register or update host metadata.

    Args:
        host: Hostname or IP address of the target node.
        cpu_cores: Total number of CPU cores (logical processors).
        cpu_sockets: Number of physical CPU sockets.
        description: Human-readable description of the host.
        path: Path to the registry file.

    Returns:
        The updated host entry.
    """
    registry = load_registry(path)

    if host not in registry:
        registry[host] = {}

    entry = registry[host]

    if cpu_cores is not None:
        entry["cpu_cores"] = cpu_cores
    if cpu_sockets is not None:
        entry["cpu_sockets"] = cpu_sockets
    if description is not None:
        entry["description"] = description

    save_registry(registry, path)
    return entry


def unregister_host(host: str, path: str = DEFAULT_REGISTRY_PATH) -> bool:
    """Remove a host from the registry.

    Returns:
        True if the host was found and removed, False otherwise.
    """
    registry = load_registry(path)
    if host in registry:
        del registry[host]
        save_registry(registry, path)
        return True
    return False


def get_host_info(host: str, path: str = DEFAULT_REGISTRY_PATH) -> Optional[dict]:
    """Look up host metadata from the registry.

    Args:
        host: Hostname or IP address.
        path: Path to the registry file.

    Returns:
        Dict with host metadata, or None if not registered.
    """
    registry = load_registry(path)
    return registry.get(host)


def list_hosts(path: str = DEFAULT_REGISTRY_PATH) -> dict:
    """List all registered hosts and their metadata.

    Returns:
        Dict mapping host identifiers to their metadata.
    """
    return load_registry(path)