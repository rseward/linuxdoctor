"""Tests for the host_registry module."""

import os
import tempfile
import pytest
from linuxdoctor.host_registry import (
    register_host,
    unregister_host,
    get_host_info,
    list_hosts,
    load_registry,
    save_registry,
)


@pytest.fixture
def temp_registry(tmp_path):
    """Create a temporary registry file path."""
    return str(tmp_path / "hosts.yaml")


class TestLoadSaveRegistry:
    """Tests for loading and saving the registry."""

    def test_load_nonexistent_returns_empty(self, temp_registry):
        result = load_registry(temp_registry)
        assert result == {}

    def test_save_and_load(self, temp_registry):
        registry = {"server1": {"cpu_cores": 4}}
        save_registry(registry, temp_registry)
        loaded = load_registry(temp_registry)
        assert loaded == registry

    def test_save_creates_directory(self, tmp_path):
        path = str(tmp_path / "subdir" / "hosts.yaml")
        registry = {"host1": {"cpu_cores": 8}}
        save_registry(registry, path)
        assert os.path.exists(path)
        loaded = load_registry(path)
        assert loaded == registry

    def test_load_corrupt_file(self, temp_registry):
        # Write invalid YAML that should not parse to a valid registry dict
        with open(temp_registry, "w") as f:
            f.write(":::invalid:::\n")
        result = load_registry(temp_registry)
        # The key maps to None, which is treated as an empty dict entry
        assert isinstance(result, dict)

    def test_load_truly_corrupt_file(self, temp_registry):
        # Write binary/unparseable content
        with open(temp_registry, "wb") as f:
            f.write(b"\x00\x01\x02\x03")
        result = load_registry(temp_registry)
        assert result == {}


class TestRegisterHost:
    """Tests for registering hosts."""

    def test_register_new_host(self, temp_registry):
        entry = register_host("server1", cpu_cores=4, path=temp_registry)
        assert entry == {"cpu_cores": 4}

    def test_register_host_with_description(self, temp_registry):
        entry = register_host("server1", cpu_cores=4, description="Web server", path=temp_registry)
        assert entry == {"cpu_cores": 4, "description": "Web server"}

    def test_register_host_with_sockets(self, temp_registry):
        entry = register_host("db1", cpu_cores=16, cpu_sockets=2, path=temp_registry)
        assert entry == {"cpu_cores": 16, "cpu_sockets": 2}

    def test_register_host_with_ssh_connect(self, temp_registry):
        entry = register_host("remote1", ssh_connect="admin@remote1", cpu_cores=4, path=temp_registry)
        assert entry["ssh_connect"] == "admin@remote1"
        assert entry["cpu_cores"] == 4

    def test_register_ssh_only_host(self, temp_registry):
        entry = register_host("remote2", ssh_connect="remote2", path=temp_registry)
        assert entry == {"ssh_connect": "remote2"}

    def test_update_existing_host_add_ssh(self, temp_registry):
        register_host("server1", cpu_cores=4, path=temp_registry)
        entry = register_host("server1", ssh_connect="admin@server1", path=temp_registry)
        assert entry["cpu_cores"] == 4
        assert entry["ssh_connect"] == "admin@server1"

    def test_update_existing_host(self, temp_registry):
        register_host("server1", cpu_cores=4, path=temp_registry)
        entry = register_host("server1", cpu_cores=8, path=temp_registry)
        assert entry == {"cpu_cores": 8}

    def test_preserves_existing_fields_on_update(self, temp_registry):
        register_host("server1", cpu_cores=4, description="Web", path=temp_registry)
        entry = register_host("server1", cpu_sockets=2, path=temp_registry)
        assert entry["cpu_cores"] == 4
        assert entry["description"] == "Web"
        assert entry["cpu_sockets"] == 2


class TestUnregisterHost:
    """Tests for unregistering hosts."""

    def test_unregister_existing(self, temp_registry):
        register_host("server1", cpu_cores=4, path=temp_registry)
        result = unregister_host("server1", path=temp_registry)
        assert result is True
        assert get_host_info("server1", path=temp_registry) is None

    def test_unregister_nonexistent(self, temp_registry):
        result = unregister_host("nothere", path=temp_registry)
        assert result is False


class TestGetHostInfo:
    """Tests for getting host info."""

    def test_get_registered_host(self, temp_registry):
        register_host("server1", cpu_cores=4, description="Web", path=temp_registry)
        info = get_host_info("server1", path=temp_registry)
        assert info == {"cpu_cores": 4, "description": "Web"}

    def test_get_unregistered_host(self, temp_registry):
        info = get_host_info("unknown", path=temp_registry)
        assert info is None


class TestListHosts:
    """Tests for listing hosts."""

    def test_list_empty(self, temp_registry):
        hosts = list_hosts(path=temp_registry)
        assert hosts == {}

    def test_list_multiple(self, temp_registry):
        register_host("server1", cpu_cores=4, path=temp_registry)
        register_host("server2", cpu_cores=8, path=temp_registry)
        hosts = list_hosts(path=temp_registry)
        assert len(hosts) == 2
        assert hosts["server1"]["cpu_cores"] == 4
        assert hosts["server2"]["cpu_cores"] == 8