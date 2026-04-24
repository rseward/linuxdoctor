"""Tests for the recommendation engine."""

import pytest
from linuxdoctor.collectors import MetricCollection, MetricResult
from linuxdoctor.recommendations import (
    generate_recommendations,
    generate_install_suggestions,
    recommend_cpu,
    recommend_memory,
    recommend_disk,
    recommend_io,
    _mount_key_to_path,
)


def _make_collection(category, metrics):
    """Helper to create a MetricCollection with MetricResults."""
    coll = MetricCollection(category=category)
    for name, value, unit, source in metrics:
        coll.metrics.append(MetricResult(
            name=name, value=value, unit=unit or "", source=source or ""
        ))
    return coll


class TestMountKeyToPath:
    """Tests for mount key to path conversion."""

    def test_root(self):
        assert _mount_key_to_path("disk_root") == "/"

    def test_boot(self):
        assert _mount_key_to_path("disk_boot") == "/boot"

    def test_multi_level(self):
        assert _mount_key_to_path("disk_mnt_data") == "/mnt/data"

    def test_bare_key(self):
        assert _mount_key_to_path("root") == "/"


class TestCpuRecommendations:
    """Tests for CPU recommendation generation."""

    def test_high_cpu_usage_critical(self):
        collection = _make_collection("cpu", [
            ("cpu_usage", 90.0, "%", "mpstat"),
            ("cpu_idle", 10.0, "%", "mpstat"),
            ("load_1m", 2.0, "", "/proc/loadavg"),
            ("cpu_count", 36, "", "/proc/cpuinfo"),
        ])
        recs = recommend_cpu([collection], {"cpu_usage_pct": 85, "load_per_cpu": 4.0, "load_per_cpu_warning": 2.0})
        assert len(recs) >= 1
        assert recs[0].severity == "critical"
        assert "CPU usage" in recs[0].message

    def test_normal_cpu_no_recs(self):
        collection = _make_collection("cpu", [
            ("cpu_usage", 30.0, "%", "mpstat"),
            ("cpu_idle", 70.0, "%", "mpstat"),
            ("load_1m", 2.0, "", "/proc/loadavg"),
            ("cpu_count", 36, "", "/proc/cpuinfo"),
        ])
        recs = recommend_cpu([collection], {"cpu_usage_pct": 85, "load_per_cpu": 4.0, "load_per_cpu_warning": 2.0})
        assert len(recs) == 0


class TestMemoryRecommendations:
    """Tests for memory recommendation generation."""

    def test_high_memory_critical(self):
        collection = _make_collection("memory", [
            ("mem_used_pct", 90.0, "%", "/proc/meminfo"),
            ("swap_used_pct", 5.0, "%", "/proc/meminfo"),
        ])
        recs = recommend_memory([collection], {"mem_used_pct": 85, "swap_used_pct": 25, "hugepages_waste_pct": 50})
        assert len(recs) >= 1
        assert recs[0].severity == "critical"
        assert "Memory" in recs[0].message

    def test_swap_usage_warning(self):
        collection = _make_collection("memory", [
            ("mem_used_pct", 50.0, "%", "/proc/meminfo"),
            ("swap_used_pct", 30.0, "%", "/proc/meminfo"),
        ])
        recs = recommend_memory([collection], {"mem_used_pct": 85, "swap_used_pct": 25, "hugepages_waste_pct": 50})
        assert len(recs) >= 1
        assert any(r.metric == "swap_used_pct" for r in recs)


class TestDiskRecommendations:
    """Tests for disk recommendation generation."""

    def test_disk_full_critical(self):
        collection = _make_collection("disk", [
            ("disk_root_used_pct", 96, "%", "df"),
        ])
        recs = recommend_disk([collection], {"disk_used_pct": 80, "disk_used_pct_critical": 95})
        assert len(recs) >= 1
        assert recs[0].severity == "critical"
        assert "/" in recs[0].message

    def test_disk_ok_no_recs(self):
        collection = _make_collection("disk", [
            ("disk_root_used_pct", 30, "%", "df"),
        ])
        recs = recommend_disk([collection], {"disk_used_pct": 80, "disk_used_pct_critical": 95})
        assert len(recs) == 0


class TestIoRecommendations:
    """Tests for I/O recommendation generation."""

    def test_high_iowait_warning(self):
        io_coll = _make_collection("io", [
            ("io_wait_pct", 25, "%", "vmstat"),
        ])
        recs = recommend_io([io_coll], {"cpu_iowait_pct": 20, "io_await_ms": 50, "io_util_pct": 90})
        assert len(recs) >= 1
        assert "I/O wait" in recs[0].message


class TestGenerateRecommendations:
    """Tests for the full recommendation pipeline."""

    def test_sorted_by_severity(self):
        collections = [
            _make_collection("cpu", [
                ("cpu_usage", 90.0, "%", "mpstat"),
                ("cpu_idle", 10.0, "%", "mpstat"),
                ("load_1m", 2.0, "", "/proc/loadavg"),
                ("cpu_count", 36, "", "/proc/cpuinfo"),
            ]),
            _make_collection("disk", [
                ("disk_root_used_pct", 96, "%", "df"),
            ]),
        ]
        recs = generate_recommendations(collections, "default")
        # Critical should come before warning
        if len(recs) >= 2:
            severity_order = {"critical": 0, "warning": 1, "info": 2}
            for i in range(len(recs) - 1):
                assert severity_order.get(recs[i].severity, 3) <= severity_order.get(recs[i+1].severity, 3)

    def test_threshold_profiles(self):
        collection = _make_collection("memory", [
            ("mem_used_pct", 78.0, "%", "/proc/meminfo"),
            ("swap_used_pct", 5.0, "%", "/proc/meminfo"),
        ])
        # Strict should flag this; default should not
        strict_recs = generate_recommendations([collection], "strict")
        default_recs = generate_recommendations([collection], "default")
        assert len(strict_recs) >= len(default_recs)


class TestInstallSuggestions:
    """Tests for generate_install_suggestions."""

    def test_known_tool_has_description(self):
        """Known tools in TOOL_PACKAGES should get a description in the message."""
        coll = MetricCollection(category="cpu", missing_tools=["mpstat"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert rec.metric == "mpstat"
        assert rec.severity == "info"
        # Should include description in the message
        assert "Per-CPU" in rec.message or "mpstat" in rec.message
        # Should include package names in action
        assert "sysstat" in rec.action
        assert "dnf" in rec.action
        assert "apt-get" in rec.action
        # Detail should mention what the tool provides
        assert "description" in rec.detail.lower() or "Provides" in rec.detail or "mpstat" in rec.detail

    def test_unknown_tool_fallback(self):
        """Unknown tools should still get a useful suggestion with install hint."""
        coll = MetricCollection(category="cpu", missing_tools=["nonexistent_tool"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert rec.metric == "nonexistent_tool"
        assert rec.severity == "info"
        # Should still include install commands
        assert "dnf" in rec.action or "apt-get" in rec.action
        # Should include search hint for unknown packages
        assert "search" in rec.action.lower() or "dnf" in rec.action

    def test_deduplication_across_categories(self):
        """Same tool missing from multiple categories should only appear once."""
        coll1 = MetricCollection(category="cpu", missing_tools=["sar"])
        coll2 = MetricCollection(category="network", missing_tools=["sar"])
        recs = generate_install_suggestions([coll1, coll2])
        sar_recs = [r for r in recs if r.metric == "sar"]
        assert len(sar_recs) == 1
        # But should mention both categories
        sar_rec = sar_recs[0]
        assert "cpu" in sar_rec.detail and "network" in sar_rec.detail

    def test_sorted_output(self):
        """Package-grouped output should be deterministic."""
        coll = MetricCollection(
            category="io",
            missing_tools=["vmstat", "iostat", "sar"]
        )
        recs = generate_install_suggestions([coll])
        # vmstat is its own package, iostat+sar are grouped as sysstat
        assert len(recs) == 2  # vmstat + sysstat group
        # Should have vmstat and sysstat group
        metrics = [r.metric for r in recs]
        assert "vmstat" in metrics
        # The sysstat group has metric like "sysstat/sysstat"
        assert any("sysstat" in m for m in metrics)

    def test_empty_missing_tools(self):
        """No missing tools should produce no suggestions."""
        coll = MetricCollection(category="cpu", metrics=[
            MetricResult(name="cpu_usage", value=50.0, unit="%", source="mpstat")
        ])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 0

    def test_all_known_tools_have_packages(self):
        """All tools used by collectors should have entries in TOOL_PACKAGES."""
        from linuxdoctor.collectors import TOOL_PACKAGES
        # These are the tools actually checked by collectors
        tools_used = ["mpstat", "sar", "perf", "iostat", "vmstat", "ss", "uptime"]
        for tool in tools_used:
            assert tool in TOOL_PACKAGES, f"Tool '{tool}' missing from TOOL_PACKAGES"

    def test_tool_packages_have_description(self):
        """All TOOL_PACKAGES entries should have description, categories, and metrics."""
        from linuxdoctor.collectors import TOOL_PACKAGES
        for tool, info in TOOL_PACKAGES.items():
            assert "dnf" in info, f"Tool '{tool}' missing dnf package"
            assert "apt_get" in info, f"Tool '{tool}' missing apt_get package"
            assert "description" in info, f"Tool '{tool}' missing description"
            assert "categories" in info, f"Tool '{tool}' missing categories"
            assert "metrics" in info, f"Tool '{tool}' missing metrics"

    def test_iostat_suggestion_content(self):
        """iostat suggestion should mention I/O metrics."""
        coll = MetricCollection(category="io", missing_tools=["iostat"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert "I/O" in rec.message or "io" in rec.message.lower()
        # Detail should include affected metrics
        assert "await" in rec.detail or "util" in rec.detail or "metrics" in rec.detail.lower()

    def test_sysstat_grouping(self):
        """Multiple tools from the same package should be grouped together."""
        coll = MetricCollection(
            category="cpu",
            missing_tools=["mpstat", "sar", "iostat", "pidstat"],
        )
        recs = generate_install_suggestions([coll])
        # All four tools come from sysstat, should be a single suggestion
        sysstat_recs = [r for r in recs if "sysstat" in r.metric]
        assert len(sysstat_recs) == 1
        rec = sysstat_recs[0]
        # Should list all the tools it provides
        assert "mpstat" in rec.message or "mpstat" in rec.detail
        assert "sar" in rec.message or "sar" in rec.detail
        assert "iostat" in rec.message or "iostat" in rec.detail
        # Action should mention sysstat package
        assert "sysstat" in rec.action
        assert "dnf" in rec.action
        assert "apt-get" in rec.action

    def test_unknown_tool_with_collection_category(self):
        """Unknown tools should include the collection category in the detail."""
        coll = MetricCollection(category="cpu", missing_tools=["some_unknown_tool"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert "cpu" in rec.detail  # Should mention the affected category
        # Action should include search hint for unknown packages
        assert "search" in rec.action or "apt-cache" in rec.action

    def test_platform_labels_in_action(self):
        """Install actions should clearly label Fedora/RHEL vs Debian/Ubuntu."""
        coll = MetricCollection(category="io", missing_tools=["iotop"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert "Fedora" in rec.action or "RHEL" in rec.action
        assert "Debian" in rec.action or "Ubuntu" in rec.action

    def test_detail_includes_description(self):
        """Known tools should include a description in the detail."""
        coll = MetricCollection(category="cpu", missing_tools=["mpstat"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert "Provides:" in rec.detail
        assert "CPU" in rec.detail  # mpstat description mentions CPU

    def test_detail_includes_categories(self):
        """Known tools should list affected categories in the detail."""
        coll = MetricCollection(category="cpu", missing_tools=["sar"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert "Affected categories" in rec.detail or "Affects" in rec.detail

    def test_detail_includes_metrics_enabled(self):
        """Known tools should list specific metrics that become available."""
        coll = MetricCollection(category="io", missing_tools=["iostat"])
        recs = generate_install_suggestions([coll])
        assert len(recs) == 1
        rec = recs[0]
        assert "Metrics enabled" in rec.detail

    def test_fallback_package_map(self):
        """The _UNKNOWN_TOOL_PACKAGES fallback should be used for tools not in TOOL_PACKAGES."""
        from linuxdoctor.recommendations import _get_pkg_info
        # lsof is not in TOOL_PACKAGES but should be in the fallback
        info = _get_pkg_info("lsof")
        assert info is not None
        assert "dnf" in info
        assert "apt_get" in info
        assert info["description"]  # should have a description

    def test_different_packages_not_grouped(self):
        """Tools from different packages should not be grouped together."""
        coll = MetricCollection(
            category="io",
            missing_tools=["iotop", "blktrace"],  # Different packages
        )
        recs = generate_install_suggestions([coll])
        assert len(recs) == 2  # Two separate suggestions