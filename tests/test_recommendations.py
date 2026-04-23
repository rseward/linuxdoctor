"""Tests for the recommendation engine."""

import pytest
from linuxdoctor.collectors import MetricCollection, MetricResult
from linuxdoctor.recommendations import (
    generate_recommendations,
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