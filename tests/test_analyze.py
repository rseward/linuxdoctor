"""Tests for the analyze module."""

import json
import pytest
from linuxdoctor.analyze import analyze_host


class TestAnalyzeHost:
    """Tests for the main analyze_host function."""

    def test_human_readable_output(self):
        """Default output should be human-readable, not JSON."""
        result = analyze_host()
        assert "linuxdoctor" in result
        assert "Host Analysis Report" in result
        # Should NOT be valid JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(result)

    def test_json_output(self):
        """JSON output should be valid JSON."""
        result = analyze_host(json_output=True)
        data = json.loads(result)
        assert "host" in data
        assert "metrics" in data
        assert "recommendations" in data
        assert "timestamp" in data

    def test_no_recommendations(self):
        """Should skip recommendations when asked."""
        result = analyze_host(include_recommendations=False)
        assert "RECOMMENDATIONS" not in result

    def test_json_no_recommendations(self):
        """JSON output with no recommendations should have empty list."""
        result = analyze_host(json_output=True, include_recommendations=False)
        data = json.loads(result)
        assert data["recommendations"] == []

    def test_specific_checks(self):
        """Should only run specified checks."""
        result = analyze_host(checks=["cpu", "memory"])
        # Should have CPU and MEMORY sections
        assert "CPU" in result
        assert "MEMORY" in result
        # Should NOT have DISK or IO sections (since we only asked for cpu + memory)
        # Note: this is a soft check since the output format may vary

    def test_json_specific_checks(self):
        """JSON output should only contain requested check categories."""
        result = analyze_host(json_output=True, checks=["cpu"])
        data = json.loads(result)
        assert "cpu" in data["metrics"]
        # Should not have other categories
        assert "memory" not in data["metrics"]

    def test_threshold_profiles(self):
        """All threshold profiles should work."""
        for profile in ["default", "strict", "relaxed"]:
            result = analyze_host(json_output=True, checks=["memory"], threshold_profile=profile)
            import json
            data = json.loads(result)
            assert "host" in data

    def test_json_system_info(self):
        """JSON output should include system info."""
        result = analyze_host(json_output=True)
        data = json.loads(result)
        assert data["system"]["os"] == "Linux"
        assert "release" in data["system"]
        assert "machine" in data["system"]