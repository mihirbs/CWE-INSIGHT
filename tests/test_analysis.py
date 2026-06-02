# Author: Mihir Brijesh Solanki (40481948)
"""Tests for GET /api/v1/analysis/consequence-platform-matrix.

Makes sure the response has the right shape and that the endpoint
behaves sensibly — only GET allowed, errors come back as JSON, data is consistent.
"""
from __future__ import annotations


class TestConsequencePlatformMatrix:
    """Tests for the platform-CIA consequence matrix endpoint."""

    def test_matrix_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        assert resp.status_code == 200

    def test_response_has_required_top_level_keys(self, client):
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        data = resp.get_json()
        assert "matrix" in data
        assert "top_risks" in data
        assert "metadata" in data

    def test_metadata_has_required_fields(self, client):
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        meta = resp.get_json()["metadata"]
        assert "total_weaknesses_in_dataset" in meta
        assert "platforms_analysed" in meta
        assert "description" in meta
        assert isinstance(meta["total_weaknesses_in_dataset"], int)
        assert meta["total_weaknesses_in_dataset"] > 0

    def test_analysis_endpoint_returns_expected_matrix_shape(self, client):
        """Matrix must map platform -> scope -> impact -> {count, percentage}."""
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        data = resp.get_json()
        matrix = data["matrix"]

        assert isinstance(matrix, dict), "Matrix must be a dict"

        for platform, scopes in matrix.items():
            assert isinstance(scopes, dict), f"Scopes for {platform} must be dict"
            for scope, impacts in scopes.items():
                assert isinstance(impacts, dict), f"Impacts for {platform}/{scope} must be dict"
                for impact, stats in impacts.items():
                    assert "count" in stats, f"Missing 'count' in {platform}/{scope}/{impact}"
                    assert "percentage" in stats, f"Missing 'percentage' in {platform}/{scope}/{impact}"
                    assert stats["count"] >= 0
                    assert 0.0 <= stats["percentage"] <= 100.0

    def test_top_risks_have_correct_structure(self, client):
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        top_risks = resp.get_json()["top_risks"]

        for platform, risks in top_risks.items():
            assert isinstance(risks, list)
            assert len(risks) <= 3, f"{platform} should have at most 3 top risks"
            for risk in risks:
                assert "cwe_id" in risk
                assert "name" in risk
                assert "distinct_consequence_scopes" in risk
                assert "total_consequence_entries" in risk
                assert isinstance(risk["cwe_id"], int)

    def test_top_risks_ordered_by_scope_count(self, client):
        """Top risks must be ordered descending by distinct_consequence_scopes."""
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        top_risks = resp.get_json()["top_risks"]

        for platform, risks in top_risks.items():
            scope_counts = [r["distinct_consequence_scopes"] for r in risks]
            assert scope_counts == sorted(scope_counts, reverse=True), (
                f"{platform} top risks not sorted by scope count: {scope_counts}"
            )

    def test_matrix_includes_known_platforms_from_seed(self, client):
        """Java, Python, PHP, JavaScript should appear (from seeded test data)."""
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        data = resp.get_json()
        all_platforms = set(data["matrix"].keys()) | set(data["top_risks"].keys())
        expected = {"Java", "Python", "PHP", "JavaScript", "Web Based"}
        # At least some of the expected platforms should be present
        assert len(expected & all_platforms) > 0, (
            f"No expected platforms found. Got: {all_platforms}"
        )

    def test_matrix_response_is_json(self, client):
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        assert resp.content_type.startswith("application/json")

    def test_post_method_not_allowed_on_analysis(self, client):
        resp = client.post("/api/v1/analysis/consequence-platform-matrix", json={})
        assert resp.status_code == 405
        assert resp.content_type.startswith("application/json")

    def test_unknown_route_returns_json_404(self, client):
        resp = client.get("/api/v1/analysis/nonexistent")
        assert resp.status_code == 404
        assert resp.content_type.startswith("application/json")

    def test_cia_scopes_present_in_matrix(self, client):
        """CIA scopes (Confidentiality, Integrity, Availability) should appear."""
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        matrix = resp.get_json()["matrix"]

        all_scopes: set[str] = set()
        for platform_data in matrix.values():
            all_scopes.update(platform_data.keys())

        cia = {"Confidentiality", "Integrity", "Availability"}
        assert len(cia & all_scopes) > 0, f"No CIA scopes found. Got: {all_scopes}"

    def test_sql89_is_high_risk_in_java(self, client):
        """CWE-89 (SQL Injection) should appear in Java top risks (from seed data)."""
        resp = client.get("/api/v1/analysis/consequence-platform-matrix")
        top_risks = resp.get_json()["top_risks"]

        if "Java" in top_risks:
            java_cwe_ids = [r["cwe_id"] for r in top_risks["Java"]]
            assert 89 in java_cwe_ids, f"CWE-89 not in Java top risks: {java_cwe_ids}"
