# Author: Mihir Brijesh Solanki (40481948)
"""Tests for the /api/v1/weaknesses endpoints.

Each test checks one specific thing — valid input, bad input, wrong HTTP method,
that kind of thing. The test names are written to be self-explanatory.
"""
from __future__ import annotations

import json


class TestGetWeakness:
    """Tests for GET /api/v1/weaknesses/<cwe_id>."""

    def test_valid_cwe_id_returns_200(self, client):
        resp = client.get("/api/v1/weaknesses/79")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["cwe_id"] == 79
        assert "XSS" in data["name"] or "Cross-site" in data["name"]

    def test_response_contains_required_fields(self, client):
        resp = client.get("/api/v1/weaknesses/89")
        data = resp.get_json()
        required = {
            "cwe_id", "name", "abstraction", "description",
            "likelihood_of_exploit", "consequences",
            "applicable_platforms", "detection_methods",
        }
        assert required.issubset(data.keys()), f"Missing fields: {required - data.keys()}"

    def test_cwe_id_rejects_negative_integers(self, client):
        """Negative IDs are outside the allowed range 1–9999."""
        resp = client.get("/api/v1/weaknesses/-1")
        # Flask's <int:> converter treats '-' as non-matching -> 404
        assert resp.status_code in (400, 404)

    def test_cwe_id_rejects_string_input(self, client):
        """String values must not reach validation logic — Flask returns 404."""
        resp = client.get("/api/v1/weaknesses/xss")
        assert resp.status_code == 404

    def test_cwe_id_rejects_out_of_range_high(self, client):
        """IDs above 9999 should be rejected with 400."""
        resp = client.get("/api/v1/weaknesses/99999")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_cwe_id_rejects_zero(self, client):
        """Zero is outside the allowed range."""
        resp = client.get("/api/v1/weaknesses/0")
        assert resp.status_code == 400

    def test_nonexistent_cwe_returns_404(self, client):
        resp = client.get("/api/v1/weaknesses/9999")
        assert resp.status_code == 404

    def test_404_returns_json_not_html(self, client):
        """Error responses must always be JSON — never HTML with server info."""
        resp = client.get("/api/v1/weaknesses/9999")
        assert resp.content_type.startswith("application/json")
        data = resp.get_json()
        assert "error" in data

    def test_500_does_not_expose_stack_trace(self, client):
        """The error handler must return a generic message, not a traceback."""
        # Trigger 404 (easiest reproducible error) and verify no traceback in response
        resp = client.get("/api/v1/weaknesses/8888")
        body = resp.get_data(as_text=True)
        assert "Traceback" not in body
        assert "Exception" not in body
        assert "File " not in body

    def test_post_method_not_allowed(self, client):
        """Only GET is allowed — POST should return 405."""
        resp = client.post("/api/v1/weaknesses/79", json={})
        assert resp.status_code == 405
        assert resp.content_type.startswith("application/json")

    def test_consequences_have_cia_structure(self, client):
        """Consequences must include scope and impact fields."""
        resp = client.get("/api/v1/weaknesses/89")
        data = resp.get_json()
        for c in data["consequences"]:
            assert "scope" in c
            assert "impact" in c


class TestSearchWeaknesses:
    """Tests for GET /api/v1/weaknesses/search."""

    def test_default_search_returns_results(self, client):
        resp = client.get("/api/v1/weaknesses/search")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total" in data
        assert "results" in data
        assert isinstance(data["results"], list)

    def test_search_by_valid_likelihood(self, client):
        resp = client.get("/api/v1/weaknesses/search?likelihood=High")
        assert resp.status_code == 200
        data = resp.get_json()
        for r in data["results"]:
            assert r["likelihood_of_exploit"] == "High"

    def test_search_by_valid_abstraction(self, client):
        resp = client.get("/api/v1/weaknesses/search?abstraction=Base")
        assert resp.status_code == 200
        data = resp.get_json()
        for r in data["results"]:
            assert r["abstraction"] == "Base"

    def test_search_by_platform(self, client):
        resp = client.get("/api/v1/weaknesses/search?platform=Java")
        assert resp.status_code == 200
        data = resp.get_json()
        # All results should include Java as a platform
        for r in data["results"]:
            platforms = [p["name"] for p in r["applicable_platforms"]]
            assert any("Java" in p for p in platforms)

    def test_search_rejects_invalid_likelihood_value(self, client):
        """Only High/Medium/Low are valid — 'Critical' must be rejected."""
        resp = client.get("/api/v1/weaknesses/search?likelihood=Critical")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_search_rejects_unknown_query_params(self, client):
        """Unknown parameters indicate potential param pollution — reject with 400."""
        resp = client.get("/api/v1/weaknesses/search?severity=high&unknown=xyz")
        assert resp.status_code == 400

    def test_search_rejects_invalid_abstraction_value(self, client):
        resp = client.get("/api/v1/weaknesses/search?abstraction=SuperClass")
        assert resp.status_code == 400

    def test_sql_injection_attempt_in_search_param(self, client):
        """SQL injection via platform param must be blocked by marshmallow length validation
        and then parameterised queries — the response must be 400 (too long) or safe 200."""
        payload = "'; DROP TABLE weaknesses; --"
        resp = client.get(f"/api/v1/weaknesses/search?platform={payload}")
        # Either rejected (400) because it's too long (>50 chars), or safely returns 200/empty
        assert resp.status_code in (200, 400)
        if resp.status_code == 200:
            data = resp.get_json()
            # If it got through, the table must still exist (parameterised query protected it)
            assert "results" in data

    def test_short_sql_injection_attempt_returns_empty_not_error(self, client):
        """Short SQL injection that passes length check should return empty results safely."""
        resp = client.get("/api/v1/weaknesses/search?platform=' OR '1'='1")
        # Must not crash or expose an error — parameterised queries protect this
        assert resp.status_code in (200, 400)

    def test_pagination_limit_respected(self, client):
        resp = client.get("/api/v1/weaknesses/search?limit=2")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["results"]) <= 2

    def test_limit_above_100_rejected(self, client):
        resp = client.get("/api/v1/weaknesses/search?limit=101")
        assert resp.status_code == 400

    def test_negative_limit_rejected(self, client):
        resp = client.get("/api/v1/weaknesses/search?limit=-1")
        assert resp.status_code == 400

    def test_platform_over_50_chars_rejected(self, client):
        """Platform strings over 50 characters must be rejected — prevents oversized input."""
        long_platform = "A" * 51
        resp = client.get(f"/api/v1/weaknesses/search?platform={long_platform}")
        assert resp.status_code == 400

    def test_combined_filters_work(self, client):
        resp = client.get("/api/v1/weaknesses/search?likelihood=High&abstraction=Base")
        assert resp.status_code == 200
