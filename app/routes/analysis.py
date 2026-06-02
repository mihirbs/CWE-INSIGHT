# Author: Mihir Brijesh Solanki (40481948)
"""Analysis routes — the main insight feature of this app.

The consequence-platform matrix is something you can't get directly from the
CWE website. The CWE site shows weaknesses per platform, but doesn't aggregate
the CIA impact breakdown across all weaknesses for a given platform. That's
what this endpoint does — it cross-references platform data with consequence
data to produce a platform-level risk profile.

The analysis endpoint has a tighter rate limit (10/min) because the aggregation
query is computationally heavier than a simple weakness lookup.
"""
from __future__ import annotations

import logging
from collections import defaultdict

from flask import Blueprint, current_app, jsonify

logger = logging.getLogger(__name__)

analysis_bp = Blueprint("analysis", __name__, url_prefix="/api/v1/analysis")

# platforms to include in the matrix — common languages and environments
TARGET_PLATFORMS = [
    "C",
    "C++",
    "Java",
    "Python",
    "PHP",
    "JavaScript",
    ".NET",
    "Ruby",
    "Go",
    "Perl",
    "Web Based",
    "Windows",
    "Linux",
    "Android",
    "iOS",
]


@analysis_bp.route("/consequence-platform-matrix", methods=["GET"])
def consequence_platform_matrix():
    """Return a CIA consequence distribution matrix broken down by platform.

    For each platform (e.g. Java), shows the breakdown of Confidentiality,
    Integrity, and Availability impacts across all weaknesses that affect it,
    plus the top 3 highest-risk CWEs for that platform.

    Response shape:
        matrix     — platform -> scope -> impact -> {count, percentage}
        top_risks  — platform -> top 3 CWEs ranked by distinct consequence scopes
        metadata   — total weaknesses analysed, platforms included
    """
    db = current_app.extensions["cwe_db"]

    # Step 1: get all rows for our target platforms
    # placeholders are built from the list so the query stays parameterised
    placeholders = ",".join("?" for _ in TARGET_PLATFORMS)
    platform_rows = db.execute(
        f"SELECT cwe_id, name FROM platforms WHERE name IN ({placeholders})",  # noqa: S608
        TARGET_PLATFORMS,
    ).fetchall()

    # build a map: platform name -> set of CWE IDs
    platform_to_cwes: dict[str, set[int]] = defaultdict(set)
    for row in platform_rows:
        platform_to_cwes[row["name"]].add(row["cwe_id"])

    # Step 2: fetch all consequence rows at once (cheaper than per-weakness queries)
    consequence_rows = db.execute(
        "SELECT cwe_id, scope, impact FROM consequences"
    ).fetchall()

    # build a map: CWE ID -> list of (scope, impact) tuples
    cwe_to_consequences: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for row in consequence_rows:
        cwe_to_consequences[row["cwe_id"]].append((row["scope"], row["impact"]))

    # Step 3: build the matrix — platform -> scope -> impact -> count
    matrix: dict[str, dict[str, dict[str, int]]] = {}

    for platform in TARGET_PLATFORMS:
        cwe_ids = platform_to_cwes.get(platform, set())
        if not cwe_ids:
            continue

        scope_impact_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        total_consequence_entries = 0

        for cwe_id in cwe_ids:
            for scope, impact in cwe_to_consequences.get(cwe_id, []):
                if scope and impact:
                    scope_impact_counts[scope][impact] += 1
                    total_consequence_entries += 1

        # convert raw counts to percentages within each scope
        platform_matrix: dict[str, dict[str, dict[str, int | float]]] = {}
        for scope, impacts in scope_impact_counts.items():
            platform_matrix[scope] = {}
            scope_total = sum(impacts.values())
            for impact, count in impacts.items():
                pct = round((count / scope_total) * 100, 1) if scope_total else 0.0
                platform_matrix[scope][impact] = {
                    "count": count,
                    "percentage": pct,
                }

        matrix[platform] = platform_matrix  # type: ignore[assignment]

    # Step 4: find the top 3 riskiest CWEs per platform
    # ranked by how many distinct CIA scopes they affect (wider blast radius = higher risk)
    top_risks: dict[str, list[dict]] = {}

    weakness_name_cache: dict[int, str] = {}

    for platform in TARGET_PLATFORMS:
        cwe_ids = platform_to_cwes.get(platform, set())
        if not cwe_ids:
            continue

        scored: list[tuple[int, int, int]] = []  # (distinct_scope_count, cwe_id, consequence_count)
        for cwe_id in cwe_ids:
            consequences = cwe_to_consequences.get(cwe_id, [])
            distinct_scopes = len({scope for scope, _ in consequences})
            total_consequences = len(consequences)
            scored.append((distinct_scopes, total_consequences, cwe_id))

        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        top_3 = scored[:3]

        # fetch weakness names for the top CWEs, caching to avoid repeat queries
        top_risks[platform] = []
        for distinct_scopes, total_consequences, cwe_id in top_3:
            if cwe_id not in weakness_name_cache:
                row = db.execute(
                    "SELECT name, likelihood FROM weaknesses WHERE cwe_id = ?", (cwe_id,)
                ).fetchone()
                weakness_name_cache[cwe_id] = row["name"] if row else "Unknown"
                likelihood = row["likelihood"] if row else ""
            else:
                weakness_name_cache[cwe_id]
                row = db.execute(
                    "SELECT likelihood FROM weaknesses WHERE cwe_id = ?", (cwe_id,)
                ).fetchone()
                likelihood = row["likelihood"] if row else ""

            top_risks[platform].append(
                {
                    "cwe_id": cwe_id,
                    "name": weakness_name_cache[cwe_id],
                    "distinct_consequence_scopes": distinct_scopes,
                    "total_consequence_entries": total_consequences,
                    "likelihood_of_exploit": likelihood,
                }
            )

    # Step 5: attach metadata
    total_weaknesses: int = db.execute(
        "SELECT COUNT(*) FROM weaknesses"
    ).fetchone()[0]

    return jsonify(
        {
            "metadata": {
                "total_weaknesses_in_dataset": total_weaknesses,
                "platforms_analysed": sorted(matrix.keys()),
                "description": (
                    "CIA consequence distribution per platform, computed across all CWE weaknesses. "
                    "Percentages are within each consequence scope (CIA). "
                    "Top risks are ranked by number of distinct consequence scopes affected."
                ),
            },
            "matrix": matrix,
            "top_risks": top_risks,
        }
    ), 200
