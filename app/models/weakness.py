# Author: Mihir Brijesh Solanki (40481948)
"""Data models for CWE weakness entries.

Frozen dataclasses mean the data can't be changed once created — useful
because parsed weaknesses get reused across requests and we don't want
one request accidentally affecting another's data.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Consequence:
    """One security impact entry for a weakness.

    CIA stands for Confidentiality, Integrity, Availability —
    the three main things a weakness can damage.
    """
    scope: str   # which part of CIA is affected, e.g. 'Confidentiality'
    impact: str  # what actually happens, e.g. 'Read Application Data'
    note: str = ""


@dataclass(frozen=True)
class Platform:
    """A language or technology where this weakness can show up."""
    platform_type: str  # 'Language', 'Technology', or 'Operating_System'
    name: str           # e.g. 'Python', 'Java', 'Web Based'
    prevalence: str = ""


@dataclass(frozen=True)
class DetectionMethod:
    """A way this weakness can be found in code."""
    method: str           # e.g. 'Manual Analysis', 'Automated Static Analysis'
    effectiveness: str = ""


@dataclass(frozen=True)
class Weakness:
    """Full details for a single CWE weakness entry."""

    cwe_id: int
    name: str
    abstraction: str  # how specific this weakness is: Class, Base, Variant, or Compound
    description: str
    extended_description: str
    likelihood_of_exploit: str  # High, Medium, Low, or empty if unknown
    consequences: tuple[Consequence, ...] = field(default_factory=tuple)
    platforms: tuple[Platform, ...] = field(default_factory=tuple)
    detection_methods: tuple[DetectionMethod, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for JSON responses."""
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "abstraction": self.abstraction,
            "description": self.description,
            "extended_description": self.extended_description,
            "likelihood_of_exploit": self.likelihood_of_exploit,
            "consequences": [
                {"scope": c.scope, "impact": c.impact, "note": c.note}
                for c in self.consequences
            ],
            "applicable_platforms": [
                {
                    "type": p.platform_type,
                    "name": p.name,
                    "prevalence": p.prevalence,
                }
                for p in self.platforms
            ],
            "detection_methods": [
                {"method": d.method, "effectiveness": d.effectiveness}
                for d in self.detection_methods
            ],
        }
