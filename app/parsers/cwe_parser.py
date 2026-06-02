# Author: Mihir Brijesh Solanki (40481948)
"""CWE XML parser and SQLite caching layer.

A few design choices worth knowing about:

- We use defusedxml instead of Python's built-in xml.etree.ElementTree.
  The standard library parser is vulnerable to XXE attacks — an attacker
  could craft an XML file that makes the server read local files or
  exhaust memory. defusedxml blocks all of that by default.

- The XML file is parsed just once at startup and cached in SQLite.
  All subsequent queries go to the database, not back to the XML file.
  Parsing a 255k-line file on every request would be way too slow.

- All SQL queries use ? placeholders, never string formatting.
  That's what prevents SQL injection regardless of what input comes in.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

import defusedxml.ElementTree as ET  # noqa: N817 — replaces stdlib xml.etree.ElementTree

from app.models.weakness import Consequence, DetectionMethod, Platform, Weakness

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# XML namespace used in the CWE dataset — needed for all XPath lookups
_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

_CREATE_WEAKNESSES = """
CREATE TABLE IF NOT EXISTS weaknesses (
    cwe_id              INTEGER PRIMARY KEY,
    name                TEXT    NOT NULL,
    abstraction         TEXT    NOT NULL DEFAULT '',
    description         TEXT    NOT NULL DEFAULT '',
    extended_description TEXT   NOT NULL DEFAULT '',
    likelihood          TEXT    NOT NULL DEFAULT ''
)
"""

_CREATE_CONSEQUENCES = """
CREATE TABLE IF NOT EXISTS consequences (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id  INTEGER NOT NULL REFERENCES weaknesses(cwe_id),
    scope   TEXT    NOT NULL DEFAULT '',
    impact  TEXT    NOT NULL DEFAULT '',
    note    TEXT    NOT NULL DEFAULT ''
)
"""

_CREATE_PLATFORMS = """
CREATE TABLE IF NOT EXISTS platforms (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id        INTEGER NOT NULL REFERENCES weaknesses(cwe_id),
    platform_type TEXT    NOT NULL DEFAULT '',
    name          TEXT    NOT NULL DEFAULT '',
    prevalence    TEXT    NOT NULL DEFAULT ''
)
"""

_CREATE_DETECTION = """
CREATE TABLE IF NOT EXISTS detection_methods (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id        INTEGER NOT NULL REFERENCES weaknesses(cwe_id),
    method        TEXT    NOT NULL DEFAULT '',
    effectiveness TEXT    NOT NULL DEFAULT ''
)
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_weakness_likelihood ON weaknesses(likelihood)",
    "CREATE INDEX IF NOT EXISTS idx_weakness_abstraction ON weaknesses(abstraction)",
    "CREATE INDEX IF NOT EXISTS idx_platform_name ON platforms(name)",
]


def _get_text(element: ET.Element | None, path: str, ns: dict) -> str:  # type: ignore[type-arg]
    """Pull text out of an XML element at the given path. Returns '' if missing."""
    if element is None:
        return ""
    found = element.find(path, ns)
    if found is None or found.text is None:
        return ""
    return found.text.strip()


def _strip_ns(tag: str) -> str:
    """Remove the XML namespace prefix from a tag, e.g. '{http://...}Language' -> 'Language'."""
    return tag.split("}")[-1] if "}" in tag else tag


def _parse_weakness(elem: ET.Element) -> Weakness:  # type: ignore[type-arg]
    """Parse a single <Weakness> XML element into a Weakness object."""
    cwe_id = int(elem.attrib.get("ID", 0))
    name = elem.attrib.get("Name", "")
    abstraction = elem.attrib.get("Abstraction", "")

    description = _get_text(elem, "cwe:Description", _NS)
    extended_description = _get_text(elem, "cwe:Extended_Description", _NS)
    likelihood = _get_text(elem, "cwe:Likelihood_Of_Exploit", _NS)

    # --- Consequences ---
    consequences: list[Consequence] = []
    for cons_elem in elem.findall(".//cwe:Common_Consequences/cwe:Consequence", _NS):
        scope = _get_text(cons_elem, "cwe:Scope", _NS)
        impact = _get_text(cons_elem, "cwe:Impact", _NS)
        note = _get_text(cons_elem, "cwe:Note", _NS)
        if scope or impact:
            consequences.append(Consequence(scope=scope, impact=impact, note=note))

    # --- Platforms ---
    platforms: list[Platform] = []
    platforms_elem = elem.find("cwe:Applicable_Platforms", _NS)
    if platforms_elem is not None:
        for child in platforms_elem:
            tag = _strip_ns(child.tag)
            # tag is one of: Language, Technology, Operating_System, Architecture
            pname = child.attrib.get("Name") or child.attrib.get("Class", "")
            prevalence = child.attrib.get("Prevalence", "")
            if pname:
                platforms.append(
                    Platform(
                        platform_type=tag,
                        name=pname,
                        prevalence=prevalence,
                    )
                )

    # --- Detection Methods ---
    detection_methods: list[DetectionMethod] = []
    for dm_elem in elem.findall(".//cwe:Detection_Methods/cwe:Detection_Method", _NS):
        method = _get_text(dm_elem, "cwe:Method", _NS)
        effectiveness = _get_text(dm_elem, "cwe:Effectiveness", _NS)
        if method:
            detection_methods.append(
                DetectionMethod(method=method, effectiveness=effectiveness)
            )

    return Weakness(
        cwe_id=cwe_id,
        name=name,
        abstraction=abstraction,
        description=description,
        extended_description=extended_description,
        likelihood_of_exploit=likelihood,
        consequences=tuple(consequences),
        platforms=tuple(platforms),
        detection_methods=tuple(detection_methods),
    )


def _schema_up_to_date(conn: sqlite3.Connection) -> bool:
    """Return True if the weaknesses table already has data (so we can skip re-parsing)."""
    cursor = conn.execute("SELECT COUNT(*) FROM weaknesses")
    count: int = cursor.fetchone()[0]
    return count > 0


def init_db(db_path: str, xml_path: str) -> sqlite3.Connection:
    """Set up the SQLite cache from the CWE XML file.

    If the database already has data in it, XML parsing is skipped.
    We never import stdlib xml.etree.ElementTree here — defusedxml only.
    """
    conn = sqlite3.connect(
        db_path,
        check_same_thread=False,  # Flask may use multiple threads
        isolation_level=None,     # autocommit; we manage transactions manually
    )
    conn.row_factory = sqlite3.Row

    # create tables and indexes if they don't exist yet
    conn.execute(_CREATE_WEAKNESSES)
    conn.execute(_CREATE_CONSEQUENCES)
    conn.execute(_CREATE_PLATFORMS)
    conn.execute(_CREATE_DETECTION)
    for idx_sql in _CREATE_INDEXES:
        conn.execute(idx_sql)

    if _schema_up_to_date(conn):
        logger.info("CWE SQLite cache already populated — skipping XML parse")
        return conn

    logger.info("Parsing CWE XML dataset: %s", xml_path)
    xml_file = Path(xml_path)
    if not xml_file.exists():
        raise FileNotFoundError(f"CWE XML file not found: {xml_path}")

    # defusedxml.ElementTree.parse() is used here — NEVER xml.etree.ElementTree
    # This prevents XXE, entity expansion DoS, and external DTD loading.
    tree = ET.parse(str(xml_file))  # type: ignore[attr-defined]
    root = tree.getroot()

    weaknesses_elem = root.find("cwe:Weaknesses", _NS)
    if weaknesses_elem is None:
        raise ValueError("CWE XML missing <Weaknesses> root element")

    parsed: list[Weakness] = []
    for weakness_elem in weaknesses_elem.findall("cwe:Weakness", _NS):
        try:
            parsed.append(_parse_weakness(weakness_elem))
        except Exception:
            logger.exception("Failed to parse weakness element — skipping")

    logger.info("Parsed %d weaknesses; writing to SQLite cache", len(parsed))

    conn.execute("BEGIN")
    try:
        for w in parsed:
            conn.execute(
                "INSERT OR REPLACE INTO weaknesses VALUES (?,?,?,?,?,?)",
                (
                    w.cwe_id,
                    w.name,
                    w.abstraction,
                    w.description,
                    w.extended_description,
                    w.likelihood_of_exploit,
                ),
            )
            for c in w.consequences:
                conn.execute(
                    "INSERT INTO consequences (cwe_id, scope, impact, note) VALUES (?,?,?,?)",
                    (w.cwe_id, c.scope, c.impact, c.note),
                )
            for p in w.platforms:
                conn.execute(
                    "INSERT INTO platforms (cwe_id, platform_type, name, prevalence) VALUES (?,?,?,?)",
                    (w.cwe_id, p.platform_type, p.name, p.prevalence),
                )
            for d in w.detection_methods:
                conn.execute(
                    "INSERT INTO detection_methods (cwe_id, method, effectiveness) VALUES (?,?,?)",
                    (w.cwe_id, d.method, d.effectiveness),
                )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    logger.info("SQLite cache populated successfully")
    return conn


def get_weakness_by_id(conn: sqlite3.Connection, cwe_id: int) -> Weakness | None:
    """Look up a single weakness by its numeric ID. Returns None if not found."""
    row = conn.execute(
        "SELECT * FROM weaknesses WHERE cwe_id = ?", (cwe_id,)
    ).fetchone()
    if row is None:
        return None
    return _row_to_weakness(conn, row)


def search_weaknesses(
    conn: sqlite3.Connection,
    platform: str | None = None,
    likelihood: str | None = None,
    abstraction: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[Weakness], int]:
    """Search weaknesses with optional filters. Returns (results, total_count).

    All filter values are passed as SQL bound parameters — no string formatting
    is used in the query, so SQL injection isn't possible here.
    """
    conditions: list[str] = []
    params: list[str | int] = []

    base_query = "SELECT DISTINCT w.* FROM weaknesses w"
    count_query = "SELECT COUNT(DISTINCT w.cwe_id) FROM weaknesses w"

    if platform:
        base_query += " JOIN platforms p ON p.cwe_id = w.cwe_id"
        count_query += " JOIN platforms p ON p.cwe_id = w.cwe_id"
        conditions.append("LOWER(p.name) LIKE ?")
        params.append(f"%{platform.lower()}%")

    if likelihood:
        conditions.append("w.likelihood = ?")
        params.append(likelihood)

    if abstraction:
        conditions.append("w.abstraction = ?")
        params.append(abstraction)

    where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    base_query += where_clause + " LIMIT ? OFFSET ?"
    count_query += where_clause

    total: int = conn.execute(count_query, params).fetchone()[0]
    rows = conn.execute(base_query, params + [limit, offset]).fetchall()

    weaknesses = [_row_to_weakness(conn, row) for row in rows]
    return weaknesses, total


def _row_to_weakness(conn: sqlite3.Connection, row: sqlite3.Row) -> Weakness:
    """Rebuild a full Weakness object from a database row, including related data."""
    cwe_id: int = row["cwe_id"]

    cons_rows = conn.execute(
        "SELECT scope, impact, note FROM consequences WHERE cwe_id = ?", (cwe_id,)
    ).fetchall()
    consequences = tuple(
        Consequence(scope=r["scope"], impact=r["impact"], note=r["note"])
        for r in cons_rows
    )

    plat_rows = conn.execute(
        "SELECT platform_type, name, prevalence FROM platforms WHERE cwe_id = ?", (cwe_id,)
    ).fetchall()
    platforms = tuple(
        Platform(platform_type=r["platform_type"], name=r["name"], prevalence=r["prevalence"])
        for r in plat_rows
    )

    dm_rows = conn.execute(
        "SELECT method, effectiveness FROM detection_methods WHERE cwe_id = ?", (cwe_id,)
    ).fetchall()
    detection_methods = tuple(
        DetectionMethod(method=r["method"], effectiveness=r["effectiveness"])
        for r in dm_rows
    )

    return Weakness(
        cwe_id=cwe_id,
        name=row["name"],
        abstraction=row["abstraction"],
        description=row["description"],
        extended_description=row["extended_description"],
        likelihood_of_exploit=row["likelihood"],
        consequences=consequences,
        platforms=platforms,
        detection_methods=detection_methods,
    )
