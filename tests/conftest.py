# Author: Mihir Brijesh Solanki (40481948)
"""Pytest setup — shared fixtures and test database seeding.

Tests run against an in-memory SQLite database so they're fast and don't
touch any real files. A small handful of known weaknesses are inserted at
startup so the tests have predictable data to work with.
"""
from __future__ import annotations

import sqlite3

import pytest

from app import create_app


def _seed_test_db(conn: sqlite3.Connection) -> None:
    """Insert a minimal set of known test data into the in-memory database."""
    conn.execute("BEGIN")

    # Weaknesses
    test_weaknesses = [
        (79, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Base", "XSS description", "Extended XSS description", "High"),
        (89, "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Base", "SQL injection description", "", "High"),
        (22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "Base", "Path traversal description", "", "Medium"),
        (200, "Exposure of Sensitive Information to an Unauthorized Actor", "Class", "Info disclosure description", "", "Medium"),
        (502, "Deserialization of Untrusted Data", "Base", "Deserialization description", "", "High"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO weaknesses VALUES (?,?,?,?,?,?)",
        test_weaknesses,
    )

    # Consequences
    test_consequences = [
        (79, "Confidentiality", "Read Application Data", "XSS can steal cookies"),
        (79, "Integrity", "Execute Unauthorized Code or Commands", "XSS can inject scripts"),
        (89, "Confidentiality", "Read Application Data", "SQL injection can dump DB"),
        (89, "Integrity", "Modify Application Data", "SQL injection can update DB"),
        (89, "Availability", "DoS: Crash, Exit, or Restart", "SQL injection can drop tables"),
        (22, "Confidentiality", "Read Application Data", "Path traversal reads arbitrary files"),
        (200, "Confidentiality", "Read Application Data", "Sensitive data exposed"),
        (502, "Integrity", "Execute Unauthorized Code or Commands", "Remote code execution"),
        (502, "Availability", "DoS: Crash, Exit, or Restart", "Malformed input can crash"),
    ]
    conn.executemany(
        "INSERT INTO consequences (cwe_id, scope, impact, note) VALUES (?,?,?,?)",
        test_consequences,
    )

    # Platforms
    test_platforms = [
        (79, "Language", "JavaScript", "Often"),
        (79, "Technology", "Web Based", "Often"),
        (89, "Language", "PHP", "Often"),
        (89, "Language", "Java", "Sometimes"),
        (22, "Language", "Python", "Sometimes"),
        (22, "Language", "PHP", "Often"),
        (200, "Language", "Not Language-Specific", "Undetermined"),
        (502, "Language", "Java", "Often"),
        (502, "Language", "Python", "Sometimes"),
    ]
    conn.executemany(
        "INSERT INTO platforms (cwe_id, platform_type, name, prevalence) VALUES (?,?,?,?)",
        test_platforms,
    )

    # Detection methods
    test_detection = [
        (79, "Automated Static Analysis", "High"),
        (89, "Automated Static Analysis", "High"),
        (89, "Manual Review", "Medium"),
        (22, "Automated Static Analysis", "Medium"),
    ]
    conn.executemany(
        "INSERT INTO detection_methods (cwe_id, method, effectiveness) VALUES (?,?,?)",
        test_detection,
    )

    conn.execute("COMMIT")


@pytest.fixture(scope="session")
def app():
    """Create a test Flask application with a seeded in-memory database."""
    flask_app = create_app("testing")

    # The testing config sets DB_PATH=':memory:' which means init_db creates
    # empty tables. We seed known test data here.
    db_conn = flask_app.extensions["cwe_db"]
    _seed_test_db(db_conn)

    yield flask_app


@pytest.fixture(scope="session")
def client(app):
    """Return a Flask test client for HTTP request simulation."""
    return app.test_client()
