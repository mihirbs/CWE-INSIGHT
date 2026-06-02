# Author: Mihir Brijesh Solanki (40481948)
"""One-time script to populate the CWE database cache.

Run this before starting the app for the first time, or whenever the
CWE XML data file is updated. It parses the XML and stores everything
in SQLite so the app doesn't have to re-parse the file on each startup.

Usage:
    python scripts/init_db.py

Set FLASK_ENV=production to use production database paths.
"""
from __future__ import annotations

import logging
import os
import sys

# add project root to path so the `app` package is importable from here
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import CONFIG_MAP
from app.parsers.cwe_parser import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    env = os.environ.get("FLASK_ENV", "development")
    config = CONFIG_MAP.get(env, CONFIG_MAP["default"])()
    db_path: str = config.DB_PATH
    xml_path: str = config.XML_PATH

    logger.info("Initialising database at: %s", db_path)
    logger.info("CWE XML source: %s", xml_path)

    conn = init_db(db_path, xml_path)
    count = conn.execute("SELECT COUNT(*) FROM weaknesses").fetchone()[0]
    logger.info("Database ready. Weaknesses cached: %d", count)
    conn.close()


if __name__ == "__main__":
    main()
