# Author: Mihir Brijesh Solanki (40481948)
"""
App configuration for different environments (development, testing, production).

Sensitive values like SECRET_KEY come from environment variables so nothing
secret is hardcoded here. Debug mode is always off in production.
"""
from __future__ import annotations

import os


class BaseConfig:
    """Shared defaults inherited by all environments."""

    # grab from env if set, otherwise generate a random one each startup
    SECRET_KEY: str = os.environ.get("SECRET_KEY", os.urandom(32).hex())

    # path to the CWE XML data file — override with CWE_XML_PATH env var
    XML_PATH: str = os.environ.get(
        "CWE_XML_PATH",
        os.path.join(os.path.dirname(__file__), "..", "data", "cwec_v4_19_1.xml"),
    )

    # SQLite database for caching parsed CWE data — override with CWE_DB_PATH
    DB_PATH: str = os.environ.get("CWE_DB_PATH", "cwe_cache.db")

    RATELIMIT_DEFAULT: str = "200 per day, 50 per hour"
    RATELIMIT_STORAGE_URI: str = "memory://"
    JSON_SORT_KEYS: bool = False
    TESTING: bool = False
    DEBUG: bool = False


class DevelopmentConfig(BaseConfig):
    """Local dev config — debug on, separate DB so we don't touch production data."""
    DEBUG: bool = True
    DB_PATH: str = "cwe_cache_dev.db"


class TestingConfig(BaseConfig):
    """Test config — uses an in-memory DB so tests are fast and don't leave files behind."""
    TESTING: bool = True
    DB_PATH: str = ":memory:"
    RATELIMIT_ENABLED: bool = False  # don't want rate limits tripping up tests


class ProductionConfig(BaseConfig):
    """Production config — debug and testing modes explicitly off."""
    DEBUG: bool = False
    TESTING: bool = False


CONFIG_MAP: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
