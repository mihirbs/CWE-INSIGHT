# Author: Mihir Brijesh Solanki (40481948)
"""
CWE Insight — main Flask app setup.

Handles security headers, rate limiting, database init, and route registration.
No third-party security packages are used here — keeps dependencies minimal
and makes the security logic easy to read and audit.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Any

from flask import Flask, jsonify, request

from app.config import CONFIG_MAP, BaseConfig
from app.parsers.cwe_parser import init_db
from app.routes.analysis import analysis_bp
from app.routes.weaknesses import weaknesses_bp
from app.routes.ui import ui_bp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# tracks request timestamps per IP so we can enforce sliding-window rate limits
_rate_store: dict[str, list] = defaultdict(list)
_rate_lock = Lock()

_GLOBAL_LIMIT = 200    # 200 requests per hour per IP
_ANALYSIS_LIMIT = 10   # tighter limit for the analysis endpoint — those queries are heavy


def _check_rate_limit(ip: str, key: str, max_calls: int, window_seconds: int) -> bool:
    """Check if this IP is still within the allowed request count for the given time window.

    Returns True if the request should go through, False if the limit is hit.
    Uses a sliding window — old timestamps are dropped as time moves forward.
    Thread-safe via a lock, which is fine for a single-process setup.
    """
    now = time.time()
    store_key = f"{ip}:{key}"
    with _rate_lock:
        # drop timestamps that have fallen outside the window
        _rate_store[store_key] = [
            ts for ts in _rate_store[store_key] if now - ts < window_seconds
        ]
        if len(_rate_store[store_key]) >= max_calls:
            return False
        _rate_store[store_key].append(now)
    return True


def create_app(config_name: str = "default") -> Flask:
    """Build and return a configured Flask app.

    Pass a config name like 'development', 'testing', or 'production'.
    Defaults to 'default' which maps to development settings.
    """
    app = Flask(__name__)

    config_class: type[BaseConfig] = CONFIG_MAP.get(config_name, CONFIG_MAP["default"])
    app.config.from_object(config_class)

    @app.after_request
    def add_security_headers(response):
        """Attach security headers to every response.

        These are standard browser security controls. They tell the browser
        things like "don't let this page be embedded in an iframe" or
        "don't guess at the content type, trust what the server says".
        """
        # only allow loading resources from our own domain
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # tell browsers to use HTTPS only, for one year
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

    @app.before_request
    def enforce_rate_limits():
        """Block requests from IPs that are hitting the API too fast.

        Rate limiting is skipped during tests so they don't accidentally trip it.
        The analysis endpoint gets a tighter limit because its aggregation query
        is much heavier than a simple weakness lookup.
        """
        if app.config.get("TESTING"):
            return None

        ip = request.remote_addr or "unknown"

        if request.path.startswith("/api/v1/analysis/"):
            if not _check_rate_limit(ip, "analysis", _ANALYSIS_LIMIT, 60):
                return jsonify(
                    {"error": "Rate limit exceeded. Please slow down.", "code": 429}
                ), 429

        if not _check_rate_limit(ip, "global", _GLOBAL_LIMIT, 3600):
            return jsonify(
                {"error": "Rate limit exceeded. Please slow down.", "code": 429}
            ), 429

        return None

    db_path: str = app.config["DB_PATH"]
    xml_path: str = app.config["XML_PATH"]
    try:
        db_conn = init_db(db_path, xml_path)
        app.extensions["cwe_db"] = db_conn
    except Exception:
        logger.exception("Failed to initialise CWE database")
        app.extensions["cwe_db"] = None

    app.register_blueprint(ui_bp)
    app.register_blueprint(weaknesses_bp)
    app.register_blueprint(analysis_bp)

    _register_error_handlers(app)

    return app


def _register_error_handlers(app: Flask) -> None:
    """Set up JSON error responses for all common HTTP errors.

    Without this Flask would return an HTML error page, which can leak
    server details. JSON keeps things consistent and safe.
    """
    @app.errorhandler(400)
    def bad_request(e: Any):
        return jsonify({"error": "Bad request", "code": 400}), 400

    @app.errorhandler(404)
    def not_found(e: Any):
        return jsonify({"error": "Resource not found", "code": 404}), 404

    @app.errorhandler(405)
    def method_not_allowed(e: Any):
        return jsonify({"error": "Method not allowed", "code": 405}), 405

    @app.errorhandler(429)
    def rate_limit_exceeded(e: Any):
        return jsonify({"error": "Rate limit exceeded", "code": 429}), 429

    @app.errorhandler(500)
    def internal_server_error(e: Any):
        logger.exception("Internal server error")
        return jsonify({"error": "Internal server error", "code": 500}), 500
