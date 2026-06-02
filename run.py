# Author: Mihir Brijesh Solanki (40481948)
"""Entry point for the CWE Insight web app.

Reads FLASK_ENV to pick the right config (defaults to 'development').
Debug mode is controlled by the config, not hardcoded here.
"""
from __future__ import annotations

import os

from app import create_app

config_name = os.environ.get("FLASK_ENV", "development")
app = create_app(config_name)

if __name__ == "__main__":
    # only bind to localhost — not accessible from other machines by default
    app.run(host="127.0.0.1", port=5000, debug=app.config.get("DEBUG", False))
