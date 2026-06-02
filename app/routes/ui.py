# Author: Mihir Brijesh Solanki (40481948)
"""Route to serve the HTML dashboard."""
from __future__ import annotations

from flask import Blueprint, render_template

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")
