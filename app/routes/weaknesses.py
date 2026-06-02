# Author: Mihir Brijesh Solanki (40481948)
"""Routes for the /api/v1/weaknesses endpoints.

Provides two endpoints: fetch a weakness by ID, or search/filter weaknesses
by platform, likelihood, and abstraction level.
"""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify
from flask import request as flask_request

from app.parsers.cwe_parser import get_weakness_by_id, search_weaknesses
from app.validators.schemas import ValidationError, validate_cwe_id, validate_search_params

logger = logging.getLogger(__name__)

weaknesses_bp = Blueprint("weaknesses", __name__, url_prefix="/api/v1/weaknesses")


@weaknesses_bp.route("/<int:cwe_id>", methods=["GET"])
def get_weakness(cwe_id: int):
    """Return full details for a single CWE weakness by its numeric ID.

    Returns 400 if the ID is out of the valid range, 404 if it doesn't exist.
    """
    try:
        validated_id = validate_cwe_id(cwe_id)
    except ValidationError as exc:
        return jsonify({"error": "Validation failed", "details": exc.messages}), 400

    db = current_app.extensions["cwe_db"]
    weakness = get_weakness_by_id(db, validated_id)

    if weakness is None:
        return jsonify({"error": "CWE not found", "code": 404}), 404

    return jsonify(weakness.to_dict()), 200


@weaknesses_bp.route("/search", methods=["GET"])
def search():
    """Search weaknesses by platform, likelihood, and/or abstraction level.

    All parameters are optional. Results are paginated.

    Query params:
        platform   — partial, case-insensitive match on platform name
        likelihood — exact match: High, Medium, or Low
        abstraction — exact match: Class, Base, Variant, or Compound
        limit      — max results to return (default 20, max 100)
        offset     — how many results to skip for pagination (default 0)
    """
    try:
        params = validate_search_params(dict(flask_request.args))
    except ValidationError as exc:
        return jsonify({"error": "Validation failed", "details": exc.messages}), 400

    db = current_app.extensions["cwe_db"]
    weaknesses, total = search_weaknesses(
        db,
        platform=params.get("platform"),
        likelihood=params.get("likelihood"),
        abstraction=params.get("abstraction"),
        limit=params["limit"],
        offset=params["offset"],
    )

    return jsonify({
        "total": total,
        "limit": params["limit"],
        "offset": params["offset"],
        "results": [w.to_dict() for w in weaknesses],
    }), 200
