# Author: Mihir Brijesh Solanki (40481948)
from app.routes.analysis import analysis_bp
from app.routes.weaknesses import weaknesses_bp
from app.routes.ui import ui_bp

__all__ = ["weaknesses_bp", "analysis_bp", "ui_bp"]
