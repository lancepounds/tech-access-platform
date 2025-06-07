from flask import Blueprint

categories_bp = Blueprint('categories', __name__, url_prefix='/categories')

# Import routes after blueprint definition to avoid circular imports
from . import routes
