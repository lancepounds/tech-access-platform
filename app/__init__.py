
from flask import Flask
from app.extensions import db, ma
from app.auth.routes import auth_bp
from app.users.routes import users_bp
from app.companies.routes import companies_bp
from app.events.routes import events_bp
from app.main.routes import main_bp
import os


def create_app():
    app = Flask(__name__, template_folder='../templates')
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')
    app.secret_key = os.environ.get('SECRET_KEY', 'fallback-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions
    db.init_app(app)
    ma.init_app(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(companies_bp, url_prefix='/api/companies')
    app.register_blueprint(events_bp, url_prefix='/api/events')
    app.register_blueprint(main_bp)
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    return app
