from flask import Flask, render_template
from app.extensions import db, ma, login_manager, migrate, mail, limiter # Import limiter
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import os


def create_app():
    app = Flask(__name__, template_folder='../templates')

    # Load configuration
    from config import DevelopmentConfig
    app.config.from_object(DevelopmentConfig)

    # Initialize Talisman with default CSP
    Talisman(app)

    # Configure session cookie security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    if not app.debug and not app.testing:
        app.config['SESSION_COOKIE_SECURE'] = True

    # Set max content length for file uploads (e.g., 5MB)
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

    # Suppress sending emails by default (tests override if needed)
    app.config.setdefault('MAIL_SUPPRESS_SEND', True)

    # Initialize extensions
    db.init_app(app)
    ma.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    limiter.init_app(app) # Initialize limiter
    # Set global limits directly on the limiter instance
    # limiter.global_limits = ["200 per day", "60 per hour"] # This is an alternative to app.config
    app.config['RATELIMIT_DEFAULT'] = '200 per day;60 per hour' # Using app.config

    app.mail = mail
    login_manager.login_view = 'auth.login'
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id: str):
        return User.query.get(user_id)
    
    # Initialize CSRF protection
    csrf = CSRFProtect()
    csrf.init_app(app)
    
    # Initialize Supabase
    from supabase import create_client
    if app.config.get('SUPABASE_URL') and app.config.get('SUPABASE_KEY'):
        supabase = create_client(
            app.config['SUPABASE_URL'],
            app.config['SUPABASE_KEY']
        )
        app.supabase = supabase
    else:
        app.supabase = None

    from flask_bcrypt import Bcrypt
    from flask_jwt_extended import JWTManager

    # initialize extensions
    bcrypt = Bcrypt(app)
    jwt = JWTManager(app)

    # attach to app context if you like
    app.bcrypt = bcrypt
    app.jwt = jwt

    # Initialize scheduler
    from app.tasks import initialize_scheduler
    initialize_scheduler(app)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.users.routes import api_users_bp
    from app.users import users_bp
    from app.companies.routes import companies_bp
    from app.events.routes import evt_bp as events_bp
    from app.categories import categories_bp
    from app.main.routes import main_bp
    from app.checks.routes import checks_bp
    from app.dashboard.routes import dash_bp
    from app.api import api_bp

    csrf.exempt(auth_bp)
    csrf.exempt(api_users_bp)
    csrf.exempt(users_bp)
    csrf.exempt(events_bp)
    csrf.exempt(companies_bp)
    csrf.exempt(categories_bp)
    csrf.exempt(checks_bp)
    csrf.exempt(main_bp)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dash_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(events_bp, url_prefix='/api/events')
    app.register_blueprint(api_users_bp, url_prefix='/api/users')
    app.register_blueprint(users_bp)
    app.register_blueprint(companies_bp, url_prefix='/companies')
    app.register_blueprint(checks_bp, url_prefix='/checks')
    app.register_blueprint(categories_bp)
    app.register_blueprint(main_bp)

    # Register CLI commands
    from app.users.cli import grant_admin_command
    app.cli.add_command(grant_admin_command)

    # Create tables
    with app.app_context():
        db.create_all()

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def server_error(error):
        return render_template('500.html'), 500

    return app