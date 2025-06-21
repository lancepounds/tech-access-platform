from flask import Flask, render_template
from app.extensions import db, ma, login_manager, migrate, mail, limiter # Import limiter
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import os


from config import config # Import the config dictionary

def create_app(config_name=None):
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'default')

    app = Flask(__name__, template_folder='../templates')

    # Load configuration using the provided name or default
    app.config.from_object(config[config_name]()) # Instantiates the config class

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

    # Import models BEFORE initializing db and migrate
    from app import models

    # Initialize extensions
    db.init_app(app)
    ma.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # Configure rate limiter (Standard Limiter)
    # RATELIMIT_STORAGE_URL is still useful for standard Limiter if not set in constructor
    app.config.setdefault('RATELIMIT_STORAGE_URL', 'memory://')
    app.config.setdefault('RATELIMIT_STRATEGY', 'fixed-window') # Can also be useful

    if app.config.get('TESTING'):
        app.config['RATELIMIT_ENABLED'] = False
    else:
        app.config['RATELIMIT_ENABLED'] = True
        app.config.setdefault('RATELIMIT_DEFAULT', '200 per day;60 per hour')

    limiter.init_app(app) # Always call init_app for standard Limiter

    app.mail = mail
    login_manager.login_view = 'auth.login'
    # User model is already imported via `from app import models`
    # from app.models import User # This line can be removed or commented out

    @login_manager.user_loader
    def load_user(user_id: str):
        return models.User.query.get(user_id) # Use models.User
    
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
    from app.admin import admin_bp as admin_blueprint # Import admin blueprint

    # csrf.exempt(auth_bp) # Protected by default
    # csrf.exempt(api_users_bp) # Potentially exempt if pure API and token auth
    # csrf.exempt(users_bp) # Protected by default
    # csrf.exempt(events_bp) # Potentially exempt if pure API and token auth
    # csrf.exempt(companies_bp) # Protected by default
    # csrf.exempt(categories_bp) # Protected by default
    # csrf.exempt(checks_bp) # Protected by default
    # csrf.exempt(main_bp) # Protected by default
    
    # Exempt API blueprint if it's purely token-based
    csrf.exempt(api_bp)
    # api_users_bp and events_bp might also need exemption if they are purely token-based APIs.
    # For now, let's assume they might have session-based interaction points or need protection.
    # If issues arise, these can be exempted later.
    # csrf.exempt(api_users_bp)
    # csrf.exempt(events_bp)


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
    app.register_blueprint(admin_blueprint) # Register admin blueprint

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