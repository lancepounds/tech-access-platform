from flask import Flask
from app.extensions import db, ma, login_manager
from flask_wtf.csrf import CSRFProtect
import os


def create_app():
    app = Flask(__name__, template_folder='../templates')

    # Load configuration
    from config import DevelopmentConfig
    app.config.from_object(DevelopmentConfig)

    # Initialize extensions
    db.init_app(app)
    ma.init_app(app)
    login_manager.init_app(app)
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

    csrf.exempt(auth_bp)
    csrf.exempt(api_users_bp)
    csrf.exempt(users_bp)
    csrf.exempt(events_bp)
    csrf.exempt(companies_bp)
    csrf.exempt(categories_bp)
    csrf.exempt(checks_bp)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dash_bp)
    app.register_blueprint(events_bp, url_prefix='/api/events')
    app.register_blueprint(api_users_bp, url_prefix='/api/users')
    app.register_blueprint(users_bp)
    app.register_blueprint(companies_bp, url_prefix='/companies')
    app.register_blueprint(checks_bp, url_prefix='/checks')
    app.register_blueprint(categories_bp)
    app.register_blueprint(main_bp)

    # Create tables
    with app.app_context():
        db.create_all()

    return app