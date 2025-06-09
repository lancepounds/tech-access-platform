from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from apscheduler.schedulers.background import BackgroundScheduler
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from flask_limiter import Limiter # Reverted to standard Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
bcrypt = Bcrypt()
ma = Marshmallow()
scheduler = BackgroundScheduler()
login_manager = LoginManager()
migrate = Migrate()
mail = Mail()
# storage_uri will be set via app.config during init_app, or use default
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
