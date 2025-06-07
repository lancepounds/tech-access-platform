from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from apscheduler.schedulers.background import BackgroundScheduler
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail

db = SQLAlchemy()
bcrypt = Bcrypt()
ma = Marshmallow()
scheduler = BackgroundScheduler()
login_manager = LoginManager()
migrate = Migrate()
mail = Mail()
