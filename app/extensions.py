from apscheduler.schedulers.background import BackgroundScheduler
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
bcrypt = Bcrypt()
ma = Marshmallow()
scheduler = BackgroundScheduler()