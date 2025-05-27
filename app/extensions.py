from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
bcrypt = Bcrypt()
ma = Marshmallow()
scheduler = BackgroundScheduler()