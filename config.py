import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-secret-key')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
    STRIPE_MOCK = os.getenv("STRIPE_SECRET_KEY") is None
    JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-jwt-secret')
    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
    SENDGRID_MOCK = SENDGRID_API_KEY is None

    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your-username'
    MAIL_PASSWORD = 'your-password'
    MAIL_DEFAULT_SENDER = ('Tech Access', 'no-reply@techaccess.org')

    # JWT configuration
    JWT_SECRET_KEY = os.getenv("SECRET_KEY", 'fallback-secret-key')
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
    PASSWORD_RESET_TOKEN_EXPIRES_HOURS = 1


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}