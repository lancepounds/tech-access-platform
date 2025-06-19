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
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'your-username')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'your-password')
    _mail_default_sender_name = os.environ.get('MAIL_DEFAULT_SENDER_NAME', 'Tech Access')
    _mail_default_sender_email = os.environ.get('MAIL_DEFAULT_SENDER_EMAIL', 'no-reply@techaccess.org')
    MAIL_DEFAULT_SENDER = (_mail_default_sender_name, _mail_default_sender_email)

    # JWT configuration
    # JWT_SECRET_KEY will use SECRET_KEY's value if JWT_SECRET_KEY env var is not set
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
    PASSWORD_RESET_TOKEN_EXPIRES_HOURS = 1


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    TESTING = True # Common for a testing config

    def __init__(self):
        super().__init__() # Ensure Config's attributes are loaded if it had an __init__

        # Check for insecure default values for critical settings
        if self.SECRET_KEY == 'fallback-secret-key':
            raise ValueError("PRODUCTION ERROR: SECRET_KEY is not set or is using an insecure default. Set a strong SECRET_KEY environment variable.")

        # self.JWT_SECRET_KEY would have resolved using self.SECRET_KEY if JWT_SECRET_KEY env var was not set.
        # So, if self.JWT_SECRET_KEY is the fallback, it means either it was explicitly set to that (unlikely)
        # or it defaulted to self.SECRET_KEY which is the fallback.
        if self.JWT_SECRET_KEY == 'fallback-secret-key':
            raise ValueError("PRODUCTION ERROR: JWT_SECRET_KEY is not set, is set to a fallback, or is derived from an insecure SECRET_KEY. Set a strong JWT_SECRET_KEY environment variable.")

        if self.SQLALCHEMY_DATABASE_URI == 'sqlite:///:memory:':
            raise ValueError("PRODUCTION ERROR: SQLALCHEMY_DATABASE_URI is using the in-memory SQLite default. Set a proper DATABASE_URL environment variable for production.")

        # Check for missing essential keys that must be set (cannot be None or empty string)
        # These keys do not have fallbacks or their fallbacks are not inherently insecure but they must be explicitly set for production.
        essential_prod_keys = ['STRIPE_SECRET_KEY', 'SUPABASE_URL', 'SUPABASE_KEY']

        if not self.SENDGRID_MOCK: # If SendGrid is the intended mailer (not mocked)
            essential_prod_keys.append('SENDGRID_API_KEY')
        else: # If SendGrid is mocked (meaning basic SMTP is the fallback)
            # Check if basic SMTP settings are still their placeholder example values
            if self.MAIL_SERVER == 'smtp.example.com' or \
               self.MAIL_USERNAME == 'your-username' or \
               self.MAIL_PASSWORD == 'your-password':
                raise ValueError("PRODUCTION ERROR: Basic SMTP mail settings are using placeholder values (e.g., 'smtp.example.com', 'your-username'). If not using SendGrid, configure these MAIL_* environment variables for production.")

        for key in essential_prod_keys:
            if not getattr(self, key, None): # getattr with default None to handle if key somehow wasn't defined in Config
                raise ValueError(f"PRODUCTION ERROR: Essential configuration variable '{key}' is not set. It must be set via an environment variable for production.")


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
# Important: When using these configurations, instantiate the class:
# Example: app.config.from_object(config[os.getenv('FLASK_ENV', 'default')]())
# The parentheses () after the class runs the __init__ method, enabling these checks.


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL', 'sqlite:///:memory:')
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key' # Override for predictable test sessions
    # Disable real emails and rate limits during tests
    MAIL_SUPPRESS_SEND = True
    RATELIMIT_ENABLED = False
    DEBUG = True # Often useful for debugging test failures


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig, # Added TestingConfig
    'default': DevelopmentConfig
}