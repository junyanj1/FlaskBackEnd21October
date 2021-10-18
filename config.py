class Config(object):
    SECRET_KEY = 'Just use this string for simplicity which is insecure and should be avoided in production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///user.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    USER_ENABLE_EMAIL = False
    USER_ENABLE_USERNAME = True
