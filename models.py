from config import Config
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    role = db.Column(db.String(80))
    passhash = db.Column(db.String)
    permissions = db.Column(db.String, default='')

    def __init__(self, username):
        self.username = username

    def create_entry(self):
        db.session.add(self)
        db.session.commit()

    def delete_entry(self):
        db.session.delete(self)
        db.session.commit()
        return self

    def set_password(self, password):
        self.passhash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.passhash, password)

    def set_role(self, role):
        self.role = role.lower()

    def get_role(self):
        # Assuming one user can only have one role
        return self.role

    def set_permissions(self, permissions):
        self.permissions = permissions.lower()

    def add_permission(self, permission):
        if self.permissions is None or len(self.permissions) == 0:
            self.permissions = permission.lower()
        else:
            self.permissions += ',' + permission.lower()

    def generate_auth_token(self, expiration = 800):
        s = Serializer(Config.SECRET_KEY, expires_in = expiration)
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(Config.SECRET_KEY)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.query.get(data['id'])
        return user