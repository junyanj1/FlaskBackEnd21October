from email.policy import default
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../user.db'
db = SQLAlchemy(app)

class User(db.Model):
    '''
    Q2: basic user model
    '''
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, default='')
    role = db.Column(db.String, nullable=False)
    permissions = db.Column(db.String, default='')
