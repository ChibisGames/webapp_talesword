from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


app = Flask(__name__)
app.secret_key = 'some secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///datatalesworld.db'
db = SQLAlchemy(app)
manager = LoginManager(app)


def check_password(password):
    #  if ok -> False
    if len(password) < 8 or len(password) > 64:
        return True
    if ' ' in password:
        return True
    return False


def check_login(login):
    #  if ok -> False
    if len(login) < 8 or len(login) > 32:
        return True
    if ' ' in login:
        return True
    return False


from webapp import models, routes

with app.app_context():
    db.create_all()
    db.session.commit()
