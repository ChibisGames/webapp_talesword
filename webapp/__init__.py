from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


app = Flask(__name__)
app.secret_key = 'some secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///datatalesworld.db'
db = SQLAlchemy(app)
manager = LoginManager(app)

from webapp import models, routes

with app.app_context():
    db.create_all()
    db.session.commit()
