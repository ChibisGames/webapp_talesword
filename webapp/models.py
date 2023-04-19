import datetime

from flask_login import UserMixin

from webapp import db, manager


class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1536), nullable=False)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User',
                           backref=db.backref('feedbacks', lazy='joined'),
                           lazy=True)

    def __repr__(self):
        return '<Feedback %r>' % self.text


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50),
                      nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.id





@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)