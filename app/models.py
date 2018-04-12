from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_security import RoleMixin

class UserRole(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id'), default=1)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(255), unique=True)
    password_hash = db.Column(db.String(255))
    img_uri = db.Column(db.String(100))
    roles = db.relationship('UserRole', backref=db.backref('user', lazy='joined'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Roles(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    description = db.Column(db.String(255))
    roles = db.relationship('UserRole', backref=db.backref('roles', lazy='joined'))

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# class Services(db.Model):
#     id = 
#     name = 
#     price = 
#     description = 