from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, FloatField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
from app.models import User, UserRole, Roles

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username')

class ManageUser(FlaskForm):
    action = SelectField(u'Action', choices=[('add', 'Add User'), ('update', 'Update User'), ('delete', 'Delete User')], validators=[DataRequired()])
    submit2 = SubmitField('Submit')

class AddUserForm(FlaskForm):
    role = SelectField(u'Role Type', choices=[('1', 'Client'), ('2', 'Partner'), ('3', 'Admin')], validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')

class SelectUserForm(FlaskForm):
    users = UserRole.query.all()
    for user in users:
        user = user
    user = SelectField(u'User', choices=[(user.id, user.id)])
    submit = SubmitField('Select')

class UpdateUserForm(FlaskForm):
    role = SelectField(u'Role Type', choices=[('1', 'Client'), ('2', 'Partner'), ('3', 'Admin')], validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Delete')
