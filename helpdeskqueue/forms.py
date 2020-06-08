from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from helpdeskqueue.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators = [DataRequired(), Length(min = 2, max = 20)])
    email = StringField('Email', validators = [DataRequired(), Email()])
    password = PasswordField('Password', validators = [DataRequired(), Length(min = 8, max = 20)])
    confirm_password = PasswordField('Confirm Password', validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    ## validates that the username is unique, if not validation error will kickback
    def validate_username(self, username):
        user = User.query.filter_by(username = username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please input a different one.')

    ## validates that the email is unique, if not validation error will kickback
    def validate_email(self, email):
        user = User.query.filter_by(email = email.data).first()
        if user:
            raise ValidationError('That email is already been used to register. Please input a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators = [DataRequired(), Email()])
    password = PasswordField('Password', validators = [DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class QueueForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    category = SelectField('Category', choices= [('default', "Please select one from this drop down"),('access needed', "Access needed"),('equipment requests',"Equipment requests"), ('laptop hardware',"Laptop hardware issues"), ('laptop performance',"Laptop performance"), ('software requests',"Software requests"), ('shoretel',"Shoretel"), ('vpn',"VPN"), ('webex',"Webex")], validators=[DataRequired()])
    notes = TextAreaField('Notes')
    submit = SubmitField('Post')


class PageAction(FlaskForm):
    filter_by = SelectField('Filter', choices= [('all', "All"),('open', "Open"),('assisting',"Assisting"), ('complete',"Complete"), ('canceled',"Canceled")])
    submit = SubmitField('Complete')
    open_filter_button = SubmitField('Open')
    assisting_filter_button = SubmitField('Assisting')
    complete_filter_button = SubmitField('Complete')
    canceled_filter_button = SubmitField('Canceled')
    search = TextAreaField('Search for a ticket, by ticket number')
    submit_search = SubmitField('Search')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators = [DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email = email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators = [DataRequired(), Length(min = 8, max = 20)])
    confirm_password = PasswordField('Confirm Password', validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')