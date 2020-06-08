import os
from flask import Flask
## SQLAlchemy is used for SQLlite built into flask
from flask_sqlalchemy import SQLAlchemy
## bcrypt is used to encrypt passwords
from flask_bcrypt import Bcrypt
## flask_login used to manage user logins
from flask_login import LoginManager
from flask_mail import Mail

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ea3732f4fbdd4d644378eb64d9d1f665'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
## db created is sqllite
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
## login view is aimed to login route
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)


from helpdeskqueue import routes