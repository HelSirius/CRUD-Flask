from flask_wtf import FlaskForm
from wtforms import StringField, TextField, TextAreaField, SubmitField, validators, ValidationError, PasswordField
from wtforms.validators import Required

class SignupForm(FlaskForm):
	firstname = TextField("First name",[ validators.Required("please enter your first name")])
	lastname = TextField("Last name", [validators.Required("please enter your last name")])
	username = TextField("User name", [validators.Required("please enter your user name")])
	email = TextField("Email", [validators.Required("please enter your email address.")])
	password = PasswordField('Password', [validators.Required("please enter a password. ")])
	submit = SubmitField("create account")


