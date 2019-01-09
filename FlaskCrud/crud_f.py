from flask import Flask, render_template, request, flash, session, redirect, url_for
from forms import SignupForm


from flask_wtf import FlaskForm
from wtforms import StringField, TextField, TextAreaField, SubmitField, validators, ValidationError, PasswordField
from wtforms.validators import Required
from flask_bcrypt import Bcrypt
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_security import login_required
from flask_migrate import Migrate
import os


app = Flask(__name__, static_url_path = '/static')

bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:siriusstar@localhost/CRUD'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


SECRET_KEY = os.urandom(32)
app.config ['SECRET_KEY'] = SECRET_KEY


login_manager = LoginManager()
login_manager.init_app(app)


login_manager.session_protection = "strong"

login_manager.login_view = 'login'

db = SQLAlchemy(app)

migrate = Migrate(app, db)


class SignupForm(FlaskForm):

	firstname = TextField("First name",[ validators.Required("please enter your first name")])
	lastname = TextField("Last name", [validators.Required("please enter your last name")])
	username = TextField("User name", [validators.Required("please enter your user name")])
	email = TextField("Email", [validators.Required("please enter your email address.")])
	password = PasswordField('Password', [validators.Required("please enter a password. ")])
	submit = SubmitField("create account")


class LoginForm(FlaskForm):

	username = TextField("Username", [validators.Required("please enter your username")])
	password = PasswordField("Password", [validators.Required("please enter a password")])
	submit = SubmitField("LogIn")

	def validate(self):
		if not FlaskForm.validate(self):
			return False

		user  = Users.query.filter_by(username = self.username.data.lower()).first()

		if user and user.check_password(self.password.data):
			return True
		else:
			self.username.errors.append("Invalid username or password")



class WebDetailsForm(FlaskForm):
	websitename = TextField ("Website Name", [validators.Required("please enter the website name to procced")])
	websiteurl = TextField ("Website  URL", [validators.Required("please enter the website url to procced")])
	websitedetails = TextAreaField ("Content")
	submit = SubmitField("Add")


class Users(db.Model):
	__tablename__ = 'users'
	uid = db.Column(db.Integer, primary_key = True)
	firstname = db.Column (db.String(100))
	lastname = db.Column (db.String(100))
	username = db.Column (db.String(100), nullable = False)
	email = db.Column (db.String(120), unique = True, nullable = False)
	pwdhash = db.Column (db.String(54))
	users = db.relationship("WebsiteD", backref= db.backref('users'), lazy = 'dynamic')



	def __init__(self, firstname, lastname, username, email, password):

		self.firstname = firstname 
		self.lastname = lastname
		self.username = username
		self.email = email
		self.set_password (password)

	def set_password(self, password):

		self.pwdhash = generate_password_hash(password)

	def check_password(self, password):

		return check_password_hash (self.pwdhash, password)

	def is_active(self):
		return True


	def get_id(self):
		return self.uid

	def is_authenticated(self):
		return True

	def is_anonymous(self):
		return False

	def __repr__(self):
		return '<Users %r' % (Self.username)


class WebsiteD(db.Model):
	__tablename__ = "Websitedetails"
	user_id = db.Column(db.Integer, db.ForeignKey('users.uid'))
	wid = db.Column(db.Integer, primary_key = True)
	websitename = db.Column (db.String(100))
	websiteurl = db.Column(db.Text(65535))
	websitedetails = db.Column(db.UnicodeText())
	savedat = db.Column(db.DateTime(), default = datetime.utcnow)
	editedat = db.Column( db.DateTime(), default = datetime.utcnow)
	

	def __init__(self, websitename, websiteurl, websitedetails):

		self.websitename = websitename
		self.websiteurl = websiteurl
		self.websitedetails = websitedetails


@login_manager.user_loader
def load_user(uid):
    return Users.query.get(uid)


@app.route('/')
def index():
	return render_template("home.html")


@app.route('/dashboard', methods = ['GET','POST'])
@login_required
def dashboard():
	form = WebDetailsForm()
	if request.method == 'POST':

		website_details = WebsiteD( websitename = form.websitename.data, websiteurl = form.websiteurl.data,
		 websitedetails = form.websitedetails.data)
		db.session.add(website_details)
		db.session.commit()
		details = WebsiteD.query.all()
		return render_template("info.html", details = details)

	elif request.method == 'GET':
		return render_template("dashboard.html", form = form)


@app.route('/info')
@login_required
def info():
	details = WebsiteD.query.all()

	return render_template("info.html", details = details)


@app.route('/login', methods=['GET','POST'])
def login():
	
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()
		if user is None or not user.check_password(form.password.data):
			flash('Invalid username or password')
			return redirect(url_for('login', username = username))
		login_user(user)

		return redirect(url_for('dashboard'))
	return render_template('login.html', form=form)


@app.route('/logout', methods = ["GET"])
@login_required
def logout():
	user = current_user
	user.authenticated = False
	session.pop('username', None)
	return redirect(url_for('index'))


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
	form = SignupForm()
	if request.method == 'POST':
		if form.validate() == False:
			return render_template("signup.html", form = form)
		else:
			reg_user = Users(form.firstname.data, form.lastname.data,form.username.data,
				form.email.data, form.password.data)
			db.session.add(reg_user)
			db.session.commit()
			return render_template('login.html', form = form)

	elif request.method == 'GET':
		return render_template('signup.html', form = form)


if __name__ == '__main__':

	app.debug = True
	db.create_all()
	app.run(host = '0.0.0.0')