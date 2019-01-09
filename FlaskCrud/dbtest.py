from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import bcrypt 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:siriusstar@localhost/CRUD'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):

	__tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key = True)
    firstname = db.Column (db.String(100))
    lastname = db.Column (db.String(100))
    username = db.Column (db.String(100), nullable = False)
    email = db.Column (db.String(120), unique = True, nullable = False)
    pwdhash = db.Column (db.String(54))

	def __init__(self, name, username, email, city):

		self.firstname = firstname 
		self.lastname = secondname
		self.username = username
		self.email = email
		self.set_password (password)

	def set_password(self, password):

		self.pwdhash = bcrypt.generate_password_hash(password).decode('utf-8')

	def check_password(self, password):

		self.pwdhash = bcrypt. check_password(self.pwdhash, password)
