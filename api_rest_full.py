from functools import wraps
from flask import Flask, request, jsonify, make_response 						# http request, like headers and authorization using http protocols and encode the resposes to json
from flask_sqlalchemy import SQLAlchemy 										# connection to your DB and query uses
from werkzeug.security import generate_password_hash, check_password_hash		# to pass the password for an hask encode and check the hash
import uuid									# universally unique identifier		# generate the public_id
import jwt									# json web token					# generate the token. PyJWT
import datetime								# get the time and calculate date dif

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/testrestfull'	# your DB connection

app.config['SECRET_KEY'] = 'secrettoken'										# your key to encode the token

db = SQLAlchemy(app)

class User(db.Model):
	id 			= db.Column(db.Integer, primary_key=True) 	# simple id column. the real id from the user
	public_id 	= db.Column(db.String(50), unique=True) 	# id for who want to decode the token . like an fake id. is not the exactly sequential id. to make harder to figureout how many user exists and the next or previous number off an user
	name 		= db.Column(db.String(50))					# just the name for the login
	password 	= db.Column(db.String(80))					# key for the login. need to be 80 characters because we will use sha256 to hash
	permission 	= db.Column(db.Boolean)						# if the user had the permission, he can search or create users. you can set permission as string and put multiples values and than when you verify this column, make sure that you are searching the permission that you need

# you need to have already created the database. in this case the database called testrestfull
# after than use the python commands to generate the table with the especifications above
# >>> from 'file_name' import db
# >>> db.create_all()

@app.route('/login')
def login():

	auth = request.authorization							# using the basic authorization http protocol

	if not auth or not auth.username or not auth.password:
		return make_response('Could Not Verify', 400, {'WWW-Authenticate' : 'Basic Realm = "Login Required !!"'}), 401
		# check the login fields

	user = User.query.filter_by(name = auth.username).first()

	if not user:
		return make_response('Could Not Verify', 400, {'WWW-Authenticate' : 'Basic Realm = "Cannot Find This User !!"'}), 404
		# try to find the login user in the DB

	if check_password_hash(user.password, auth.password):
		token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes = 30)}, app.config['SECRET_KEY'])		
		# check the password from the login and DB, after than generate the token and set a time for the expiration. the secret_key will be used to encode the token

		return jsonify({'token' : token.decode('UTF-8')}), 201
	
	return make_response('Could Not Verify', 400, {'WWW-Authenticate' : 'Basic Realm = "Wrong Password !!"'})
	# if the password dosent match

# 3 cases when the login get pass back: when they dont suply any authorization information; when there is no user in the DB; when is the password is incorrect


def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None																		# blank token

		if 'tcc-access-token' in request.headers:											# verify if had some token with the name "tcc-access-token" in the headers
			token = request.headers['tcc-access-token']

		if not token:																		# if dont have a token with this name in the headers
			return jsonify({'message' : 'Missing Token !!'}), 401

		try:
			data = jwt.decode(token,  app.config['SECRET_KEY'])								# if have some token with this name, try to decode
			current_user = User.query.filter_by(public_id = data['public_id']).first()		# and try to find the user

		except:
			return jsonify({'message' : 'Invalid Token !!'}), 401							# if dont find the user correspondent

		return f(current_user, *args, **kwargs)												#token is valid and i have a user

	return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

	if not current_user.permission:
		return jsonify({'message' : 'You Need Permission To Do That !!'}), 401

	users = User.query.all()							# sqlAlchemy syntax

	output = []											# this is an object that will contain the output of the query above
	
	for user in users:									# for each user in users query result
		
		user_data = {}									# new dictonary to bind the query result with the fields that we already have
		user_data['public_id']		= user.public_id
		user_data['name']			= user.name
		user_data['password']		= user.password
		user_data['permission']		= user.permission
		# the left side is the response from the DB and the right side is our new dictonary for this values

		output.append(user_data)						# bind the results with our new object created previusly

	return jsonify({'user' : output}), 200


@app.route('/user/<public_id>', methods = ['GET'])
@token_required
def get_one_user(current_user, public_id):

	if not current_user.permission:
		return jsonify({'message' : 'You Need Permission To Do That !!'}), 401

	user = User.query.filter_by(public_id = public_id).first()

	if user:

		user_data = {}									
		user_data['public_id']		= user.public_id
		user_data['name']			= user.name
		user_data['password']		= user.password
		user_data['permission']		= user.permission

		return jsonify({'user' : user_data}), 200

	else:

		return jsonify({'message' : 'User Not Found !!'}), 404


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

	if not current_user.permission:
		return jsonify({'message' : 'You Need Permission To Do That !!'}), 401

	data = request.get_json()								
	# pass the json object data to the variable called data

	hashed_password = generate_password_hash(data['password'], method = 'sha256')
	# pass the password to the function that will hashed to sha256 base

	new_user = User(
		public_id = str(uuid.uuid1()),		# uuid1 generate using a timestamp and the MAC address of the computer on which it was generated. you can use the uuid4 that uses random numbers. 
		name = str(data['name']),
		password = str(hashed_password),
		permission = False)
	# this is all the parameters that an user needs to be created

	db.session.add(new_user)
	db.session.commit()

	# in postman you only need to pass a json with name and password

	return jsonify({'message' : 'New User Added !!'}), 201


@app.route('/user/<public_id>', methods = ['PUT'])
@token_required
def update_user(current_user, public_id):

	if not current_user.permission:
		return jsonify({'message' : 'You Need Permission To Do That !!'}), 401

	user = User.query.filter_by(public_id = public_id).first()

	if user:

		user.permission = True
		db.session.commit()

		return jsonify({'message' : 'User Successfully Updated'}), 202

	else:

		return jsonify({'message' : 'User Not Found !!'}), 404


@app.route('/user/<public_id>', methods = ['DELETE'])
@token_required
def delete_user(current_user, public_id):

	if not current_user.permission:
		return jsonify({'message' : 'You Need Permission To Do That !!'}), 401

	user = User.query.filter_by(public_id = public_id).first()

	if user:

		db.session.delete(user)
		db.session.commit()

		return jsonify({'message' : 'User Successfully Deleted'}), 202

	else:

		return jsonify({'message' : 'User Not Found !!'}), 404


if __name__ == '__main__':
	app.run(debug=True)

