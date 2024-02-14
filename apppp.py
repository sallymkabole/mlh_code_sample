from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os, uuid,jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from flask_cors import CORS, cross_origin
from flask import Response
from sqlalchemy import func

from sqlalchemy import create_engine
from sqlalchemy import inspect
import psycopg2
from sqlalchemy.exc import OperationalError

import mysql.connector



app = Flask(__name__)
CORS(app)


"""app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://dadamwen_sally:sally@2320//localhost/dadamwen_23"
db = SQLAlchemy(app)


from models import User,Position
"""

"""db_host = 'https://www.dadamwenzangu.org/'
db_port = '5432'
db_name = 'dadamwen_23'
db_user = 'dadamwen_sally'
db_password = 'passc^de22'"""


#engine = create_engine(connection_string)


#engine = create_engine("postgresql+psycopg2://dadamwen_sally:51.91.14.20@51.91.14.20/dadamwen_23")



db_connection = mysql.connector.connect(
    host='localhost',
    user='root',
    password='password',
    database='dada001'
)





@app.route("/", methods=["GET"])
def get_example():
    """GET in server"""

    

    try:
        engine = create_engine("postgresql+psycopg2://dadamwen_sally:sallypasscode@51.91.14.20/dadamwen_23")
        with engine.connect() as connection:
            print("Database connected.")
    except OperationalError as error:
    # Handle the exception if the database connection fails
        print(f"Database connection error: {str(error)}")
        print("Database not connected.")
    return 'none'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).all()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated




@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message':'Cannot perfom this action'})
    users=User.query.all()
    output=[]
    for user in users:
        user_data = {}
        user_data['public_id']= user.public_id
        user_data['fname']= user.fname
        user_data['lname']= user.lname
        user_data['email']= user.email
        user_data['password']= user.password
        user_data['admin']= user.admin
        output.append(user_data)
    return jsonify({'users':output})
  
@app.route('/user', methods=['GET'])
#@token_required
def get_one_user():

    #if not current_user or current_user.admin:
        #return jsonify({'message':'Cannot perfom this action'})


      # creates dictionary of form data
    auth = request.get_json()
    print(auth)
   
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Enter email and Password',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
   
    user = User.query.filter_by(email = auth.get('email')).first()
    user_data = {}
    user_data['public_id']= user.public_id
    user_data['fname']= user.fname
    user_data['lname']= user.lname
    user_data['email']= user.email

    user= User.query.filter_by(public_id=user_data['public_id']).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    

    user_data = {}
    user_data['public_id']= user.public_id
    user_data['fname']= user.fname
    user_data['lname']= user.fname
    user_data['email']= user.emailUser
    user_data['password']= user.password
    user_data['admin']= user.admin

    return jsonify({'user' : user_data})

@app.route('/user/<public_id>', methods=['GET'])
#@token_required
def get_onet_user( public_id):

    user= User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    

    user_data = {}
    user_data['public_id']= user.public_id
    user_data['fname']= user.fname
    user_data['lname']= user.fname
    user_data['email']= user.email
    user_data['password']= user.password
    user_data['admin']= user.admin

    return jsonify({'user' : user_data})

@app.route('/createuser', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message':'Cannot perfom this action'})

    data= request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), fname=data['fname'],lname=data['lname'],email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'New User created'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def edit_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message':'Cannot perfom this action'})

    user= User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user.admin = True
    db.session.commit()
    return  jsonify({'message': 'User is now admin' })

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):

    if not current_user.admin:
        return jsonify({'message':'Cannot perfom this action'})

    user= User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    db.session.delete(user)
    db.session.commit()
    return  jsonify({'message': 'User has been deleted successfully!' })
@app.route('/reset-pass', methods =['POST'])
def reset_password():
    # creates dictionary of form data
    auth = request.get_json()
    print(auth)
   
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Enter email and Password',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
   
    user = User.query.filter_by(email = auth.get('email')).first()
    print(user.email,user.lname)
    
   
        
   
    if user:
        # generates the JWT Token
        user.password=generate_password_hash(auth.get('password') )
        db.session.add(user)
        db.session.commit()
   
        return make_response(jsonify({'type':'success'},{'message':"Password has been reset"}), 201)
    else:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
    # returns 403 if password is wrong


@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.get_json()
    #print(auth.get('password'))
   
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Enter email and Password',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
   
    user = User.query.filter_by(email = auth.get('email')).first()
    print(user.email,user.lname)
    user_data = {}
    user_data['public_id']= user.public_id
    user_data['fname']= user.fname
    user_data['lname']= user.lname
    user_data['email']= user.email



    
    
   
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
   
    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
   
        return make_response(jsonify({'type':'success'},{'message':"User logged in"},{'token' : token}, {'user' : user_data}), 201)
    # returns 403 if password is wrong
    return make_response(
        jsonify('Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'})
    )

@app.route('/signup', methods =['POST'])
@cross_origin()
def signup():
    data = request.get_json()
    print(data)
    fname,lname, email, age,phone = data['user']['fname'],data['user']['lname'] ,data['user']['email'],data['user']['age'], data['user']['phone']
    password = data['user']['password']
    longitude = data['marker']['lng']
    latitude = data['marker']['lat']
    geo = 'POINT({} {})'.format(longitude, latitude)
    password = data['user']['password']
    position = Position.query.filter_by(geo=geo).first()
    new_position = Position(longitude=longitude,
                                latitude=latitude, geo=geo)

    if not position:
        new_position = Position(longitude=longitude,
                                latitude=latitude, geo=geo)
        db.session.add(new_position)
    
    
    user = User.query.filter_by(email = email).first()
    if not user:
        user = User(
            public_id = str(uuid.uuid4()),
            fname = fname,
            lname = lname,
            email = email,
            age=age,
            phone=phone,
            password = generate_password_hash(password),
            admin = False
        )
        

        db.session.add(user)
        new_position.users.append(user)

        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)
@app.route('/position', methods=['POST'])
def create_position():
    data= request.get_json()
    longitude=data['longitude']
    latitude=data['latitude']
    location=data['location']
    geo = 'POINT({} {})'.format(longitude, latitude)
    new_position = Position(longitude=longitude,latitude=latitude,location=location, geo=geo)
    db.session.add(new_position)
    db.session.commit()
    return jsonify({'message':'New Location created'})
@app.route('/positions/<radius>', methods=['POST','GET'])
def get_position_within_radius(radius):
    data= request.get_json()
    print(data)
    longitude=data['marker']['position']['lng']
    latitude=data['marker']['position']['lat']
    geo = 'POINT({} {})'.format(longitude, latitude)

    
    #if request.method=='GET':
    positions = Position.query.join(User, Position.users).filter(func.ST_DistanceSphere(
        Position.geo, geo) < radius).with_entities(User.fname, User.phone).all()

    #user_pos=Position.query.with_entities(User.fname, User.fcm_token).all()

    name = positions[0][0]
    phone = positions[0][1]
    
    print(name,phone)
    if not positions:
        return jsonify({'message':'No Position found'})
    print(positions)
  
    
    return make_response(jsonify({'name': name}, {'phone': phone}), 201)
    
        
    """elif request.method=='POST':
        data= request.get_json()
        longitude=data['longitude']
        latitude=data['latitude']
        location=data['location']
        geo = 'POINT({} {})'.format(longitude, latitude)
        new_position = Position(longitude=longitude,latitude=latitude,location=location, geo=geo)
        db.session.add(new_position)
        db.session.commit()
        return jsonify({'message':'New Location created'})"""
if __name__ == '__main__':
    app.run()
