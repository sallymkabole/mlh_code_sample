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

from sqlalchemy import func
from geopy.distance import distance, geodesic
import mysql.connector
from flask_migrate import Migrate

#import mysql.connector



app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:password@localhost/dada001'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    phone_number = db.Column(db.String(20))
    email = db.Column(db.String(255))
    location = db.relationship('Location', backref='user', uselist=False)

class Location(db.Model):
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
db.create_all()




@app.route('/', methods=['GET'])
def home():
    return 'Table created successfully'

@app.route('/new_user', methods=['POST'])
def new_user():
    data = request.get_json()
    print(data)
    name = data['name']
    phone_number = data['phone_number']
    email = data['email']
    latitude = data['latitude']
    longitude = data['longitude']

    # Create a new user
    user = User(name=name,email=email,phone_number=phone_number)
    db.session.add(user)
    db.session.flush()  # Flush the session to obtain the auto-generated user ID

    # Create a new location for the user
    location = Location(latitude=latitude, longitude=longitude, user_id=user.id)
    db.session.add(location)
    db.session.commit()

    return 'User created successfully'



@app.route('/update_user_details', methods=['POST'])
def update_user_details():
    # Create a new user with the given name
    data= request.get_json()
    id = data['id']
    email = data['email']
    name = data['name']
    phone_number = data['phone_number']

    user = User.query.get(id)

    if user:
        # Update the user's location
        user.name = name
        user.email = email
        user.phone_number = phone_number
        db.session.commit()
        return 'User Data updated successfully'
    else:
        return 'User not found', 404

    return 'User updated successfully'


@app.route('/update_user_location', methods=['POST'])
def update_user_location():
    # Create a new user with the given name
    data= request.get_json()
    id = data['id']
    updated_latitude = data['latitude']
    updated_longitude = data['longitude']

    user = User.query.get(id)

    if user:
        # Update the user's location
        user.location.latitude = updated_latitude
        user.location.longitude = updated_longitude
        db.session.commit()
        return 'User location updated successfully'
    else:
        return 'User not found', 4

    return 'User and location created successfully'


@app.route('/users', methods=['POST'])
def get_position_within_radius():
    data= request.get_json()
    print(data)

    my_longitude=data['longitude']
    my_latitude=data['latitude']


    max_distance = 115
    
    # Query the database to find users within the radius
    users_within_radius = db.session.query(User).join(Location).all()

    # Filter users based on the distance
    users_within_distance = [
        (user, geodesic((my_latitude, my_longitude), (user.location.latitude, user.location.longitude)).meters)
        for user in users_within_radius
        if geodesic((my_latitude, my_longitude), (user.location.latitude, user.location.longitude)).meters <= max_distance
    ]

    
    names=[]
    for user,distance in users_within_distance:
        print(user.name)
        names.append({"name":user.name,"distance":distance})




  
    
    return make_response(jsonify({'names': names}), 201)
