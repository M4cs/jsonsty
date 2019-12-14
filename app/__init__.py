from flask import Flask, jsonify, session, request
from flask_restful import reqparse, Api
from flask_mongoengine import MongoEngine
from flask_pymongo import PyMongo
from uuid import uuid4
from bson import ObjectId
from app.models.helpers import check_email, check_token, ModelHelpers
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os

app = Flask(__name__)
api = Api(app)

with open('.config.json', 'r') as file:
    config = json.load(file)
    if os.environ.get('JSON_TESTING') == 'True':
        app.config['MONGO_URI'] = config['TEST_MONGO_URI']
    else:
        app.config['MONGO_URI'] = config['MONGO_URI']
    app.config['SECRET_KEY'] = config['SECRET_KEY']

mongo = PyMongo(app)

mhelp = ModelHelpers()

def signup_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('email', required=True)
    parser.add_argument('password', required=True)
    return parser

def get_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('Access-Token', location='headers', required=True)
    return parser
    

@app.route('/stores/<store_name>', methods=['GET'])
def get_store(store_name):
    if session.get('access_token'):
        user = mhelp.get_user({'current_token': session['access_token']})
        if user:
            stores = mhelp.get_stores({'owner': user['email']})
            requested_store = None
            for store in stores:
                if store['name'] == store_name:
                    if requested_store is not None:
                        return jsonify({ 'error': 'Multiple Stores Found With This Name! This should never happen.' }), 500
                    else:
                        requested_store = store
                else:
                    pass
            if requested_store:
                return jsonify(requested_store['data'])
    else:
        return jsonify({ "error": "You must authorize first. Please login or signup."}), 403
    
@app.route('/api_v1/all_stores', methods=['GET'])
def get_all_api():
    parser = get_parser()
    args = parser.parse_args()
    user = mhelp.get_user({ 'current_token': args['Access-Token'] })
    if user:
        stores = mhelp.get_stores({'owner': user['email']})
        for store in stores:
            for k, v in store.items():
                if k == '_id':
                    store[k] = str(v)
                else:
                    store[k] = v
        return jsonify({'stores': stores}), 200
    else:
        return jsonify({ "error": "You must authorize first. Please login or signup."}), 403
    
@app.route('/api_v1/stores/<store_name>', methods=['GET', 'PUT', 'DELETE'])
def get_store_api(store_name):
    if request.method == 'GET':
        parser = get_parser()
        args = parser.parse_args()
        user = mhelp.get_user({'current_token': args['Access-Token']})
        if user:
            stores = mhelp.get_stores({'owner': user['email']})
            requested_store = None
            for store in stores:
                if store['name'] == store_name:
                    if requested_store is not None:
                        return jsonify({ 'error': 'Multiple Stores Found With This Name! This should never happen.' }), 500
                    else:
                        requested_store = store
                else:
                    pass
            if requested_store:
                return jsonify(requested_store['data']), 200
        else:
            return jsonify({"error": "Authorization Error. Please Pass Your Valid Access Token!"}), 403
    elif request.method == 'PUT':
        parser = get_parser()
        args = parser.parse_args()
        data = request.get_json()
        user = mhelp.get_user({'current_token': args['Access-Token']})
        store = mhelp.get_single_store({'owner': user['email'], 'name': store_name})
        if store and user:
            mongo.db.stores.find_one_and_update({'owner': user['email'], 'name': store_name}, {'$set': {'data':data}})
            return jsonify({ "message": "Updated Store." }), 200
        elif store and not user:
            return jsonify({ "error": "Store Not Found" }), 404
        else:
            return jsonify({ "error": "Authorization Error. Please Pass Your Valid Access Token!"}), 403
    elif request.method == 'DELETE':
        parser = get_parser()
        args = parser.parse_args()
        user = mhelp.get_user({'current_token': args['Access-Token']})
        if user:
            stores = mhelp.get_stores({'owner': user['email']})
            requested_store = None
            for store in stores:
                if store['name'] == store_name:
                    mongo.db.stores.find_one_and_delete({'_id': store['_id']})
                    old_stores = mhelp.get_store_ids({'owner': user['email']})
                    mongo.db.free_users.find_one_and_update({'email': user['email'] }, { '$set': {'stores': old_stores, 'store_count': user['store_count'] - 1}})
                    return jsonify({ 'message': 'Success' }), 200
                else:
                    pass
            return jsonify({ "message": "Store Not Found" }), 404
        else:
            return jsonify({"error": "Authorization Error. Please Pass Your Valid Access Token!"}), 403
    
@app.route('/api_v1/login', methods=['POST'])
def login_api():
    parser = signup_parser()
    args = parser.parse_args()
    result = check_email(args['email'])
    if not result:
        return {"error": "No Account with that E-Mail Exists!"}, 403
    else:
        pass
    user = mhelp.get_user({'email': args['email']})
    if user:
        if check_password_hash(user.get('password'), args['password']):
            access_token = str(uuid4())
            mongo.db.free_users.find_one_and_update({'email': args['email']}, {'$set': { 'current_token': access_token } })
        else:
            return jsonify({ "error": "Incorrect Password!" }), 403
    else:
        return jsonify({"error": "Something broke"}), 500
    return jsonify({"message": "Logged In!", "access_token": access_token}), 200
    
@app.route('/login', methods=['POST'])
def login():
    parser = signup_parser()
    args = parser.parse_args()
    result = check_email(args['email'])
    if not result:
        return {"error": "No Account with that E-Mail Exists!"}, 403
    else:
        pass
    user = mhelp.get_user({'email': args['email']})
    if user:
        if check_password_hash(user.get('password'), args['password']):
            access_token = str(uuid4())
            user.pop('current_token')
            mongo.db.free_users.find_one_and_update({'email': args['email']}, {'$set': { 'current_token': access_token } })
            session['access_token'] = access_token
        else:
            return jsonify({ "error": "Incorrect Password!" }), 403
    else:
        return jsonify({"error": "Something broke"}), 500
    return jsonify({"msg": "logged in!"}), 200
    

@app.route('/signup', methods=['POST'])
def signup():
    parser = signup_parser()
    args = parser.parse_args()
    result = check_email(args['email'])
    if not result:
        pass
    else:
        return jsonify({ "error": "Account with E-Mail already exists!" }), 403
    pw_hash = generate_password_hash(args['password'], method="sha256", salt_length=16)
    access_token = str(uuid4())
    new_user = {
        "email": args["email"],
        "password": pw_hash,
        "date_created": datetime.now(),
        "store_count": 1,
        "current_token": access_token
    }
    session['access_token'] = access_token
    store = {
        "name": str(uuid4()),
        "owner": new_user['email'],
        "data": {}
    }
    mongo.db.free_users.insert_one(new_user)
    mongo.db.stores.insert_one(store)
    stores = []
    for store in mongo.db.stores.find():
        if store.get('owner') == new_user['email']:
            stores.append(ObjectId(store.get('_id')))
    mongo.db.free_users.find_one_and_update({'email': new_user['email']}, {'$set': { 'stores': stores}})
    
    return jsonify({"msg": "Signup complete!"}), 200

from app.resources import Create

api.add_resource(Create, '/api_v1/create')