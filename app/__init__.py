from flask import Flask, jsonify, session, request, redirect, render_template, send_file
from flask_recaptcha import ReCaptcha
from flask_restful import reqparse, Api
from validate_email import validate_email
from jinja2 import Markup, escape
from flask_pymongo import PyMongo
from uuid import uuid4
from bson import ObjectId
from app.models.helpers import check_email, check_token, ModelHelpers
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from app.html_templates import store_template
import json
import os
import random

app = Flask(__name__)
api = Api(app)
recaptcha = ReCaptcha(app=app)

with open('.config.json', 'r') as file:
    config = json.load(file)
    app.config['RECAPTCHA_ENABLED'] = config['RECAPTCHA_ENABLED']
    app.config['RECAPTCHA_SITE_KEY'] = config['RECAPTCHA_SITE_KEY']
    app.config['RECAPTCHA_SECRET_KEY'] = config['RECAPTCHA_SECRET_KEY']
    if os.environ.get('JSON_TESTING') == 'True':
        app.config['MONGO_URI'] = config['TEST_MONGO_URI']
        app.config['BASE_URL'] = 'http://localhost:5000'
    else:
        app.config['MONGO_URI'] = config['MONGO_URI']
        app.config['BASE_URL'] = 'https://json.psty.io'
    app.config['SECRET_KEY'] = config['SECRET_KEY']

mongo = PyMongo(app)

mhelp = ModelHelpers()

words = open('app/templates/words', 'r').readlines()

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=90)
    

@app.errorhandler(500):
def handle_five(e):
    session.clear()
    return redirect('/', 302)

def create_chain():
    word = ""
    for _ in range(3):
        word += str(random.choice(words)).capitalize().replace('\n', '')
    return word

def update_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('data', required=True)
    parser.add_argument('store_name')
    return parser

def signup_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('email', required=True)
    parser.add_argument('password', required=True)
    return parser

def get_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('Api-Key', location='headers', required=True)
    return parser

def password_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('old_password')
    parser.add_argument('new_password')
    parser.add_argument('confirm_password')
    return parser

def store_msg_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('msg')
    parser.add_argument('umsg')
    parser.add_argument('color')
    return parser

@app.route('/', methods=['GET'])
def index():
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({'current_token': session.get('access_token')})
        if user:
            return redirect(app.config['BASE_URL'] +'/stores', 302)
        else:
            return redirect('/', 302)
    else:
        number = mongo.db.free_users.count()
        return render_template('index.html', number=number), 200
    
@app.route('/stores', methods=['GET'])
def stores():
    parser = store_msg_parser()
    args = parser.parse_args()
    if args.get('msg'):
        msg = args['msg']
    else:
        msg = ''
    if args.get('color'):
        color = args['color']
    else:
        color = 'red'
    if args.get('umsg'):
        u_msg = args['umsg']
    else:
        u_msg = ''
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({'current_token': session.get('access_token')})
        if user:
            template = ""
            if user['store_count'] > 0:
                for store in user['stores']:
                    if store:
                        store = mongo.db.stores.find_one({'_id': store})
                        template += store_template.format(store_name=store['name'], data=store['data'])
            else:
                template = "<center><h3>No Stores Found. Read the API to learn how to make them!<h3></center>"
            return render_template('stores.html', stores=template, msg=msg, color=color, u_msg=u_msg)
    return redirect(app.config['BASE_URL'] +'/login', 302)

@app.route('/stores/<store_name>/delete', methods=['GET'])
def del_store(store_name):
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({ 'current_token': session.get('access_token')})
        if user:
            stores = mhelp.get_stores({'owner': user['email']})
            for store in stores:
                if store['name'] == store_name:
                    mongo.db.stores.find_one_and_delete({'_id': store['_id']})
                    store_ids = [store for store in mhelp.get_store_ids({'owner': user['email']})]
                    mongo.db.free_users.find_one_and_update({'_id': user['_id']}, { '$set': { 'store_count': user['store_count'] - 1, 'stores': store_ids}})
                    return redirect(app.config['BASE_URL'] +'/stores?umsg=Store+Deleted+Successfully&color=green', 302)
            return redirect(app.config['BASE_URL'] +'/stores', 302)
        else:
            return redirect(app.config['BASE_URL'] +'/login', 302)
    return redirect(app.config['BASE_URL'] +'/login', 302)

@app.route('/stores/<store_name>/edit', methods=['POST'])
def edit_store(store_name):
    parser = update_parser()
    args = parser.parse_args()
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({ 'current_token': session.get('access_token')})
        if user:
            for store in user['stores']:
                store = mhelp.get_single_store({ '_id': store })
                if store['name'] == store_name:
                    mongo.db.stores.find_one_and_update({'_id': store['_id']}, {'$set': { 'data': args['data']}})
            return redirect(app.config['BASE_URL'] +'/stores?umsg=Store+Updated&color=green', 302)
        else:
            return redirect(app.config['BASE_URL'] +'/login', 302)
    return redirect(app.config['BASE_URL'] +'/login', 302)

@app.route('/stores/create', methods=['POST'])
def create_store():
    parser = update_parser()
    args = parser.parse_args()
    try:
        data = json.loads(args['data'])
    except:
        return redirect(app.config['BASE_URL'] +'/stores?msg=Bad+JSON+Data', 302)
    name = args['store_name']
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({ 'current_token': session.get('access_token')})
        if user:
            for store in user['stores']:
                store = mhelp.get_single_store({ '_id': store})
                if store['name'] == name:
                    return redirect(app.config['BASE_URL'] +'/stores?msg=Name+In+Use+Already', 302)
            mongo.db.stores.insert_one({
                'owner': user['email'],
                'name': name,
                'data': data
            })
            stores = mhelp.get_store_ids({ 'owner': user['email']})
            mongo.db.free_users.find_one_and_update({ '_id': user['_id']}, { '$set': { 'store_count': user['store_count'] + 1, 'stores': stores}})
            return redirect(app.config['BASE_URL'] +'/stores?umsg=Store+Created+Successfully&color=green', 302)
    return redirect(app.config['BASE_URL'] + '/login')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        parser = signup_parser()
        args = parser.parse_args()
        user = mhelp.get_user({'email': args['email']})
        if not user:
            return render_template('login.html', error="E-Mail Not In Use!")
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
                return render_template('login.html', error="Incorrect Password!"), 200
        else:
            return render_template('login.html', error="Something Broke. Try Again Later."), 200
        return redirect(app.config['BASE_URL'] +'/stores', 302)
    elif request.method == 'GET':
        if session.get('access_token'):
            user = mhelp.get_user({'current_token': session.get('access_token')})
            if user:
                return redirect(app.config['BASE_URL'] +'/stores', 302)
            else:
                session.clear()
                return render_template('login.html'), 200
        else:
            return render_template('login.html'), 200
        
@app.route('/account', methods=['GET'])
def account():
    if session.get('access_token'):
        user = mhelp.get_user({'current_token': session.get('access_token')})
        if user:
            return render_template('account.html', email=user['email'], store_count=user['store_count'], api_key=user['api_key'])
    else:
        return redirect(app.config['BASE_URL'] +'/login', 302)
    
@app.route('/regen_api', methods=['GET'])
def regen_api():
    if request.method == 'GET':
        user = mhelp.get_user({'current_token': session['access_token']})
        if user:
            mongo.db.free_users.find_one_and_update({'_id': user['_id']}, { '$set': { 'api_key': str(uuid4()) }})
            return redirect(app.config['BASE_URL'] +'/account', 302)
        
@app.route('/logout', methods=['GET'])
def logout():
    if request.method == 'GET':
        if session.get('access_token'):
            user = mhelp.get_user({ 'current_token': session['access_token']})
            if user:
                mongo.db.free_users.find_one_and_update({ '_id': user['_id']}, {'$set': {'current_token': ''}})
                session.clear()
                return redirect(app.config['BASE_URL'] +'/', 302)
            else:
                session.clear()
                return redirect(app.config['BASE_URL'] +'/', 302)
        else:
            return redirect(app.config['BASE_URL'] +'/', 302)
        
@app.route('/change_password', methods=['POST'])
def change_password():
    if request.method == 'POST':
        parser = password_parser()
        args = parser.parse_args()
        if session.get('access_token'):
            user = mhelp.get_user({ 'current_token': session['access_token']})
            if user:
                if check_password_hash(user['password'], args['old_password']):
                    if args['new_password'] == args['confirm_password']:
                        new_pw_hash = generate_password_hash(args['new_password'], method="sha256", salt_length=16)
                        mongo.db.free_users.find_one_and_update({'_id': user['_id']}, {'$set': { 'password': new_pw_hash }})
                        return redirect(app.config['BASE_URL'] +'/account', 302)
    return redirect(app.config['BASE_URL'] +'/login')

@app.route('/api_documentation')
def docs():
    signup = """<a href="/signup" style="display: inline-block;"><button type="submit" class="button">Signup</button></a>"""
    if session.get('access_token'):
        user = mhelp.get_user({'current_token': session['access_token']})
        if user:
            signup = ""
        else:
            signup = """<a href="/signup" style="display: inline-block;"><button type="submit" class="button">Signup</button></a>"""
    return render_template('docs.html', signup=signup)
                

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        parser = signup_parser()
        args = parser.parse_args()
        print(recaptcha.verify())
        if not recaptcha.verify():
            return render_template('signup.html', error="ReCaptcha Failed!")
        result = check_email(args['email'])
        if not result:
            pass
        else:
            return render_template('signup.html', error="Email In Use!")
        pw_hash = generate_password_hash(args['password'], method="sha256", salt_length=16)
        access_token = str(uuid4())
        new_user = {
            "email": args["email"],
            "password": pw_hash,
            "date_created": datetime.now(),
            "store_count": 1,
            "current_token": access_token,
            "api_key": str(uuid4())
        }
        session['access_token'] = access_token
        
        store = {
            "name": create_chain(),
            "owner": new_user['email'],
            "data": {}
        }
        mongo.db.free_users.insert_one(new_user)
        mongo.db.stores.insert_one(store)
        stores = []
        for store in mongo.db.stores.find():
            if store.get('owner') == new_user['email']:
                stores.append(ObjectId(store.get('_id')))
        mongo.db.free_users.find_one_and_update({'email': new_user['email']}, {'$set': { 'stores': stores }})
        
        return redirect(app.config['BASE_URL'] +'/stores', 302)
    elif request.method == "GET":
        return render_template('signup.html'), 200
    
@app.route('/assets/<folder>/<file>')
def serve_assets(folder, file):
    return send_file('templates/assets/{}/{}'.format(folder, file))

@app.route('/api_v1/all_stores', methods=['GET'])
def get_all_api():
    parser = get_parser()
    args = parser.parse_args()
    print(args['Api-Key'])
    user = mhelp.get_user({ 'api_key': args['Api-Key']})
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
        user = mhelp.get_user({ 'api_key': args['Api-Key']})
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
        user = mhelp.get_user({ 'api_key': args['Api-Key']})
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
        user = mhelp.get_user({ 'api_key': args['Api-Key']})
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
    return jsonify({"message": "Logged In!", "api-key": user['api_key']}), 200

from app.resources import Create

api.add_resource(Create, '/api_v1/create')