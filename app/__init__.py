from flask import Flask, jsonify, session, request, redirect, render_template, send_file
from flask_recaptcha import ReCaptcha
from flask_restful import reqparse, Api
from validate_email import validate_email
from jinja2 import Markup, escape
from flask_pymongo import PyMongo
from uuid import uuid4
from bson import ObjectId
from app.models.db_helpers import check_email, check_token, ModelHelpers
from app.models.crypto_helpers import generate_aes_key, encrypt_str, decrypt_str
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from app.html_templates import store_template
import json
import os
import random

app = Flask(__name__)
api = Api(app)
recaptcha = ReCaptcha(app=app)

with open('.config.json', 'r+') as file:
    config = json.load(file)
    app.config['RECAPTCHA_ENABLED'] = config['RECAPTCHA_ENABLED']
    app.config['RECAPTCHA_SITE_KEY'] = config['RECAPTCHA_SITE_KEY']
    app.config['RECAPTCHA_SECRET_KEY'] = config['RECAPTCHA_SECRET_KEY']
    if os.environ.get('JSON_TESTING') == 'True':
        app.config['MONGO_URI'] = config['TEST_MONGO_URI']
        app.config['BASE_URL'] = config['BASE_URL_TEST']
    else:
        app.config['MONGO_URI'] = config['MONGO_URI']
        app.config['BASE_URL'] = config['BASE_URL']
    app.config['SECRET_KEY'] = config['SECRET_KEY']
    if 'AES_KEY' not in config or config['AES_KEY'] == '':
        config['AES_KEY'] = generate_aes_key().decode('latin-1')
        file.seek(0)
        json.dump(config, file, indent = 4)
    app.config['AES_KEY'] = str(config['AES_KEY']).encode('latin-1')

mongo = PyMongo(app)

mhelp = ModelHelpers()

words = open('app/templates/words', 'r').readlines()

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=90)

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
            session.clear()
            return redirect(app.config['BASE_URL'] + '/', 302)
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
            for store in user['stores']:
                store = mongo.db.stores.find_one({'_id': store})
                keys = mongo.db.unique_keys.find_one({'store_id' : store['_id']})
                encrypted_data = store['data']
                NONCE = keys['nonce']
                MAC = keys['mac']
                source_dict = decrypt_str(encrypted_data, NONCE, MAC, app.config['AES_KEY'])
                source_json = json.dumps(source_dict)
                template += store_template.format(store_name=store['name'], data=source_json)
            template = template if template != "" else "<center><h3>No Stores Found. Read the API to learn how to make them!<h3></center>"
            return render_template('stores.html', stores=template, msg=msg, color=color, u_msg=u_msg)
        else:
            session.clear()
            return redirect(app.config['BASE_URL'] +'/login', 302)

@app.route('/stores/<store_name>/delete', methods=['GET'])
def del_store(store_name):
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({ 'current_token': session.get('access_token')})
        if user:
            store = mhelp.get_single_store({'owner': user['email'], 'name': store_name})
            if not store:
               return redirect(app.config['BASE_URL'] +'/stores', 302)

            mongo.db.stores.find_one_and_delete({'_id': store['_id']})
            mongo.db.unique_keys.find_one_and_delete({'store_id': store['_id']})
            store_ids = [store for store in mhelp.get_store_ids({'owner': user['email']})]
            mongo.db.free_users.find_one_and_update({'_id': user['_id']}, { '$set': { 'store_count': user['store_count'] - 1, 'stores': store_ids}})
            return redirect(app.config['BASE_URL'] +'/stores?umsg=Store+Deleted+Successfully&color=green', 302)
        else:
            session.clear()
            return redirect(app.config['BASE_URL'] +'/login', 302)
    else:
        return redirect(app.config['BASE_URL'] +'/login', 302)

@app.route('/stores/<store_name>/edit', methods=['POST'])
def edit_store(store_name):
    parser = update_parser()
    args = parser.parse_args()
    try:
        json.loads(args['data'])        # Making sure input is in json format
        data, NONCE, MAC = encrypt_str(args['data'], app.config['AES_KEY'])
    except:
        return redirect(app.config['BASE_URL'] +'/stores?msg=Bad+JSON+Data', 302)
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({ 'current_token': session.get('access_token')})
        store = mhelp.get_single_store({'owner': user['email'], 'name': store_name})
        if user and store:
            mongo.db.stores.find_one_and_update({'_id': store['_id']}, {'$set': { 'data': data}})
            mongo.db.unique_keys.find_one_and_update({'store_id': store['_id']}, {'$set': { 'nonce': NONCE}})
            mongo.db.unique_keys.find_one_and_update({'store_id': store['_id']}, {'$set': { 'mac': MAC}})
            return redirect(app.config['BASE_URL'] +'/stores?umsg=Store+Updated&color=green', 302)
        elif not store and user:
            return redirect(app.config['BASE_URL'] +'/stores', 302)
        else:
            return redirect(app.config['BASE_URL'] +'/login', 302)
    else:
        return redirect(app.config['BASE_URL'] +'/login', 302)

@app.route('/stores/create', methods=['POST'])
def create_store():
    parser = update_parser()
    args = parser.parse_args()
    try:
        json.loads(args['data'])        # Making sure input is in json format
        data, NONCE, MAC = encrypt_str(args['data'], app.config['AES_KEY'])
    except:
        return redirect(app.config['BASE_URL'] +'/stores?msg=Bad+JSON+Data', 302)
    name = args['store_name']
    if session.get('access_token'):
        user = mongo.db.free_users.find_one({ 'current_token': session.get('access_token')})
        if user:
            store = mongo.db.stores.find_one({ 'owner': user['email'], 'name': name})
            if store:
               return redirect(app.config['BASE_URL'] +'/stores?msg=Name+In+Use+Already', 302)

            docinsertion = mongo.db.stores.insert_one({
                'owner': user['email'],
                'name': name,
                'data': data
            })
            mongo.db.unique_keys.insert_one({
                'store_id': docinsertion.inserted_id,
                'nonce': NONCE,
                'mac' : MAC
            })
            stores = mhelp.get_store_ids({ 'owner': user['email']})
            mongo.db.free_users.find_one_and_update({ '_id': user['_id']}, { '$set': { 'store_count': user['store_count'] + 1, 'stores': stores}})
            return redirect(app.config['BASE_URL'] +'/stores?umsg=Store+Created+Successfully&color=green', 302)
        else:
            session.clear()
    else:
        return redirect(app.config['BASE_URL'] +'/login', 302)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        parser = signup_parser()
        args = parser.parse_args()
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
        
        data, NONCE, MAC = encrypt_str('{ "key" : "value" }', app.config['AES_KEY'])
        mongo.db.free_users.insert_one(new_user)
        docinsertion = mongo.db.stores.insert_one({
            "name": create_chain(),
            "owner": new_user['email'],
            "data": data
        })
        mongo.db.unique_keys.insert_one({
            'store_id': docinsertion.inserted_id,
            'nonce': NONCE,
            'mac' : MAC
        })
        stores = []
        for store in mongo.db.stores.find():
            if store.get('owner') == new_user['email']:
                stores.append(ObjectId(store.get('_id')))
        mongo.db.free_users.find_one_and_update({'email': new_user['email']}, {'$set': { 'stores': stores }})
        
        return redirect(app.config['BASE_URL'] + '/stores', 302)
    elif request.method == "GET":
        return render_template('signup.html'), 200
    
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
        if user and check_password_hash(user.get('password'), args['password']):
            access_token = str(uuid4())
            user.pop('current_token')
            mongo.db.free_users.find_one_and_update({'email': args['email']}, {'$set': { 'current_token': access_token } })
            session['access_token'] = access_token
            return redirect(app.config['BASE_URL'] +'/stores', 302)
        elif not user:
            session.clear()
            return render_template('login.html', error="Something Broke. Try Again Later."), 200
        else:
            return render_template('login.html', error="Incorrect Password!"), 200
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
            session.clear()
            return redirect(app.config['BASE_URL'] + '/login', 302)
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
            if (user and
                    check_password_hash(user['password'], args['old_password']) and
                    args['new_password'] == args['confirm_password']):
                new_pw_hash = generate_password_hash(args['new_password'], method="sha256", salt_length=16)
                mongo.db.free_users.find_one_and_update({'_id': user['_id']}, {'$set': { 'password': new_pw_hash }})
                return redirect(app.config['BASE_URL'] +'/account', 302)
            elif (not user and
                    check_password_hash(user['password'], args['old_password']) and
                    args['new_password'] == args['confirm_password']):
                session.clear()
                return render_template('login.html', error="Something Broke. Try Again Later."), 200
            elif (user and 
                    not check_password_hash(user['password'], args['old_password']) and 
                    args['new_password'] == args['confirm_password']):
                return render_template('login.html', error="Incorrect Password!"), 200
            elif (user and 
                    check_password_hash(user['password'], args['old_password']) and 
                    not args['new_password'] == args['confirm_password']):
                return render_template('login.html', error="Incorrect Password!"), 200
        else:
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
                
    
@app.route('/assets/<folder>/<file>')
def serve_assets(folder, file):
    return send_file('templates/assets/{}/{}'.format(folder, file))

from app.resources import CreateStore, SingleStore, JSONLogin, GetAllStores

print('Adding CreateStore')
api.add_resource(CreateStore, '/api_v1/create')
print('Adding GetAll')
api.add_resource(GetAllStores, '/api_v1/all_stores')
print('Adding Single')
api.add_resource(SingleStore, '/api_v1/stores/<store_name>')
print('Adding Login')
api.add_resource(JSONLogin, '/api_v1/login')
