from flask import Flask, jsonify, session, request, redirect, render_template, send_file
from flask_recaptcha import ReCaptcha
from flask_restful import reqparse, Api
from jinja2 import Markup, escape
from flask_pymongo import PyMongo
from flask_mongoengine import MongoEngine
from uuid import uuid4
from bson import ObjectId
from app.helpers.db_helpers import check_email, check_token, ModelHelpers
from app.helpers.input_helpers import verify_email, verify_name
from app.helpers.crypto_helpers import generate_aes_key, encrypt_and_encode, decode_and_decrypt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from app.html_templates import store_template
import json
import os
import random
import urllib.parse as urlparse

app = Flask(__name__)
api = Api(app)
recaptcha = ReCaptcha(app=app)

with open('.config.json', 'r+') as file:
    config = json.load(file)
    app.config['RECAPTCHA_ENABLED'] = config['RECAPTCHA_ENABLED']
    app.config['RECAPTCHA_SITE_KEY'] = config['RECAPTCHA_SITE_KEY']
    app.config['RECAPTCHA_SECRET_KEY'] = config['RECAPTCHA_SECRET_KEY']
    app.config['TESTING'] = config['TESTING']
    if app.config['TESTING'] == 'True':
        app.config['MONGODB_SETTINGS'] = {
            'db': 'jsonsty_test',
            'host': config['TEST_MONGO_URI']
        }
        app.config['BASE_URL'] = config['BASE_URL_TEST']
    else:
        app.config['MONGODB_SETTINGS'] = {
            'db': 'jsonsty_test',
            'host': config['MONGO_URI']
        }
        app.config['BASE_URL'] = config['BASE_URL']
    app.config['SECRET_KEY'] = config['SECRET_KEY']
    if 'AES_KEY' not in config or config['AES_KEY'] == '':
        config['AES_KEY'] = generate_aes_key().decode('latin-1')
        file.seek(0)
        json.dump(config, file, indent = 4)
    app.config['AES_KEY'] = str(config['AES_KEY']).encode('latin-1')

mongo = MongoEngine(app)

from app.models.models import User, Store, UniqueKeys

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

def msg_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('msg')
    parser.add_argument('umsg')
    parser.add_argument('color')
    return parser

@app.route('/', methods=['GET'])
def index():
    if session.get('access_token'):
        user = User.objects(current_token=session.get('access_token')).first()
        if user:
            return redirect(app.config['BASE_URL'] +'/stores', 302)
        else:
            session.clear()
            return redirect(app.config['BASE_URL'] + '/', 302)
    else:
        number = len(User.objects().all())
        return render_template('index.html', number=number), 200
    
@app.route('/stores', methods=['GET'])
def stores():
    parser = msg_parser()
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
        user = User.objects(current_token=session.get('access_token')).first()
        if user:
            template = ""
            for store in user.stores:
                store_obj = Store.objects(id=store).first()
                keys = UniqueKeys.objects(store_id=store).all()
                if len(keys) == 1:
                    encrypted_data = store_obj.data
                    NONCE = keys[0].nonce
                    MAC = keys[0].mac
                    source_dict = decode_and_decrypt(encrypted_data, NONCE, MAC, app.config['AES_KEY'])
                    source_json = json.dumps(source_dict)
                    template += store_template.format(store_name=store_obj.name, store_name_url=urlparse.quote_plus(store_obj.name), data=source_json)
            template = template if template != "" else "<center><h3>No Stores Found. Read the API to learn how to make them!<h3></center>"
            return render_template('stores.html', stores=template, msg=msg, color=color, u_msg=u_msg)
        else:
            session.clear()
            return redirect(app.config['BASE_URL'] +'/login', 302)
    return redirect(app.config['BASE_URL'] + '/', 302)

@app.route('/stores/<store_name>/delete', methods=['GET'])
def del_store(store_name):
    store_name = urlparse.unquote_plus(store_name)
    if session.get('access_token'):
        user = User.objects(current_token= session.get('access_token')).first()
        if user:
            store = Store.objects(owner=user.email, name=store_name).first()
            if not store:
               return redirect(app.config['BASE_URL'] +'/stores', 302)

            store.delete()
            uk_obj = UniqueKeys.objects(store_id=store.id).first()
            uk_obj.delete()
            store_ids = [store.id for store in Store.objects(owner=user.email).all()]
            user.store_count -= 1
            user.stores = store_ids
            user.save()
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
    store_name = urlparse.unquote_plus(store_name)
    try:
        json.loads(args['data'])        # Making sure input is in json format
        data, NONCE, MAC = encrypt_and_encode(args['data'], app.config['AES_KEY'])
    except:
        return redirect(app.config['BASE_URL'] +'/stores?msg=Bad+JSON+Data', 302)
    if session.get('access_token'):
        user = User.objects(current_token=session.get('access_token')).first()
        store = Store.objects(owner=user.email, name=store_name).first()
        if user and store:
            store.data = data
            store.save()
            uk_obj = UniqueKeys.objects(store_id=store.id).first()
            uk_obj.nonce = NONCE
            uk_obj.mac = MAC
            uk_obj.save()
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
        data, NONCE, MAC = encrypt_and_encode(args['data'], app.config['AES_KEY'])
    except:
        return redirect(app.config['BASE_URL'] +'/stores?msg=Bad+JSON+Data', 302)
    store_name = args['store_name'].strip()
    vresult = verify_name(store_name)
    if vresult:
        pass
    else:
        return redirect(app.config['BASE_URL'] +'/stores?msg=HTML+Tags+Not+Allowed+in+Name', 302)
    if session.get('access_token'):
        user = User.objects(current_token=session.get('access_token')).first()
        if user:
            store = Store.objects(owner=user.email, name=store_name).first()
            if store:
               return redirect(app.config['BASE_URL'] +'/stores?msg=Name+In+Use+Already', 302)

            store_obj = {
                'owner': user['email'],
                'name': store_name,
                'data': data
            }
            store = Store(**store_obj).save()
            if store:
                uk_obj = {
                    'store_id': store.id,
                    'nonce': NONCE,
                    'mac' : MAC
                }
                uk = UniqueKeys(**uk_obj).save()
                store_ids = [store.id for store in Store.objects(owner=user.email).all()]
                user.store_count += 1
                user.stores = store_ids
                user.save()
                return redirect(app.config['BASE_URL'] +'/stores?umsg=Store+Created+Successfully&color=green', 302)
            return redirect(app.config['BASE_URL'] + '/stores?umsg=Store+Creation+Failure&color=red', 302)
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
        vresult = verify_email(args['email'])
        if not result:
            pass
        else:
            return render_template('signup.html', error="Email In Use!")
        if vresult or app.config['TESTING'] == 'True':
            pass
        else:
            return render_template('signup.html', error="Use a real email!")
        pw_hash = generate_password_hash(args['password'], method="sha256", salt_length=16)
        access_token = str(uuid4())
        new_user = {
            "email": args["email"],
            "password": pw_hash,
            "date_created": datetime.now(),
            "store_count": 1,
            "current_token": access_token,
            "api_key": str(uuid4()),
            "account_type": "Free"
        }
        new = User(**new_user).save()
        if new:
            session['access_token'] = access_token
        
            data, NONCE, MAC = encrypt_and_encode('{ "key" : "value" }', app.config['AES_KEY'])
            store_obj = {
                "name": create_chain(),
                "owner": new_user['email'],
                "data": data
            }
            store = Store(**store_obj).save()
            if store:
                print('There Was A Store')
                uk_obj = {
                    'store_id': store.id,
                    'nonce': NONCE,
                    'mac' : MAC
                }
                unique_keys = UniqueKeys(**uk_obj)
                unique_keys.save()
                stores = []
                for store in Store.objects(owner=new.email).all():
                    stores.append(ObjectId(store.id))
                new.stores = stores
                new.save()
                return redirect(app.config['BASE_URL'] + '/stores', 302)
    elif request.method == "GET":
        return render_template('signup.html'), 200
    return render_template('signup.html'), 200
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        parser = signup_parser()
        args = parser.parse_args()
        user = User.objects(email=args['email']).first()
        if not user:
            return render_template('login.html', error="E-Mail Not In Use!")
        else:
            pass
        if user and check_password_hash(user.password, args['password']):
            access_token = str(uuid4())
            user.current_token = access_token
            user.save()
            session['access_token'] = access_token
            return redirect(app.config['BASE_URL'] +'/stores', 302)
        elif not user:
            session.clear()
            return render_template('login.html', error="Something Broke. Try Again Later."), 200
        else:
            return render_template('login.html', error="Incorrect Password!"), 200
    elif request.method == 'GET':
        if session.get('access_token'):
            user = User.objects(current_token=session['access_token']).first()
            if user:
                return redirect(app.config['BASE_URL'] +'/stores', 302)
            else:
                session.clear()
                return render_template('login.html'), 200
        else:
            return render_template('login.html'), 200
        
@app.route('/account', methods=['GET'])
def account():
    parser = msg_parser()
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
        user = User.objects(current_token=session.get('access_token')).first()
        if user:
            return render_template('account.html', email=user.email, store_count=user['store_count'], api_key=user['api_key'], msg=msg, color=color, u_msg=u_msg, type=user.account_type)
        else:
            session.clear()
            return redirect(app.config['BASE_URL'] + '/login', 302)
    else:
        return redirect(app.config['BASE_URL'] +'/login', 302)
    
@app.route('/regen_api', methods=['GET'])
def regen_api():
    if request.method == 'GET':
        user = User.objects(current_token=session.get('access_token')).first()
        if user:
            user.api_key = str(uuid4())
            user.save()
            return redirect(app.config['BASE_URL'] +'/account', 302)
        
@app.route('/logout', methods=['GET'])
def logout():
    if request.method == 'GET':
        if session.get('access_token'):
            user = User.objects(current_token=session['access_token']).first()
            if user:
                user.current_token = ''
                user.save()
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
            user = User.objects(current_token=session['access_token']).first()
            if not user:
                session.clear()
                return redirect(app.config['BASE_URL'] + '/account?msg=Something+broke.+Try+again+later', 302)                
            if (check_password_hash(user.password, args['old_password']) and
                    args['new_password'] == args['confirm_password']):
                new_pw_hash = generate_password_hash(args['new_password'], method="sha256", salt_length=16)
                user.password = new_pw_hash
                user.save()
                return redirect(app.config['BASE_URL'] + '/account?umsg=Password+Changed+Successfully&color=green', 302)
            elif (not check_password_hash(user.password, args['old_password']) and 
                    args['new_password'] == args['confirm_password']):
                return redirect(app.config['BASE_URL'] + '/account?msg=Incorrect+Password', 302)
            elif (check_password_hash(user.password, args['old_password']) and 
                    not args['new_password'] == args['confirm_password']):
                return redirect(app.config['BASE_URL'] + '/account?msg=Passwords+do+not+match', 302)
            else:
                return redirect(app.config['BASE_URL'] + '/account?msg=Incorrect+Password.+Passwords+do+not+match', 302)
        else:
            return redirect(app.config['BASE_URL'] +'/login')

@app.route('/api_documentation')
def docs():
    signup = """<a href="/signup" style="display: inline-block;"><button type="submit" class="button">Signup</button></a>"""
    if session.get('access_token'):
        user = User.objects(current_token=session['access_token']).first()
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
