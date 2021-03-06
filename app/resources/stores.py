from flask_restful import Resource, reqparse
from flask import request
from app import app, mongo, mhelp
from app.helpers.crypto_helpers import encrypt_and_encode, decode_and_decrypt
import json
import urllib.parse as urlparse

def get_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('Api-Key', location='headers', required=True)
    return parser

class GetAllStores(Resource):
    def get(self):
        parser = get_parser()
        args = parser.parse_args()
        user = mhelp.get_user({ 'api_key': args['Api-Key']})
        if user:
            stores = mhelp.get_stores({'owner': user['email']})
            for store in stores:
                keys = mongo.db.unique_keys.find_one({'store_id' : store['_id']})
                encrypted_data = store['data']
                NONCE = keys['nonce']
                MAC = keys['mac']
                store['data'] = decode_and_decrypt(encrypted_data, NONCE, MAC, app.config['AES_KEY'])
                store['_id'] = str(store['_id'])
            return {'stores': stores}, 200
        else:
            return { "error": "You must authorize first. Please login or signup."}, 403

class SingleStore(Resource):
    def get(self, store_name):
        parser = get_parser()
        args = parser.parse_args() 
        store_name = urlparse.unquote_plus(store_name)
        user = mhelp.get_user({ 'api_key': args['Api-Key']})
        store = mhelp.get_single_store({'owner': user['email'], 'name': store_name})
        if store and user:
            keys = mongo.db.unique_keys.find_one({'store_id' : store['_id']})
            encrypted_data = store['data']
            NONCE = keys['nonce']
            MAC = keys['mac']
            store['data'] = decode_and_decrypt(encrypted_data, NONCE, MAC, app.config['AES_KEY'])
            store['_id'] = str(store['_id'])
            requested_store = store
            return requested_store, 200
        elif not store and user:
            return { "error": "Store Not Found" }, 404
        else:
            return { "error": "Authorization Error. Please Pass Your Valid Access Token!"}, 403
            
    def put(self, store_name):
        parser = get_parser()
        args = parser.parse_args()
        store_name = urlparse.unquote_plus(store_name)
        data = json.dumps(request.get_json())
        data, NONCE, MAC = encrypt_and_encode(data, app.config['AES_KEY'])
        user = mhelp.get_user({ 'api_key': args['Api-Key']})
        store = mhelp.get_single_store({'owner': user['email'], 'name': store_name})
        if store and user:
            mongo.db.unique_keys.find_one_and_update({'store_id': store['_id']}, {'$set': { 'nonce': NONCE}})
            mongo.db.unique_keys.find_one_and_update({'store_id': store['_id']}, {'$set': { 'mac': MAC}})
            mongo.db.stores.find_one_and_update({'owner': user['email'], 'name': store_name}, {'$set': {'data': data}})
            return { "message": "Updated Store." }, 200
        elif not store and user:
            return { "error": "Store Not Found" }, 404
        else:
            return { "error": "Authorization Error. Please Pass Your Valid Access Token!"}, 403
        
    def delete(self, store_name):
        parser = get_parser()
        args = parser.parse_args()
        store_name = urlparse.unquote_plus(store_name)
        user = mhelp.get_user({ 'api_key': args['Api-Key']})
        store = mhelp.get_single_store({'owner': user['email'], 'name': store_name})
        if store and user:
            mongo.db.stores.find_one_and_delete({'_id': store['_id']})
            mongo.db.unique_keys.find_one_and_delete({'store_id': store['_id']})
            old_stores = mhelp.get_store_ids({'owner': user['email']})
            mongo.db.free_users.find_one_and_update({'email': user['email'] }, { '$set': {'stores': old_stores, 'store_count': user['store_count'] - 1}})
            return { 'message': 'Success' }, 200
        elif not store and user:
            return { "error": "Store Not Found" }, 404
        else:
            return { "error": "Authorization Error. Please Pass Your Valid Access Token!"}, 403
