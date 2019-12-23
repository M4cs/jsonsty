from flask_restful import Resource, reqparse
from flask import request
from app import app, mongo, mhelp
from app.helpers.crypto_helpers import encrypt_and_encode, decode_and_decrypt
from app.models.models import UniqueKeys, User, Store
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
        user = User.objects(api_key=args['Api-Key']).first()
        if user:
            stores = []
            for store in user.stores:
                store_dict = {}
                store_obj = Store.objects(id=store).first()
                keys = UniqueKeys.objects(store_id=store).all()
                if len(keys) == 1:
                    encrypted_data = store_obj.data
                    NONCE = keys[0].nonce
                    MAC = keys[0].mac
                    source_dict = decode_and_decrypt(encrypted_data, NONCE, MAC, app.config['AES_KEY'])
                    source_json = json.dumps(source_dict)
                    store_dict['id'] = str(store_obj.id)
                    store_dict['name'] = store_obj.name
                    store_dict['owner'] = user.email
                    store_dict['data'] = source_json
                stores.append(store_dict)
            print({'stores': stores})
            return {'stores': stores}, 200
        else:
            return { "error": "You must authorize first. Please login or signup."}, 403

class SingleStore(Resource):
    def get(self, store_name):
        parser = get_parser()
        args = parser.parse_args() 
        store_name = urlparse.unquote_plus(store_name)
        user = User.objects(api_key=args['Api-Key']).first()
        store = Store.objects(owner=user.email, name=store_name).first()
        if store and user:
            keys = UniqueKeys.objects(store_id=store.id).first()
            encrypted_data = store.data
            NONCE = keys.nonce
            MAC = keys.nonce
            source_dict = decode_and_decrypt(encrypted_data, NONCE, MAC, app.config['AES_KEY'])
            source_json = json.dumps(source_dict)
            requested_store = source_json
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
        user = User.objects(api_key=args['Api-Key']).first()
        store = Store.objects(owner=user.email, name=store_name).first()
        if store and user:
            uk_obj = UniqueKeys(store_id=store.id, nonce=NONCE, mac=MAC).save()
            if uk_obj:
                store_ids = [store.id for store in Store.objects(owner=user.email).all()]
                user.store_count += 1
                user.stores = store_ids
                user.save()
            return { "message": "Updated Store." }, 200
        elif not store and user:
            return { "error": "Store Not Found" }, 404
        else:
            return { "error": "Authorization Error. Please Pass Your Valid Access Token!"}, 403
        
    def delete(self, store_name):
        parser = get_parser()
        args = parser.parse_args()
        store_name = urlparse.unquote_plus(store_name)
        user = User.objects(api_key=args['Api-Key']).first()
        store = Store.objects(owner=user.email, name=store_name).first()
        if store and user:
            uk = UniqueKeys.objects(store_id=store.id).first()
            uk.delete()
            store.delete()
            store_ids = [store.id for store in Store.objects(owner=user.email).all()]
            user.store_count -= 1
            user.stores = store_ids
            user.save()
            return { 'message': 'Success' }, 200
        elif not store and user:
            return { "error": "Store Not Found" }, 404
        else:
            return { "error": "Authorization Error. Please Pass Your Valid Access Token!"}, 403
