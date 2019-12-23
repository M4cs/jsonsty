from flask_restful import Resource, reqparse
from app import app, mongo, mhelp, create_chain
from app.helpers.db_helpers import check_token, check_api_key
from app.helpers.crypto_helpers import encrypt_and_encode
from app.helpers.input_helpers import verify_name
from uuid import uuid4
from flask import session, request
import json

def create_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('Api-Key', required=True, location='headers')
    return parser


class CreateStore(Resource):
    def post(self):
        parser = create_parser()
        args = parser.parse_args()
        store_template = json.loads(request.data)
        data = json.dumps(store_template['data'])
        store_name = store_template['store_name'].strip()
        if check_api_key(args['Api-Key']):
            pass
        else:
            print('Failed')
            return {"error": "Unauthorized"}, 403
        vresult = verify_name(store_name)
        if vresult:
            pass
        else:
            return {"error": "Store name not allowed"}, 403
        user = mhelp.get_user({'api_key': args['Api-Key']})
        if user['store_count'] == 100:
            return {"error": "Reached 100 store maximum!"}, 403
        else:
            store = mhelp.get_single_store({'owner': user['email'], 'name': store_name})
            if store:
               return { "error": "Name in use already" }, 403
            count = user['store_count'] + 1
            data, NONCE, MAC = encrypt_and_encode('{ "key" : "value" }', app.config['AES_KEY'])
            docinsertion = mongo.db.stores.insert_one({'name': store_name, 'owner': user['email'], 'data': data})
            mongo.db.unique_keys.insert_one({
                'store_id': docinsertion.inserted_id,
                'nonce': NONCE,
                'mac' : MAC
            })
            stores = mhelp.get_store_ids({'owner': user['email']})
            mongo.db.free_users.update_one({'email': user['email']}, {'$set': { 'store_count': count, 'stores': stores }})
        return { "message": "Success", "name": store_name }, 200
