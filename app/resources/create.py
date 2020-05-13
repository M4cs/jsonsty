from flask_restful import Resource, reqparse
from app import app, mongo, create_chain
from app.models.models import User, Store, UniqueKeys
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
        user = User.objects(api_key=args['Api-Key']).first()
        if user:
            pass
        else:
            print('Failed')
            return {"error": "Unauthorized"}, 403
        vresult = verify_name(store_name)
        if vresult:
            pass
        else:
            return {"error": "Store name not allowed"}, 403     
        if user.store_count == 100:
            return {"error": "Reached 100 store maximum!"}, 403
        else:
            store = Store.objects(owner=user.email, name=store_name).first()
            if store:
               return { "error": "Name in use already" }, 403
            data, NONCE, MAC = encrypt_and_encode('{ "key" : "value" }', app.config['AES_KEY'])
            store_db = Store(name=store_name, owner=user.email, data=data).save()
            if store_db:
                uk_obj = UniqueKeys(store_id=store_db.id, nonce=NONCE, mac=MAC).save()
                if uk_obj:
                    store_ids = [store.id for store in Store.objects(owner=user.email).all()]
                    user.store_count += 1
                    user.stores = store_ids
                    user.save()
                    return { "message": "Success", "name": store_name }, 200
        return { "message": "Failure. Something went wrong!" }, 401
