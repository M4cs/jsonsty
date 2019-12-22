from flask_restful import Resource, reqparse
from app.helpers.db_helpers import check_email
from werkzeug.security import check_password_hash, generate_password_hash
from app import app, mongo, mhelp, create_chain
from uuid import uuid4
from bson import ObjectId
from datetime import datetime


def signup_parser():
    parser = reqparse.RequestParser()
    parser.add_argument('email', required=True)
    parser.add_argument('password', required=True)
    return parser

class JSONLogin(Resource):
    def post(self):
        parser = signup_parser()
        args = parser.parse_args()
        result = check_email(args['email'])
        if not result:
            return {"error": "No Account with that E-Mail Exists!"}, 403
        else:
            pass
        user = mhelp.get_user({'email': args['email']})
        if user and check_password_hash(user.get('password'), args['password']):
            access_token = str(uuid4())
            mongo.db.free_users.find_one_and_update({'email': args['email']}, {'$set': { 'current_token': access_token } })
            return {"message": "Logged In!", "api-key": user['api_key']}, 200
        elif not user:
            return {"error": "Something broke"}, 500
        else:
            return { "error": "Incorrect Password!" }, 403
