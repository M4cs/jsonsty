from app import mongo
from mongoengine import *

class User(mongo.Document):
    meta = { 'collection': 'users' }
    email = StringField(max_length=90, unique=True)
    password = StringField()
    date_created = DateTimeField()
    store_count = IntField(min_value=0, default=0)
    current_token = StringField(default='')
    api_key = StringField(unique=True)
    stores = ListField()
    account_type = StringField()
    
    def get_stores(self):
        return Store.objects(owner=self.email).all()
    
class Store(mongo.Document):
    meta = { 'collection': 'stores' }
    name = StringField()
    data = StringField()
    owner = StringField()

    def to_json(self, data):
        return {
            'id': str(self.id),
            'name': self.name,
            'owner': self.owner,
            'data': data
        }
    
class UniqueKeys(mongo.Document):
    meta = { 'collection': 'unique_keys' }
    store_id = ObjectIdField()
    nonce = StringField()
    mac = StringField()