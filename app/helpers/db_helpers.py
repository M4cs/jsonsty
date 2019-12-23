from bson import ObjectId
    

def check_email(email):
    from app import mongo
    from app.models.models import User
    user = User.objects(email=email).first()
    match = False
    if user:
        match = True
    return match

def check_token(token):
    from app import mongo
    collection = mongo.db.free_users
    match = False
    for user in collection.find():
        if user.get('current_token') == token:
            match = True
        else:
            pass
    return match

def check_api_key(api_key):
    from app import mongo
    user = mongo.db.free_users.find_one({'api_key': api_key})
    if user.get('_id'):
        return True
    else:
        return False

class ModelHelpers:
    
    @staticmethod
    def get_store_ids(query):
        from app import mongo
        stores = []
        for store in mongo.db.stores.find(query):
            stores.append(ObjectId(store.get('_id')))
        return stores
    
    @staticmethod
    def get_stores(query):
        from app import mongo
        stores = []
        for store in mongo.db.stores.find(query):
            stores.append(store)
        return stores
    
    @staticmethod
    def get_user(query):
        from app import mongo
        user = mongo.db.free_users.find_one(query)
        return user
    
    @staticmethod
    def get_single_store(query):
        from app import mongo
        store = mongo.db.stores.find_one(query)
        return store