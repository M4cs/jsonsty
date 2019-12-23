import unittest
from app import app, mongo, mhelp
from uuid import uuid4
import json, os
import urllib.parse as urlparse

class MockUserCreds:
    email = 'test_user{}@example.com'.format(str(uuid4()).split('-')[0][0:4])
    password = str(uuid4())
    api_key = None
    store_template = {
        'store_name': 'test_store_name',
        'data': {
            'test_key': 'test_value',
            'test_key_w_sub_dict': {
                'test_key': ['test_va1', 'test_val2']
                }
            }
    }
    count = 0
    
mock_user = MockUserCreds()

def print_title(title):
    print(title.center(45, '='))

class APITests(unittest.TestCase):
    app = None
    
    def setUp(self):
        app.testing = True
        self.app = app.test_client()
             
    def test_1_signup(self):
        print_title('Testing Signup')
        res = self.app.post('/signup', data={
            'email': mock_user.email,
            'password': mock_user.password
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        self.assertTrue(res.status_code, 200)
        mock_user.count += 1
        
    def test_2_login(self):
        print_title('Testing Login')
        res = self.app.post('/api_v1/login', data={
            'email': mock_user.email,
            'password': mock_user.password
        })
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertIsNotNone(data['api-key'])
        mock_user.api_key = data['api-key']
        mock_user.count += 1
        
    def test_3_get_all_stores(self):
        print_title('Testing Get All Stores')
        res = self.app.get('/api_v1/all_stores', headers={'Api-Key': mock_user.api_key})
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        for store in data['stores']:
            self.assertEqual(store['owner'], mock_user.email)
        mock_user.count += 1
            
    def test_4_create_store(self):
        print_title('Testing Create Store')
        res = self.app.post('/api_v1/create', headers={
                'Api-Key': mock_user.api_key,
                'Content-Type': 'application/json'
            },
            data=json.dumps(mock_user.store_template)
        )
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertTrue(data['message'] == 'Success')
        self.assertEqual(data['name'], mock_user.store_template['store_name'])
        mock_user.count += 1
    
    def test_5_get_all_stores_w_multiple_stores(self):
        print_title('Testing Get All Stores After Creation')
        res = self.app.get('/api_v1/all_stores', headers={'Api-Key': mock_user.api_key})
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertEqual(len(data['stores']), 2)
        for store in data['stores']:
            self.assertEqual(store['owner'], mock_user.email)
        mock_user.count += 1
    
    def test_9_edit_store(self):
        print_title('Testing PUT on Store (Edit)')
        res = self.app.get('/api_v1/all_stores', headers={'Api-Key': mock_user.api_key})
        data = json.loads(res.data)
        store = data['stores'][0]
        new_data = {'key': 'newvalue11'}
        res = self.app.put('/api_v1/stores/{}'.format(urlparse.quote_plus(store['name'])), headers={'Api-Key': mock_user.api_key}, data=json.dumps(new_data))
        self.assertTrue(res.status_code == 200)
        res = self.app.get('/api_v1/stores/{}'.format(urlparse.quote_plus(store['name'])), headers={'Api-Key': mock_user.api_key})
        store = json.loads(res.data)
        self.assertTrue(res.status_code == 200)
        self.assertNotEqual(new_data, store['data'])
    
    def test_a1_delete_stores(self):
        print_title('Testing DELETE on Store (Delete)')
        res = self.app.get('/api_v1/all_stores', headers={'Api-Key': mock_user.api_key})
        data = json.loads(res.data)
        for store in data['stores']:
            res = self.app.delete('/api_v1/stores/{}'.format(urlparse.quote_plus(store['name'])), headers={'Api-Key': mock_user.api_key})
            self.assertTrue(res.status_code == 200)
            self.assertTrue(res.json == { 'message': 'Success' })
            
    def test_a2_clean_up(self):
        print_title('Cleaning Up Database')
        mongo.db.free_users.find_one_and_delete({'email': mock_user.email})

if __name__ == "__main__":
    unittest.main()            
