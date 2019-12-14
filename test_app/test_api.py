import unittest
from app import app, mongo, mhelp
from uuid import uuid4
import json, os

class MockUserCreds:
    email = 'test_user{}@example.com'.format(str(uuid4()).split('-')[0][0:4])
    password = str(uuid4())
    access_token = None
    store_template = {
        'test_key': 'test_value',
        'test_key_w_sub_dict': {
            'test_key': ['test_va1', 'test_val2']
        }
    }
    count = 0
    
mock_user = MockUserCreds()

class APITests(unittest.TestCase):
    app = None
    
    def setUp(self):
        app.testing = True
        self.app = app.test_client()
        
        
    def test_1_signup(self):
        res = self.app.post('/signup', data={
            'email': mock_user.email,
            'password': mock_user.password
        })
        self.assertTrue(res.status_code, 200)
        self.assertTrue(res.json, json.dumps({'message': 'Signed Up!'}))
        mock_user.count += 1
        
    def test_2_login(self):
        res = self.app.post('/api_v1/login', data={
            'email': mock_user.email,
            'password': mock_user.password
        })
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertIsNotNone(data['access_token'])
        mock_user.access_token = data['access_token']
        mock_user.count += 1
        
    def test_3_get_all_stores(self):
        res = self.app.get('/api_v1/all_stores', headers={'Access-Token': mock_user.access_token})
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        for store in data['stores']:
            self.assertEqual(store['owner'], mock_user.email)
        mock_user.count += 1
            
    def test_4_create_store(self):
        res = self.app.post('/api_v1/create', headers={
                'Access-Token': mock_user.access_token,
                'Content-Type': 'application/json'
            },
            data=json.dumps(mock_user.store_template)
        )
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertTrue(data['message'] == 'Success')
        self.assertIsNotNone(data['name'])
        mock_user.count += 1
    
    def test_5_get_all_stores_w_multiple_stores(self):
        res = self.app.get('/api_v1/all_stores', headers={'Access-Token': mock_user.access_token})
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertEqual(len(data['stores']), 2)
        for store in data['stores']:
            self.assertEqual(store['owner'], mock_user.email)
        mock_user.count += 1
            
    def test_6_create_third_store(self):
        res = self.app.post('/api_v1/create', headers={
                'Access-Token': mock_user.access_token,
                'Content-Type': 'application/json'
            },
            data=json.dumps(mock_user.store_template)
        )
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertTrue(data['message'] == 'Success')
        self.assertIsNotNone(data['name'])
        mock_user.count += 1
    
    def test_7_get_all_stores_with_three(self):
        res = self.app.get('/api_v1/all_stores', headers={'Access-Token': mock_user.access_token})
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 200)
        self.assertEqual(len(data['stores']), 3)
        for store in data['stores']:
            self.assertEqual(store['owner'], mock_user.email)
        mock_user.count += 1
            
    def test_8_max_at_three(self):
        res = self.app.post('/api_v1/create', headers={
                'Access-Token': mock_user.access_token,
                'Content-Type': 'application/json'
            },
            data=json.dumps(mock_user.store_template)
        )
        data = json.loads(res.data)
        self.assertTrue(res.status_code, 403)
        self.assertTrue(data['error'] == 'Reached 3 store maximum!')
        mock_user.count += 1
    
    def test_9_edit_store(self):
        res = self.app.get('/api_v1/all_stores', headers={'Access-Token': mock_user.access_token})
        data = json.loads(res.data)
        store = data['stores'][0]
        old_data = store['data']
        new_data = old_data.update({'new_value': 'value11'})
        res = self.app.put('/api_v1/stores/{}'.format(store['name']), headers={'Access-Token': mock_user.access_token}, data=json.dumps(new_data))
        self.assertTrue(res.status_code == 200)
        res = self.app.get('/api_v1/stores/{}'.format(store['name']), headers={'Access-Token': mock_user.access_token})
        data = json.loads(res.data)
        self.assertTrue(res.status_code == 200)
        self.assertNotEqual(mock_user.store_template, data)
    
    def test_a1_delete_stores(self):
        res = self.app.get('/api_v1/all_stores', headers={'Access-Token': mock_user.access_token})
        data = json.loads(res.data)
        for store in data['stores']:
            res = self.app.delete('/api_v1/stores/{}'.format(store['name']), headers={'Access-Token': mock_user.access_token})
            self.assertTrue(res.status_code == 200)
            self.assertTrue(res.json == { 'message': 'Success' })
            
    def test_a2_clean_up(self):
        mongo.db.free_users.find_one_and_delete({'email': mock_user.email})
        mongo.db.stores.delete_many({'owner': mock_user.email})
            