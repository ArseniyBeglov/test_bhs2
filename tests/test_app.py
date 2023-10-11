import pytest
from flask_jwt_extended import create_access_token, JWTManager

from main import app, db, User, Asset, top_assets_cache, update_top_assets_cache
from passlib.hash import sha256_crypt

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        db.create_all()

    yield client

    with app.app_context():
        db.drop_all()

def test_registration(client):
    response = client.post('/sign-up', data={
        'username': 'test_user',
        'password1': 'password123',
        'password2': 'password123'
    })
    assert response.status_code == 201

def test_registration_with_existing_username(client):
    user = User(username='existing_user', hased_password='hashed_password')
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response = client.post('/sign-up', data={
        'username': 'existing_user',
        'password1': 'password123',
        'password2': 'password123'
    })
    assert response.status_code == 401

def test_login(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    assert response.status_code == 200

def test_login_with_invalid_credentials(client):
    response = client.post('/login', data={
        'username': 'non_existing_user',
        'password': 'invalid_password'
    })
    assert response.status_code == 401



def test_asset_by_user_route_unauthenticated(client):
    # Отправляем GET-запрос на защищенный маршрут /asset/by-user без JWT-токена
    response = client.get('/asset/by-user')

    # Проверяем, что статус код ответа - 401 Unauthorized
    assert response.status_code == 401

def test_asset_by_user_route_authenticated(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()

    response = client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})

    response = client.get('/asset/by-user', headers={'Authorization': "Bearer {}".format(access_token)})

    assert response.status_code == 200

def test_asset_update_asset_id_authenticated(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()

    client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})

    client.put('/asset/update/1', data={
        'name': 'New Asset gg',
        'description': 'Description for New Asset gg',
        'price': 2100.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})

    response = client.get('/asset/by-user', headers={'Authorization': "Bearer {}".format(access_token)})

    assert response.status_code == 200
    assert response.json[0] == [1,"New Asset gg","Description for New Asset gg",2100.0,1]

def test_asset_by_user_asset_id_route_authenticated(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()

    client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})
    client.post('/asset/add', data={
        'name': 'New Asset2',
        'description': 'Description for New Asset2',
        'price': 100.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})

    response = client.get('/asset/by-user/2', headers={'Authorization': "Bearer {}".format(access_token)})
    assert response1.status_code == 200
    assert response.json == [2,"New Asset2","Description for New Asset2",100.0,1]

def test_asset_top_route_authenticated(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()

    client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})
    client.post('/asset/add', data={
        'name': 'New Asset2',
        'description': 'Description for New Asset2',
        'price': 100.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})

    response = client.get('/asset/top', headers={'Authorization': "Bearer {}".format(access_token)})
    assert response.status_code == 200
    assert response.json == [[1,"New Asset","Description for New Asset",200.0,1],
                             [2,"New Asset2","Description for New Asset2",100.0,1]]

def test_asset_delete_asset_id_route_authenticated(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()

    client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})
    client.post('/asset/add', data={
        'name': 'New Asset2',
        'description': 'Description for New Asset2',
        'price': 100.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})

    response = client.delete('/asset/delete/1', headers={'Authorization': "Bearer {}".format(access_token)})
    assert response.status_code == 200
    response = client.get('/asset/by-user', headers={'Authorization': "Bearer {}".format(access_token)})
    assert response.json[0] == [2,"New Asset2","Description for New Asset2",100.0,1]

def test_asset_buy_asset_id_route_authenticated(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()

    client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})
    client.post('/asset/add', data={
        'name': 'New Asset2',
        'description': 'Description for New Asset2',
        'price': 100.0
    }, headers={'Authorization': "Bearer {}".format(access_token)})

    user1 = User(username='test_user1', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user1)
        db.session.commit()

    response2 = client.post('/login', data={
        'username': 'test_user1',
        'password': 'password123'
    })
    access_token1 = response2.get_json()

    response = client.put('/asset/buy/1', headers={'Authorization': "Bearer {}".format(access_token1)})
    assert response.status_code == 201
    response = client.get('/asset/by-user', headers={'Authorization': "Bearer {}".format(access_token1)})
    assert response.json[0] == [1,"New Asset","Description for New Asset",200.0,2]
    response4 = client.get('/asset/by-user', headers={'Authorization': "Bearer {}".format(access_token)})
    assert response4.json[0] == [2,"New Asset2","Description for New Asset2",100.0,1]

def test_add_asset_route_unauthenticated(client):
    # Send a POST request to the /asset/add route without providing a JWT token
    response = client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    })

    # Check that the response status code is 401 Unauthorized
    assert response.status_code == 401

def test_add_asset_route_authenticated(client):
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()

    response = client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    },  headers={'Authorization': "Bearer {}".format(access_token)})

    # Check that the response status code is 401 Unauthorized
    assert response.status_code == 201


def test_index_route_authenticated(client):
    # Create a user and generate a JWT token for authentication
    user = User(username='test_user', hased_password=sha256_crypt.hash('password123'))
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    response1 = client.post('/login', data={
        'username': 'test_user',
        'password': 'password123'
    })
    access_token = response1.get_json()
    # Send a GET request to the / route with the JWT token
    response = client.get('/', headers={'Authorization': "Bearer {}".format(access_token)})

    # Check that the response status code is 200 OK
    assert response1.status_code == 200

    # Check that the response contains the expected message
    expected_message = {"message": "Hello Flask!"}
    assert response.get_json() == expected_message


if __name__ == '__main__':
    pytest.main()
