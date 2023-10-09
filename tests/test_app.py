import pytest
from flask_jwt_extended import create_access_token

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





def test_add_asset_route_unauthenticated(client):
    # Send a POST request to the /asset/add route without providing a JWT token
    response = client.post('/asset/add', data={
        'name': 'New Asset',
        'description': 'Description for New Asset',
        'price': 200.0
    })

    # Check that the response status code is 401 Unauthorized
    assert response.status_code == 401

if __name__ == '__main__':
    pytest.main()
