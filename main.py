from flask import Flask, jsonify, request, flash, session, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_swagger_ui import get_swaggerui_blueprint
from passlib.hash import sha256_crypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, current_user

SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'

db = SQLAlchemy()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sdfcdfcdvcdfvgbtredcvgtr345rd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://arsenijbeglov:iamroot@localhost:5432/bhs_db'
jwt = JWTManager(app)

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "Test application for bhs"
    },
    # oauth_config={  # OAuth config. See https://github.com/swagger-api/swagger-ui#oauth2-configuration .
    #    'clientId': "your-client-id",
    #    'clientSecret': "your-client-secret-if-required",
    #    'realm': "your-realms",
    #    'appName': "your-app-name",
    #    'scopeSeparator': " ",
    #    'additionalQueryStringParams': {'test': "hello"}
    # }
)

app.register_blueprint(swaggerui_blueprint)

db.init_app(app)


class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Float, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __init__(self, name, description, price, owner_id):
        self.name = name
        self.description = description
        self.price = price
        self.owner_id = owner_id


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hased_password = db.Column(db.String(120), unique=True, nullable=False)
    assets = db.relationship('Asset', backref='owner', lazy='dynamic')

    def __init__(self, username, hased_password):
        self.username = username
        self.hased_password = hased_password


with app.app_context():
    db.create_all()


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()
    if user:
        if sha256_crypt.verify(password, user.hased_password):
            access_token = create_access_token(identity=user)
            return jsonify(message='Login Successful', access_token=access_token), 200
        else:
            return jsonify('not correct username or password'), 401
    else:
        return jsonify('not correct username or passwoord'), 401


@app.route('/logout', methods=['DELETE'])
def logout():
    return redirect('/')


@app.route('/sign-up', methods=['POST'])
def sing_up():
    if request.method == "POST":
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        print(username)
        user = User.query.filter_by(username=username).first()

        if user:
            return jsonify('Bad email or Password'), 401
        elif len(username) < 2:
            return jsonify('Bad email or Password'), 401
        elif password1 != password2:
            return jsonify('Bad email or Password'), 401
        elif len(password1) < 7:
            return jsonify('Bad email or Password'), 401
        else:
            newUser = User(username=username, hased_password=sha256_crypt.hash(
                password1))
            db.session.add(newUser)
            db.session.commit()

            return jsonify(message='User created successfully'), 201


@app.route('/', methods=['GET'])
@jwt_required()
def index():
    return jsonify(message="Hello Flask!")


top_assets_cache = {}


def update_top_assets_cache(user_id):
    user = User.query.get(user_id)
    assets = Asset.query.filter_by(owner_id=user_id).order_by(Asset.price.desc()).limit(5).all()
    list = []
    for asset in assets:
        list.append([asset.id, asset.name, asset.description, asset.price, asset.owner_id])
    top_assets_cache[user.id] = list


@app.route('/user', methods=['GET'])
@jwt_required()
def get_user_info():
    return jsonify(id=current_user.id,
                   username=current_user.username), 200


@app.route('/update/user', methods=['PUT'])
@jwt_required()
def update_user():
    username = request.form.get('username')
    password = request.form.get('password')
    if len(username) < 1:
        return jsonify(message='user not updated successfully'), 401
    else:
        user = User.query.get(current_user.id)
        user.username = username
        user.hased_password = sha256_crypt.hash(password)
        db.session.commit()
        return jsonify(message='user updated successfully'), 201


@app.route('/asset/by-user', methods=['GET'])
@jwt_required()
def home():
    user_assets = Asset.query.filter_by(owner_id=current_user.id).all()
    list = []
    for asset in user_assets:
        list.append([asset.id, asset.name, asset.description, asset.price, asset.owner_id])
    return jsonify(list), 200


@app.route('/asset/by-user/<int:asset_id>', methods=['GET'])
@jwt_required()
def asset_by_id(asset_id):
    asset = Asset.query.filter_by(id=asset_id).first()
    if asset is not None:
        list = [asset.id, asset.name, asset.description, asset.price, asset.owner_id]
        return jsonify(list), 200


@app.route('/asset/top', methods=['GET'])
@jwt_required()
def top():
    user_assets = Asset.query.filter_by(owner_id=current_user.id).order_by(Asset.price.desc()).limit(5).all()
    list = []
    for asset in user_assets:
        list.append([asset.id, asset.name, asset.description, asset.price, asset.owner_id])
    return jsonify(list), 200


@app.route('/asset/add', methods=['POST'])
@jwt_required()
def add_asset():
    name = request.form.get('name')  # Поле для имени ассета
    description = request.form.get('description')  # Поле для описания ассета
    price = request.form.get('price')

    update_top_assets_cache(current_user.id)

    if len(name) < 1:
        return jsonify('Bad name'), 401
    else:
        new_asset = Asset(name=name, description=description, price=price, owner_id=current_user.id)
        db.session.add(new_asset)
        db.session.commit()
        return jsonify(message='asset created successfully'), 201


@app.route('/asset/delete/<int:asset_id>', methods=['DELETE'])
@jwt_required()
def delete_asset(asset_id):
    asset = Asset.query.get(asset_id)
    if asset and asset.owner_id == current_user.id:
        db.session.delete(asset)
        db.session.commit()
        update_top_assets_cache(current_user.id)
        return jsonify(message='asset deleted successfully'), 201
    else:
        return jsonify(message='asset not deleted '), 401


@app.route('/asset/update/<int:asset_id>', methods=['PUT'])
@jwt_required()
def update_asset(asset_id):
    name = request.form.get('name')  # Поле для имени ассета
    description = request.form.get('description')  # Поле для описания ассета
    price = request.form.get('price')
    if len(name) < 1:
        return jsonify(message='asset not updated successfully'), 401
    else:
        asset = Asset.query.filter_by(id=asset_id).first()
        asset.name = name
        asset.description = description
        asset.price = price
        db.session.commit()
        return jsonify(message='asset updated successfully'), 201


@app.route('/asset/buy/<int:asset_id>', methods=['PUT'])
@jwt_required()
def buy_asset(asset_id):
    if Asset.query.get(asset_id) is None or User.query.filter_by(id=current_user.id) is None:
        return jsonify(message='asset not bought successfully'), 401
    else:
        asset = Asset.query.get(asset_id)
        asset.owner_id = current_user.id
        db.session.commit()
        return jsonify(message='asset bought successfully'), 201


if __name__ == '__main__':
    app.run()
