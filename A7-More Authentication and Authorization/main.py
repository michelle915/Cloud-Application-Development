# Standard library imports
from functools import wraps
import json
from os import environ as env
from urllib.request import urlopen
from urllib.parse import quote_plus, urlencode

# Third-party imports
from dotenv import find_dotenv, load_dotenv
from flask import Flask, request, jsonify, redirect, render_template, session, url_for, _request_ctx_stack
from flask_cors import cross_origin
from jose import jwt
from werkzeug.exceptions import HTTPException
from authlib.integrations.flask_client import OAuth
from google.cloud import datastore
import requests

# Local application imports
import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

client = datastore.Client()

# setup_logging()

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    api_base_url=f'https://{env.get("AUTH0_DOMAIN")}',
    access_token_url=f'https://{env.get("AUTH0_DOMAIN")}/oauth/token',
    authorize_url=f'https://{env.get("AUTH0_DOMAIN")}/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen(f'https://{env.get("AUTH0_DOMAIN")}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=env.get("AUTH0_CLIENT_ID"),
                issuer=f'https://{env.get("AUTH0_DOMAIN")}/'
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

@app.route('/')
def welcome():
    return render_template('welcome.html')

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
# @app.route('/login', methods=['POST'])
# def login_user():
#     content = request.get_json()
#     username = content["username"]
#     password = content["password"]
#     body = {'grant_type':'password','username':username,
#             'password':password,
#             'client_id':env.get("AUTH0_CLIENT_ID"),
#             'client_secret':env.get("AUTH0_CLIENT_SECRET")
#            }
#     headers = { 'content-type': 'application/json' }
#     url = f'https://{env.get("AUTH0_DOMAIN")}/oauth/token'
#     r = requests.post(url, json=body, headers=headers)
#     return r.text, 200, {'Content-Type':'application/json'}

@app.route('/login')
def login():
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))

@app.route('/callback')
def callback():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session['jwt'] = auth0.token['id_token'] 
    session['profile'] = userinfo 

    return redirect('/user-info')

@app.route('/user-info')
def user_info():
    return render_template('userinfo.html', jwt=session.get('jwt'), user_info=session.get('profile'))

# Route for creating a boat
@app.route('/boats', methods=['POST'])
def post_boat():
    # Validate JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        app.logger.error(f'Exception in /boats: {e}', exc_info=True)
        return jsonify({"error": str(e)}), 401
    
    content = request.get_json()

    # Extract 'sub' from JWT payload to use as owner
    owner = payload.get('sub')
    if not owner:
        return jsonify({"error": "Unable to identify owner from JWT"}), 400

    # Create and store new boat
    new_boat = datastore.Entity(key=client.key(constants.boats))
    new_boat.update({
        "name": content["name"],
        "type": content["type"],
        "length": content["length"],
        "public": content["public"],
        "owner": owner
    })
    client.put(new_boat)

    # Update the boat's id and owner attributes 
    new_boat["id"] = new_boat.key.id
    client.put(new_boat)
    
    # Return created boat, along with a generated self-link
    response = {
        "id": new_boat["id"],
        "name": new_boat["name"],
        "type": new_boat["type"],
        "length": new_boat["length"],
        "owner": owner,
        "public": content["public"],
        "self": f"{request.url_root}boats/{new_boat['id']}"
    }
    return jsonify(response), 201

# Route for getting all boats
@app.route('/boats', methods=['GET'])
def get_boats():
    # If JWT is valid, return boats corresponding to owner who matches the JWT sub property
    try:
        payload = verify_jwt(request)
        sub = payload.get('sub')
        query = client.query(kind=constants.boats)
        query.add_filter("owner", "=", sub)

    # If JWT is missing or invalid, return all public boats, regardless of owner    
    except AuthError:
        query = client.query(kind=constants.boats)
        query.add_filter("public", "=", True)

    results = list(query.fetch())
    return jsonify(results), 200

# Route to delete a boat
@app.route('/boats/<id>', methods=['DELETE'])
def delete_boat(id):
    # Get boat
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)

    # Ensure boat exists
    if not boat:
        return jsonify({"Error": "Boat not found"}), 403
    
    # Validate JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return handle_auth_error(e)
    
    # Check owner
    if boat['owner'] != payload.get('sub'):
        return jsonify({"Error": "You are not the owner of this boat"}), 403

    client.delete(boat_key)
    return '', 204

# Route to get all boats from a specified owner
@app.route('/owners/<owner_id>/boats', methods=['GET'])
def get_public_boats_by_owner(owner_id):
    query = client.query(kind=constants.boats)
    query.add_filter("owner", "=", owner_id)
    query.add_filter("public", "=", True)
    results = list(query.fetch())
    return jsonify(results), 200

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

