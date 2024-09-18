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

@app.route('/login')
def login():
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))

@app.route('/callback')
def callback():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    jwt_token = auth0.token['id_token']
    session['jwt'] = jwt_token 
    session['profile'] = userinfo 

    # Check if user is already registered
    user_id = userinfo['sub'] 
    query = client.query(kind='User')
    query.add_filter('user_id', '=', user_id)
    results = list(query.fetch())

    # If user not registered, create new User entity
    if len(results) == 0:
        new_user = datastore.Entity(client.key('User'))
        new_user.update({
            'user_id': user_id
        })
        client.put(new_user)

    return redirect('/user-info')

@app.route('/user-info')
def user_info():
    user_id = session.get('profile')['sub']  
    jwt_token = session.get('jwt')  
    return render_template('userinfo.html', jwt=jwt_token, user_id=user_id, user_info=session.get('profile'))

# ----------------------------------------------------------------------------- USERS

@app.route('/users', methods=['GET'])
def get_users():
    query = client.query(kind='User')
    results = list(query.fetch())
    users = [{'user_id': user['user_id']} for user in results]
    return jsonify(users), 200

# ----------------------------------------------------------------------------- BOATS

# Route for creating a boat
@app.route('/boats', methods=['POST'])
def post_boat():
    # Validate JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        app.logger.error(f'Exception in /boats: {e}', exc_info=True)
        return jsonify({"error": str(e)}), 401
    
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406

    # Invalidate request when client sends an unsupported MIME type to the endpoint
    if request.content_type != 'application/json':
        response = {"Error": "Request must be JSON"}
        return jsonify(response), 415


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
        "loads":[],
        "owner": owner
    })
    client.put(new_boat)

    # Update the boat's id and owner attributes 
    new_boat["id"] = new_boat.key.id
    client.put(new_boat)
    
    new_boat["self"] = f"{request.url_root}boats/{new_boat['id']}"
    client.put(new_boat)

    # Return created boat, along with a generated self-link
    response = {
        "id": new_boat["id"],
        "name": new_boat["name"],
        "type": new_boat["type"],
        "length": new_boat["length"],
        "loads": new_boat["loads"],
        "owner": new_boat["owner"],
        "self": new_boat["self"]
    }
    return jsonify(response), 201

# Route for getting all boats
@app.route('/boats', methods=['GET'])
def get_boats():
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406

    # Setup pagination
    limit = 5
    offset = int(request.args.get('offset', 0))
    next_offset = offset + limit
    prev_offset = max(offset - limit, 0)
    
    # Validate JWT
    try:
        payload = verify_jwt(request)
        sub = payload.get('sub')
        query = client.query(kind=constants.boats)
        query.add_filter("owner", "=", sub)
        total_count_query = client.query(kind=constants.boats)
        total_count_query.add_filter("owner", "=", sub)
        total_count = len(list(total_count_query.fetch()))
    except AuthError as e:
        return handle_auth_error(e)

    # Apply pagination to the query
    query_iter = query.fetch(limit=limit, offset=offset)
    results = list(query_iter)
    next_url = '/boats?offset=' + str(next_offset) if total_count > next_offset else None
    prev_url = '/boats?offset=' + str(prev_offset) if offset > 0 else None

    # Create response
    response = {
        "boats": results,
        "total_count": total_count,
        "next": next_url,
        "prev": prev_url
    }
    return jsonify(response), 200

# UNSUPPORTED /boats ROUTES
@app.route('/boats', methods=['DELETE', 'PUT', 'PATCH'])
def unsupported_boats():
    if request.method == 'DELETE' or request.method == 'PUT' or request.method == 'PATCH':
        return 'DELETE, PUT, and PATCH requests are not supported on /boats', 405

# Route to delete a boat
@app.route('/boats/<id>', methods=['DELETE'])
def delete_boat(id):
    # Get boat
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)

    # Boat ID not found
    if not boat:
        response = {"Error": "No boat with this boat_id exists"}
        return jsonify(response), 404
    
    # Validate JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return handle_auth_error(e)
    
    # Check owner
    if boat['owner'] != payload.get('sub'):
        return jsonify({"Error": "You are not the owner of this boat"}), 403

    # Remove loads from the boat before deleting
    for load in boat["loads"]:
        load_key = client.key(constants.loads, load["id"])
        current_load = client.get(key=load_key)
        current_load["carrier"] = None
        client.put(current_load)

    client.delete(boat_key)
    return '', 204

# Route to get a boat
@app.route('/boats/<id>', methods=['GET'])
def get_boat(id):
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406

    # Get boat
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)

   # Boat ID not found
    if not boat:
        response = {"Error": "No boat with this boat_id exists"}
        return jsonify(response), 404
    
    # Validate JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return handle_auth_error(e)
    
    # Check owner
    if boat['owner'] != payload.get('sub'):
        return jsonify({"Error": "You are not the owner of this boat"}), 403

    # Return boat
    response = {
        "id": boat["id"],
        "name": boat["name"],
        "type": boat["type"],
        "length": boat["length"],
        "loads": boat["loads"],
        "owner": boat["owner"],
        "self": boat["self"]
    }
    return jsonify(response), 200

# Route to edit a boat
@app.route('/boats/<id>', methods=['PUT', 'PATCH'])
def edit_boat(id):
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406
    
    # Invalidate EDIT request when client sends an unsupported MIME type to the endpoint
    if request.content_type != 'application/json':
        response = {"Error": "Request must be JSON"}
        return jsonify(response), 415

    # Get boat
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)

   # Boat ID not found
    if not boat:
        response = {"Error": "No boat with this boat_id exists"}
        return jsonify(response), 404
    
    # Validate JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return handle_auth_error(e)
    
    # Check owner
    if boat['owner'] != payload.get('sub'):
        return jsonify({"Error": "You are not the owner of this boat"}), 403

    content = request.get_json()

    # Forbid ID edit
    if 'id' in content:
        response = {"Error": "Updating the value of id is not allowed"}
        return jsonify(response), 403

    # Invalidate inputs that have keys other than "name", "type", or "length"
    required_attributes = ["name", "type", "length"]
    if not all(key in required_attributes for key in content.keys()):
        response = {"Error": "The request object contains unsupported attributes"}
        return jsonify(response), 400

    # PUT
    if request.method == 'PUT':
        # Check for all required attributes
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        print(boat)
        boat.update(content)
        print(boat)

        client.put(boat)
        return jsonify(boat), 200

    # PATCH
    elif request.method == 'PATCH':
        print(boat)
        boat.update(content)
        print(boat)

        client.put(boat)
        return jsonify(boat), 200

    # UNKNOWN ROUTE
    else:
        return 'Edit boat method not recognized'

# ----------------------------------------------------------------------------- LOADS

# Route for creating a load
@app.route('/loads', methods=['POST'])
def post_load():
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406

    # Invalidate request when client sends an unsupported MIME type to the endpoint
    if request.content_type != 'application/json':
        response = {"Error": "Request must be JSON"}
        return jsonify(response), 415

    content = request.get_json()

    # Create and store new load
    new_load = datastore.Entity(key=client.key(constants.loads))
    new_load.update({
        "carrier": None,
        "volume": content["volume"],
        "item": content["item"],
        "creation_date": content["creation_date"]
    })
    client.put(new_load)

    # Update the load's id attribute
    new_load["id"] = new_load.key.id
    client.put(new_load)
    
    new_load["self"] = f"{request.url_root}loads/{new_load['id']}"
    client.put(new_load)

    # Return created load, along with a generated self-link
    response = {
        "id": new_load["id"],
        "carrier": new_load["carrier"],
        "volume": new_load["volume"],
        "item": new_load["item"],
        "creation_date": new_load["creation_date"],
        "self": new_load["self"]
    }
    return jsonify(response), 201

# Route for getting all loads
@app.route('/loads', methods=['GET'])
def get_loads():
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406

    # Setup pagination
    limit = 5
    offset = int(request.args.get('offset', 0))
    next_offset = offset + limit
    prev_offset = max(offset - limit, 0)
    total_count_query = client.query(kind=constants.loads)
    total_count = len(list(total_count_query.fetch()))
    
    query = client.query(kind=constants.loads)

    # Apply pagination to the query
    query_iter = query.fetch(limit=limit, offset=offset)
    results = list(query_iter)
    next_url = '/loads?offset=' + str(next_offset) if total_count > next_offset else None
    prev_url = '/loads?offset=' + str(prev_offset) if offset > 0 else None

    # Create response
    response = {
        "loads": results,
        "total_count": total_count,
        "next": next_url,
        "prev": prev_url
    }
    return jsonify(response), 200

# UNSUPPORTED /loads ROUTES
@app.route('/loads', methods=['DELETE', 'PUT', 'PATCH'])
def unsupported_loads():
    if request.method == 'DELETE' or request.method == 'PUT' or request.method == 'PATCH':
        return 'DELETE, PUT, and PATCH requests are not supported on /loads', 405

# Route to delete a load
@app.route('/loads/<id>', methods=['DELETE'])
def delete_load(id):
    # Get load
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)

    # Load ID not found
    if not load:
        response = {"Error": "No load with this load_id exists"}
        return jsonify(response), 404
    
    # If the load was on a boat, update the boat
    if load.get("carrier"):
        boat_key = client.key(constants.boats, int(load["carrier"]["id"]))
        boat = client.get(key=boat_key)
        boat["loads"] = [l for l in boat["loads"] if l["id"] != load["id"]]
        client.put(boat)

    client.delete(load_key)
    return '', 204

# Route to get a load
@app.route('/loads/<id>', methods=['GET'])
def get_load(id):
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406

    # Get load
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)

   # Load ID not found
    if not load:
        response = {"Error": "No load with this load_id exists"}
        return jsonify(response), 404

    # Return load
    response = {
        "id": load["id"],
        "carrier": load["carrier"],
        "volume": load["volume"],
        "item": load["item"],
        "creation_date": load["creation_date"],
        "self": load["self"]
    }
    return jsonify(response), 200

# Route to edit a load
@app.route('/loads/<id>', methods=['PUT', 'PATCH'])
def edit_load(id):
    # Invalidate requests with Accept MIME types that are not supported
    if request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406
    
    # Invalidate EDIT request when client sends an unsupported MIME type to the endpoint
    if request.content_type != 'application/json':
        response = {"Error": "Request must be JSON"}
        return jsonify(response), 415

    # Get load
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)

   # Load ID not found
    if not load:
        response = {"Error": "No load with this load_id exists"}
        return jsonify(response), 404

    content = request.get_json()

    # Forbid ID edit
    if 'id' in content:
        response = {"Error": "Updating the value of id is not allowed"}
        return jsonify(response), 403

    # Invalidate inputs that have keys other than "volume", "item", or "creation_date"
    required_attributes = ["volume", "item", "creation_date"]
    if not all(key in required_attributes for key in content.keys()):
        response = {"Error": "The request object contains unsupported attributes"}
        return jsonify(response), 400

    # PUT
    if request.method == 'PUT':
        # Check for all required attributes
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        print(load)
        load.update(content)
        print(load)

        client.put(load)
        return jsonify(load), 200

    # PATCH
    elif request.method == 'PATCH':
        print(load)
        load.update(content)
        print(load)

        client.put(load)
        return jsonify(load), 200

    # UNKNOWN ROUTE
    else:
        return 'Edit load method not recognized'

# ----------------------------------------------------------------------------- LOADING

# Routes to assign and remove loads to a boat
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def assign_remove_load(boat_id, load_id):
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)

    # PUT - Assign Load
    if request.method == 'PUT':
        # Ensure boat and load exist
        if not boat or not load:
            response = {"Error": "The specified boat and/or load does not exist"}
            return jsonify(response), 404

        # Check if load is already on a boat
        if load.get("carrier"):
            response = {"Error": "The load is already loaded on another boat"}
            return jsonify(response), 403

        # Assign carrier to load
        boat_data = {
            "id": boat.key.id,
            "name": boat["name"],
            "type": boat["type"],
            "length": boat["length"],
            "loads": boat.get("loads", []),
            "owner": boat["owner"]
        }
        load["carrier"] = boat_data

        # Add load to boat
        load_data = {
            "id": load.key.id,
            "volume": load["volume"],
            "item": load["item"],
            "creation_date": load["creation_date"]
        }
        boat["loads"].append(load_data)

        client.put(boat)
        client.put(load)
        return 'Load added to boat', 204

    # DELETE - Remove Load
    elif request.method == 'DELETE':
        # Ensure boat and load exist
        if not boat or not load:
            response = {"Error": "No boat with this boat_id is loaded with the load with this load_id"}
            return jsonify(response), 404

        # Ensure load is loaded on boat
        if not load.get("carrier") or load["carrier"]["id"] != int(boat_id):
            response = {"Error": "No boat with this boat_id is loaded with the load with this load_id"}
            return jsonify(response), 404

        # Remove load from boat
        boat["loads"] = [l for l in boat.get("loads", []) if l["id"] != load.key.id]
        load["carrier"] = None
        client.put(boat)
        client.put(load)
        return 'Load removed from boat', 204

    else:
        return 'Method not recognized'

# -----------------------------------------------------------------------------

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

