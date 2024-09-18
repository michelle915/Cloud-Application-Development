from flask import Flask, redirect, request, session, render_template
from google.cloud import datastore
import requests
import os
import random
import datetime
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Datastore client
datastore_client = datastore.Client()

# Function to load credentials from the JSON file
def load_credentials():
    with open('client_secret.json') as f:
        data = json.load(f)
        web = data['web']
        return web['client_id'], web['client_secret'], web['redirect_uris'] 

# Load credentials
CLIENT_ID, CLIENT_SECRET, REDIRECT_URI = load_credentials()

AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
PEOPLE_API_URL = 'https://people.googleapis.com/v1/people/me?personFields=names'

def store_state_in_datastore(state):
    entity = datastore.Entity(key=datastore_client.key('State'))
    entity.update({
        'state_value': state,
        'timestamp': datetime.datetime.now()
    })
    datastore_client.put(entity)

def verify_state_in_datastore(state):
    query = datastore_client.query(kind='State')
    query.add_filter('state_value', '=', state)
    results = list(query.fetch())
    return len(results) > 0

@app.route('/')
def welcome():
    state = str(random.randint(100000, 999999))
    session['state'] = state
    store_state_in_datastore(state)

    auth_url = f"{AUTH_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=profile&state={state}"
    return render_template('welcome.html', auth_url=auth_url)

@app.route('/oauth')
def oauth():
    code = request.args.get('code')
    state = request.args.get('state')

    if not state or not verify_state_in_datastore(state):
        return "State mismatch or not found in Datastore.", 401

    token_data = {
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    token_r = requests.post(TOKEN_URL, data=token_data)
    access_token = token_r.json().get('access_token')
    
    user_info = requests.get(PEOPLE_API_URL, headers={'Authorization': f'Bearer {access_token}'})
    return render_template('userinfo.html', user_info=user_info.json(), state=state)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
    