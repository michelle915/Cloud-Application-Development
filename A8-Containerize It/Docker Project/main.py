from google.cloud import datastore
from flask import Flask, request, jsonify
import json
import constants

app = Flask(__name__)
client = datastore.Client()

@app.route('/')
def index():
    return "Assignment 8: Containerize It"

# Routes for all boats
@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():
    # POST
    if request.method == 'POST':
        content = request.get_json()

        # Check for all required attributes
        required_attributes = ["name"]
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        # Create and store new boat
        new_boat = datastore.Entity(key=client.key(constants.boats))
        new_boat.update({
            "name": content["name"],
        })
        client.put(new_boat)

        # Update the boat's id attribute 
        new_boat["id"] = new_boat.key.id
        client.put(new_boat)
        
        # Return created boat, along with a generated self-link
        response = {
            "id": new_boat["id"],
            "name": new_boat["name"],
        }
        return jsonify(response), 201
    
    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

# Routes for a boat
@app.route('/boats/<id>', methods=['DELETE','GET'])
def boat_delete_get(id):
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)

    # Boat ID not found
    if not boat:
        response = {"Error": "No boat with this boat_id exists"}
        return jsonify(response), 404
    
    # GET
    elif request.method == 'GET':
        # Compile boat information
        response = {
            "id": boat["id"],
            "name": boat["name"],
        }
        return jsonify(response), 200

    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
