from google.cloud import datastore
from flask import Flask, request, jsonify
import json
import constants

app = Flask(__name__)
client = datastore.Client()

@app.route('/')
def index():
    return "Please navigate to /boats or /slips to use this API"

# Routes for all boats
@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():

    # POST
    if request.method == 'POST':
        content = request.get_json()

        # Check for all required attributes
        required_attributes = ["name", "type", "length"]
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        # Create and store new boat
        new_boat = datastore.Entity(key=client.key(constants.boats))
        new_boat.update({
            "name": content["name"],
            "type": content["type"],
            "length": content["length"],
        })
        client.put(new_boat)

        # Update the boat's id attribute
        new_boat["id"] = new_boat.key.id
        client.put(new_boat)
        
        # Return created boat
        response = {
            "id": new_boat["id"],
            "name": new_boat["name"],
            "type": new_boat["type"],
            "length": new_boat["length"]
        }
        return jsonify(response), 201
    
    # GET
    elif request.method == 'GET':
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        return json.dumps(results), 200
    
    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

# Routes for a boat
@app.route('/boats/<id>', methods=['PATCH','DELETE','GET'])
def boat_patch_delete_get(id):
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)

    # Boat ID not found
    if not boat:
        response = {"Error": "No boat with this boat_id exists"}
        return jsonify(response), 404

    # PATCH
    if request.method == 'PATCH':
        content = request.get_json()

        # Check for all required attributes
        required_attributes = ["name", "type", "length"]
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        # Update boat
        boat.update({
            "name": content["name"],
            "type": content["type"],
            "length": content["length"],
        })
        client.put(boat)

        # Return updated boat
        response = {
            "id": boat["id"],
            "name": boat["name"],
            "type": boat["type"],
            "length": boat["length"]
        }
        return jsonify(response), 200


    # DELETE    
    elif request.method == 'DELETE':
        
        # If the boat is in a slip, make the slip empty
        query = client.query(kind=constants.slips)
        query.add_filter('current_boat', '=', int(id))
        slips = list(query.fetch())

        for slip in slips:
            slip['current_boat'] = None
            client.put(slip)

        # Delete boat
        client.delete(boat_key)
        return '', 204
    
    # GET
    elif request.method == 'GET':
        response = {
                "id": boat["id"],
                "name": boat["name"],
                "type": boat["type"],
                "length": boat["length"]
            }
        return jsonify(response), 200

    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

# Routes for all slips
@app.route('/slips', methods=['POST', 'GET'])
def slips_get_post():

    # POST
    if request.method == 'POST':
        content = request.get_json()

        # Check for all required attributes
        required_attributes = ["number"]
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing the required number"}
            return jsonify(response), 400

        # Create and store new slip
        new_slip = datastore.Entity(key=client.key(constants.slips))
        new_slip.update({
            "number": content["number"],
            "current_boat": None
        })
        client.put(new_slip)

        # Update the boat's id attribute
        new_slip["id"] = new_slip.key.id
        client.put(new_slip)

        # Return created slip
        response = {
            "id": new_slip["id"],
            "number": new_slip["number"],
            "current_boat": new_slip["current_boat"]
        }
        return jsonify(response), 201
    
    # GET
    elif request.method == 'GET':
        query = client.query(kind=constants.slips)
        results = list(query.fetch())
        return json.dumps(results), 200
    
    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

# Routes for a slip
@app.route('/slips/<id>', methods=['DELETE','GET'])
def slip_put_delete_get(id):
    slip_key = client.key(constants.slips, int(id))
    slip = client.get(key=slip_key)

    # Slip ID not found
    if not slip:
        response = {"Error": "No slip with this slip_id exists"}
        return jsonify(response), 404

    # DELETE    
    if request.method == 'DELETE':
        client.delete(slip_key)
        return '', 204
    
    # GET
    elif request.method == 'GET':
         # Return slip
        response = {
            "id": slip["id"],
            "number": slip["number"],
            "current_boat": slip["current_boat"]
        }
        return jsonify(response), 200

    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

# Boat ARRIVES at slip
@app.route('/slips/<slip_id>/<boat_id>', methods=['PUT'])
def boat_arrives_at_slip(slip_id, boat_id):
    slip_key = client.key(constants.slips, int(slip_id))
    slip = client.get(key=slip_key)

    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)

    # Check if both the slip and the boat exist
    if not slip or not boat:
        response = {"Error": "The specified boat and/or slip does not exist"}
        return jsonify(response), 404

    # Check if the slip is empty
    if slip["current_boat"]:
        response = {"Error": "The slip is not empty"}
        return jsonify(response), 403

    # Assign the boat to the slip
    slip["current_boat"] = boat.key.id
    client.put(slip)

    # No content to return for a successful operation    
    return '', 204    

# Boat DEPARTS from slip
@app.route('/slips/<slip_id>/<boat_id>', methods=['DELETE'])
def boat_departs_from_slip(slip_id, boat_id):
    slip_key = client.key(constants.slips, int(slip_id))
    slip = client.get(key=slip_key)

    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)

    # Check if both the slip and the boat exist and if the boat is currently at the slip
    if slip and boat and slip["current_boat"] == boat.key.id:
        # Boat departs from slip
        slip["current_boat"] = None
        client.put(slip)
        return '', 204
    else:
        response = {"Error": "No boat with this boat_id is at the slip with this slip_id"}
        return jsonify(response), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)