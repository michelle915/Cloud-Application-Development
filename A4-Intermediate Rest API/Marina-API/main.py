from google.cloud import datastore
from flask import Flask, request, jsonify
import json
import constants

app = Flask(__name__)
client = datastore.Client()

@app.route('/')
def index():
    return "Assignment 4: Intermediate Rest API"

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
            "loads": []
        })
        client.put(new_boat)

        # Update the boat's id attribute 
        new_boat["id"] = new_boat.key.id
        client.put(new_boat)
        
        # Return created boat, along with a generated self-link
        response = {
            "id": new_boat["id"],
            "name": new_boat["name"],
            "type": new_boat["type"],
            "length": new_boat["length"],
            "loads": new_boat["loads"],
            "self": f"{request.url_root}boats/{new_boat['id']}"
        }
        return jsonify(response), 201
    
    # GET
    elif request.method == 'GET':
        # Pagination setup for boats
        limit = 3
        query = client.query(kind=constants.boats)
        total_results = list(query.fetch())
        offset = request.args.get('offset', 0, int)
        query = client.query(kind=constants.boats)
        query_iter = query.fetch(limit=limit, offset=offset)
        results = list(query_iter)
        
        # Generate boat information
        boats = []

        for boat in results:

            # Generate load information
            loads = []

            for l in boat["loads"]:
                load_key = client.key(constants.loads, int(l["id"]))
                load = client.get(key=load_key)

                a_load = {
                    "id": load["id"],
                    "volume": load["volume"],
                    "item": load["item"],
                    "creation_date": load["creation_date"],
                    "self": f"{request.url_root}loads/{load['id']}"
                }
                loads.append(a_load)

            # Add all load information
            a_boat = {
                "id": boat["id"],
                "name": boat["name"],
                "type": boat["type"],
                "length": boat["length"],
                "loads": loads,
                "self": f"{request.url_root}boats/{boat['id']}"
            }
            boats.append(a_boat)
        
        output = {
            "boats": boats
        }

        # Add a "next" link if more boats are available
        if len(total_results) > offset + limit:
            output["next"] = f"{request.url_root}boats?offset={offset + limit}"

        return jsonify(output), 200
    
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

    # DELETE    
    elif request.method == 'DELETE':
        
        # Remove loads from the boat before deleting
        for load in boat["loads"]:
            load_key = client.key(constants.loads, load["id"])
            current_load = client.get(key=load_key)
            current_load["carrier"] = None
            client.put(current_load)

        # Delete boat
        client.delete(boat_key)
        return '', 204
    
    # GET
    elif request.method == 'GET':

        # Generate load information
        loads = []

        for l in boat["loads"]:
            load_key = client.key(constants.loads, int(l["id"]))
            load = client.get(key=load_key)

            a_load = {
                "id": load["id"],
                "volume": load["volume"],
                "item": load["item"],
                "creation_date": load["creation_date"],
                "self": f"{request.url_root}loads/{load['id']}"
            }
            loads.append(a_load)

        # Compile boat information
        response = {
            "id": boat["id"],
            "name": boat["name"],
            "type": boat["type"],
            "length": boat["length"],
            "loads": loads,
            "self": f"{request.url_root}boats/{boat['id']}"
        }
        return jsonify(response), 200

    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

# Routes for all loads
@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():
    # POST
    if request.method == 'POST':
        content = request.get_json()

        # Check for required attributes
        required_attributes = ["volume", "item", "creation_date"]
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        # Create and store new load
        new_load = datastore.Entity(key=client.key(constants.loads))
        new_load.update({
            "volume": content["volume"],
            "carrier": None,
            "item": content["item"],
            "creation_date": content["creation_date"]
        })
        client.put(new_load)

        # Update the load's id attribute
        new_load["id"] = new_load.key.id
        client.put(new_load)

        # Return created load, along with a generated self-link
        response = {
            "id": new_load["id"],
            "volume": new_load["volume"],
            "carrier": new_load["carrier"],
            "item": new_load["item"],
            "creation_date": new_load["creation_date"],
            "self": f"{request.url_root}loads/{new_load['id']}"
        }
        return jsonify(response), 201

    # GET
    elif request.method == 'GET':
        # Pagination setup for loads
        limit = 3
        query = client.query(kind=constants.loads)
        total_results = list(query.fetch())
        offset = request.args.get('offset', 0, int)
        query = client.query(kind=constants.loads)
        query_iter = query.fetch(limit=limit, offset=offset)
        results = list(query_iter)
        
        # Compile information for all loads
        loads = []

        for load in results:
            
            # Generate carrier information
            carrier = None

            if load["carrier"]:
                boat_key = client.key(constants.boats, int(load["carrier"]["id"]))
                boat = client.get(key=boat_key)

                if boat:
                    carrier = {
                        "id": boat["id"],
                        "name": boat["name"],
                        "self": f"{request.url_root}boats/{boat['id']}"
                    }

            # Compile load information
            a_load = {
                "id": load["id"],
                "volume": load["volume"],
                "carrier": carrier,
                "item": load["item"],
                "creation_date": load["creation_date"],
                "self": f"{request.url_root}loads/{load['id']}"
            }
            loads.append(a_load)
        
        output = {
            "loads": loads
        }

        # Add a "next" link if more loads are available
        if len(total_results) > offset + limit:
            output["next"] = f"{request.url_root}loads?offset={offset + limit}"

        return jsonify(output), 200

    else:
        return 'Method not recognized'

# Routes for a specific load
@app.route('/loads/<id>', methods=['GET', 'DELETE'])
def load_get_delete(id):
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)

    if not load:
        response = {"Error": "No load with this load_id exists"}
        return jsonify(response), 404

    # GET
    if request.method == 'GET':

        # Generate carrier information
        carrier = None

        if load["carrier"]:
            boat_key = client.key(constants.boats, int(load["carrier"]["id"]))
            boat = client.get(key=boat_key)

            carrier = {
                "id": boat["id"],
                "name": boat["name"],
                "self": f"{request.url_root}boats/{boat['id']}"
            }

        # Compile load information
        response = {
            "id": load["id"],
            "volume": load["volume"],
            "carrier": carrier,
            "item": load["item"],
            "creation_date": load["creation_date"],
            "self": f"{request.url_root}loads/{load['id']}"
        }
        return jsonify(response), 200

    # DELETE
    elif request.method == 'DELETE':
        # If the load was on a boat, update the boat
        if load.get("carrier"):
            boat_key = client.key(constants.boats, int(load["carrier"]["id"]))
            boat = client.get(key=boat_key)
            boat["loads"] = [l for l in boat["loads"] if l["id"] != load["id"]]
            client.put(boat)

        client.delete(load_key)
        return '', 204

    else:
        return 'Method not recognized'

# Route to get all loads on a boat
@app.route('/boats/<boat_id>/loads', methods=['GET'])
def get_loads_for_boat(boat_id):
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)

    # Ensure boat exists
    if not boat :
        response = {"Error": "No boat with this boat_id exists"}
        return jsonify(response), 404

    # Generate load information
    loads = []

    for l in boat["loads"]:
        load_key = client.key(constants.loads, int(l["id"]))
        load = client.get(key=load_key)

        a_load = {
            "id": load["id"],
            "volume": load["volume"],
            "item": load["item"],
            "creation_date": load["creation_date"],
            "self": f"{request.url_root}loads/{load['id']}"
        }
        loads.append(a_load)

    # Add all load information
    response = {
        "id": boat["id"],
        "name": boat["name"],
        "type": boat["type"],
        "length": boat["length"],
        "loads": loads,
        "self": f"{request.url_root}boats/{boat['id']}"
    }
            
    return response, 200

# Route to assign a load to a boat
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
        load["carrier"] = {
            "id": boat["id"]
        }

        # Add load to boat
        boat["loads"].append({
            "id": load["id"]
        })

        client.put(boat)
        client.put(load)
        return '', 204

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
        boat["loads"] = [l for l in boat["loads"] if l["id"] != load["id"]]
        load["carrier"] = None
        client.put(boat)
        client.put(load)
        return '', 204

    else:
        return 'Method not recognized'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)